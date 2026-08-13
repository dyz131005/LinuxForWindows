/*
 * pe_to_elf.c - PE -> ELF 离线二进制转换工具
 *
 * 用法: ./pe_to_elf target.exe
 *
 * 核心流程:
 *   1. 读取 PE 文件，自动识别架构 (x86 / x86_64)
 *   2. 完整解析 PE 头、段表、重定位表、导入表、导出表、调试信息
 *   3. 递归扫描 EXE 所在目录的 DLL 文件
 *   4. 构建 ELF 文件: 头、程序头、节头、段数据
 *   5. 逐节映射 PE 段 -> ELF 段/节
 *   6. 翻译 PE 重定位 -> ELF 重定位
 *   7. 处理 DLL 依赖: 转换本地 DLL 为 .so
 *   8. 复制非 PE 资源文件
 *   9. 设置执行权限
 *
 * 约束: 仅做文件格式静态转换，不实现 Win32 API/ABI
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <dirent.h>
#include <libgen.h>
#include <ctype.h>
#include <stdarg.h>

#include "pe_to_elf.h"

/* ================================================================
 * PE 调试类型名称映射
 * ================================================================ */
static const char *pe_debug_type_name(uint32_t type)
{
    switch (type) {
    case 0:  return "Unknown";
    case 1:  return "COFF";
    case 2:  return "CodeView";
    case 3:  return "FPO";
    case 4:  return "PDB";
    case 5:  return "FPO";
    case 6:  return "Misc";
    case 7:  return "ExeSpecification";
    case 8:  return "DotNet";
    case 9:  return "MapToIL";
    case 10: return "FPOState";
    case 11: return "CJIT";
    case 12: return "CLR";
    case 13: return "VCFeature";
    case 14: return "POGO";
    case 15: return "ILTCG";
    case 16: return "MPX";
    case 17: return "Repro";
    case 18: return "ExeDllCharacteristic";
    default: return "Custom";
    }
}

static int count_valid_debug_entries(pe_parse_result_t *result)
{
    int count = 0;
    for (uint32_t i = 0; i < result->num_debug_dirs; i++) {
        if (result->debug_dirs[i].PointerToRawData != 0 &&
            result->debug_dirs[i].SizeOfData > 0) {
            count++;
        }
    }
    return count;
}

/* ================================================================
 * 基础工具函数
 * ================================================================ */

static int strcasecmp_custom(const char *a, const char *b)
{
    while (*a && *b) {
        if (tolower((unsigned char)*a) != tolower((unsigned char)*b))
            return 1;
        a++; b++;
    }
    return (*a || *b) ? 1 : 0;
}

static uint32_t align_up_u32(uint32_t v, uint32_t a)
{
    return (v + a - 1) & ~(a - 1);
}

static uint64_t align_up_u64(uint64_t v, uint64_t a)
{
    return (v + a - 1) & ~(a - 1);
}

int is_dll_file_ext(const char *filename)
{
    size_t len = strlen(filename);
    if (len < 4) return 0;
    return (strcasecmp_custom(filename + len - 4, ".dll") == 0);
}

int is_pe_file_ext(const char *filename)
{
    size_t len = strlen(filename);
    if (len < 4) return 0;
    const char *ext = filename + len - 4;
    return (strcasecmp_custom(ext, ".exe") == 0 || strcasecmp_custom(ext, ".dll") == 0);
}

int is_pe_file_magic(const char *path)
{
    int fd = open(path, O_RDONLY);
    if (fd < 0) return 0;
    uint8_t magic[2];
    ssize_t n = read(fd, magic, 2);
    close(fd);
    return (n == 2 && magic[0] == 0x4D && magic[1] == 0x5A);
}

static int read_file_to_memory(const char *path, uint8_t **out_buf, size_t *out_size)
{
    struct stat st;
    if (stat(path, &st) != 0) {
        fprintf(stderr, "[ERROR] stat: %s (%s)\n", path, strerror(errno));
        return -1;
    }
    if (!S_ISREG(st.st_mode)) {
        fprintf(stderr, "[ERROR] not regular file: %s\n", path);
        return -1;
    }
    size_t size = (size_t)st.st_size;
    if (size == 0) { fprintf(stderr, "[ERROR] empty file: %s\n", path); return -1; }

    int fd = open(path, O_RDONLY);
    if (fd < 0) { fprintf(stderr, "[ERROR] open: %s (%s)\n", path, strerror(errno)); return -1; }

    uint8_t *buf = (uint8_t *)malloc(size);
    if (!buf) { close(fd); return -1; }

    size_t remaining = size;
    uint8_t *ptr = buf;
    while (remaining > 0) {
        ssize_t n = read(fd, ptr, remaining);
        if (n < 0) {
            if (errno == EINTR) continue;
            free(buf); close(fd); return -1;
        }
        if (n == 0) { free(buf); close(fd); return -1; }
        ptr += n; remaining -= (size_t)n;
    }
    close(fd);
    *out_buf = buf; *out_size = size;
    return 0;
}

static int write_file_from_memory(const char *path, const uint8_t *buf, size_t size)
{
    int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (fd < 0) { fprintf(stderr, "[ERROR] create: %s (%s)\n", path, strerror(errno)); return -1; }

    size_t remaining = size;
    const uint8_t *ptr = buf;
    while (remaining > 0) {
        ssize_t n = write(fd, ptr, remaining);
        if (n < 0) {
            if (errno == EINTR) continue;
            close(fd); return -1;
        }
        ptr += n; remaining -= (size_t)n;
    }
    close(fd);
    return 0;
}

static int make_dirs_recursive(const char *path)
{
    char *tmp = strdup(path);
    if (!tmp) return -1;
    for (char *p = tmp + 1; *p; p++) {
        if (*p == '/') {
            *p = '\0';
            mkdir(tmp, 0755);
            *p = '/';
        }
    }
    free(tmp);
    if (mkdir(path, 0755) != 0 && errno != EEXIST) return -1;
    return 0;
}

static int file_copy_binary(const char *src, const char *dst)
{
    uint8_t *buf = NULL; size_t sz = 0;
    if (read_file_to_memory(src, &buf, &sz) != 0) return -1;
    int rc = write_file_from_memory(dst, buf, sz);
    free(buf);
    return rc;
}

static int set_exec_perm(const char *path)
{
    struct stat st;
    if (stat(path, &st) != 0) return -1;
    return chmod(path, st.st_mode | S_IXUSR | S_IXGRP | S_IXOTH);
}

/* RVA -> 文件偏移 转换 (基于节表) */
static uint64_t rva_to_file_offset(pe_parse_result_t *result, uint32_t rva)
{
    for (uint16_t i = 0; i < result->num_sections; i++) {
        pe_section_header_t *sec = &result->sections[i];
        if (rva >= sec->VirtualAddress &&
            rva < sec->VirtualAddress + sec->SizeOfRawData) {
            return (uint64_t)sec->PointerToRawData + (rva - sec->VirtualAddress);
        }
    }
    /* 对于 .text 等虚拟地址 > 原始大小的情况，使用 VirtualSize */
    for (uint16_t i = 0; i < result->num_sections; i++) {
        pe_section_header_t *sec = &result->sections[i];
        uint32_t sec_end = sec->VirtualAddress +
            (sec->Misc.VirtualSize > sec->SizeOfRawData ? sec->Misc.VirtualSize : sec->SizeOfRawData);
        if (rva >= sec->VirtualAddress && rva < sec_end) {
            if (sec->SizeOfRawData > 0)
                return (uint64_t)sec->PointerToRawData + (rva - sec->VirtualAddress);
            return 0;
        }
    }
    return 0;
}

/* ================================================================
 * PE 头部解析
 * ================================================================ */

static int pe_parse_headers(const uint8_t *buf, size_t size, pe_parse_result_t *result)
{
    if (size < sizeof(pe_dos_header_t)) { fprintf(stderr, "[ERROR] file too small for DOS header\n"); return -1; }

    pe_dos_header_t *dos = (pe_dos_header_t *)buf;
    if (dos->e_magic != PE_DOS_MAGIC) {
        fprintf(stderr, "[ERROR] DOS magic: expect 0x%04X, got 0x%04X\n", PE_DOS_MAGIC, dos->e_magic); return -1;
    }
    printf("[INFO] DOS header OK (MZ magic)\n");

    if (dos->e_lfanew <= 0 || (size_t)dos->e_lfanew + 4 > size) {
        fprintf(stderr, "[ERROR] invalid e_lfanew: 0x%X\n", dos->e_lfanew); return -1;
    }

    uint32_t *pe_sig = (uint32_t *)(buf + dos->e_lfanew);
    if (*pe_sig != PE_SIGNATURE) {
        fprintf(stderr, "[ERROR] PE signature: expect 0x%08X, got 0x%08X\n", PE_SIGNATURE, *pe_sig); return -1;
    }
    printf("[INFO] PE signature OK\n");

    pe_coff_header_t *coff = (pe_coff_header_t *)(buf + dos->e_lfanew + 4);

    switch (coff->Machine) {
    case PE_MACHINE_I386:
        result->arch = PE_ARCH_X86;
        printf("[INFO] Architecture: x86 32-bit (IMAGE_FILE_MACHINE_I386)\n");
        break;
    case PE_MACHINE_AMD64:
        result->arch = PE_ARCH_X86_64;
        printf("[INFO] Architecture: x86_64 64-bit (IMAGE_FILE_MACHINE_AMD64)\n");
        break;
    default:
        fprintf(stderr, "[ERROR] unsupported machine: 0x%04X\n", coff->Machine); return -1;
    }

    uint32_t opt_off = dos->e_lfanew + 4 + (uint32_t)sizeof(pe_coff_header_t);
    uint16_t opt_size = coff->SizeOfOptionalHeader;

    if (result->arch == PE_ARCH_X86) {
        if ((size_t)opt_off + opt_size > size) { fprintf(stderr, "[ERROR] PE32 opt hdr overflow\n"); return -1; }
        pe32_nt_headers_t *nt32 = (pe32_nt_headers_t *)(buf + dos->e_lfanew);
        if (nt32->OptionalHeader.Magic != PE_MAGIC_PE32) {
            fprintf(stderr, "[ERROR] PE32 magic: expect 0x%04X, got 0x%04X\n", PE_MAGIC_PE32, nt32->OptionalHeader.Magic); return -1;
        }
        result->nt.nt32 = nt32;
        printf("[INFO] PE32 opt hdr OK (Magic=0x%04X)\n", nt32->OptionalHeader.Magic);
        printf("[INFO]   ImageBase=0x%08X EntryPoint=0x%08X SizeOfImage=0x%08X\n",
               nt32->OptionalHeader.ImageBase, nt32->OptionalHeader.AddressOfEntryPoint,
               nt32->OptionalHeader.SizeOfImage);
    } else {
        if ((size_t)opt_off + opt_size > size) { fprintf(stderr, "[ERROR] PE32+ opt hdr overflow\n"); return -1; }
        pe64_nt_headers_t *nt64 = (pe64_nt_headers_t *)(buf + dos->e_lfanew);
        if (nt64->OptionalHeader.Magic != PE_MAGIC_PE32_PLUS) {
            fprintf(stderr, "[ERROR] PE32+ magic: expect 0x%04X, got 0x%04X\n", PE_MAGIC_PE32_PLUS, nt64->OptionalHeader.Magic); return -1;
        }
        result->nt.nt64 = nt64;
        printf("[INFO] PE32+ opt hdr OK (Magic=0x%04X)\n", nt64->OptionalHeader.Magic);
        printf("[INFO]   ImageBase=0x%016llX EntryPoint=0x%08X SizeOfImage=0x%08X\n",
               (unsigned long long)nt64->OptionalHeader.ImageBase, nt64->OptionalHeader.AddressOfEntryPoint,
               nt64->OptionalHeader.SizeOfImage);
    }

    result->dos = dos;
    result->coff = coff;

    uint32_t sec_tbl_off = opt_off + opt_size;
    uint16_t nsec = coff->NumberOfSections;
    if ((size_t)sec_tbl_off + (size_t)nsec * sizeof(pe_section_header_t) > size) {
        fprintf(stderr, "[ERROR] section table overflow\n"); return -1;
    }
    result->sections = (pe_section_header_t *)(buf + sec_tbl_off);
    result->num_sections = nsec;

    printf("[INFO] Sections: %u\n", (unsigned)nsec);
    for (uint16_t i = 0; i < nsec; i++) {
        pe_section_header_t *s = &result->sections[i];
        char nm[9] = {0}; memcpy(nm, s->Name, 8);
        printf("[INFO]   [%u] %-8s VA=0x%08X Raw=0x%08X@0x%08X Virt=0x%08X Flags=0x%08X\n",
               (unsigned)i, nm, s->VirtualAddress, s->SizeOfRawData, s->PointerToRawData,
               s->Misc.VirtualSize, s->Characteristics);
    }
    return 0;
}

static int pe_parse_relocations(pe_parse_result_t *result)
{
    uint32_t rva = 0, sz = 0;
    if (result->arch == PE_ARCH_X86) {
        rva = result->nt.nt32->OptionalHeader.DataDirectory[PE_DIR_BASERELOC].VirtualAddress;
        sz  = result->nt.nt32->OptionalHeader.DataDirectory[PE_DIR_BASERELOC].Size;
    } else {
        rva = result->nt.nt64->OptionalHeader.DataDirectory[PE_DIR_BASERELOC].VirtualAddress;
        sz  = result->nt.nt64->OptionalHeader.DataDirectory[PE_DIR_BASERELOC].Size;
    }
    if (rva == 0 || sz == 0) { printf("[INFO] No relocation table\n"); return 0; }

    printf("[INFO] Parse relocations: RVA=0x%08X Size=0x%08X\n", rva, sz);
    result->has_relocations = 1;

    uint64_t rel_base = rva_to_file_offset(result, rva);
    if (rel_base == 0) {
        fprintf(stderr, "[WARN] Cannot resolve reloc RVA 0x%08X to file offset\n", rva);
        return -1;
    }

    uint64_t off = rel_base;
    uint32_t total = 0;
    while (off + 8 <= rel_base + sz) {
        pe_base_relocation_t blk;
        memcpy(&blk, result->raw_buf + off, sizeof(blk));
        if (blk.SizeOfBlock == 0) break;
        total += (blk.SizeOfBlock - 8) / 2;
        off += blk.SizeOfBlock;
    }
    if (total == 0) return 0;

    result->reloc_items = (uint32_t *)calloc(total * 2, sizeof(uint32_t));
    if (!result->reloc_items) return -1;

    off = rel_base;
    uint32_t idx = 0, unconv = 0;
    while (off + 8 <= rel_base + sz && idx < total) {
        pe_base_relocation_t blk;
        memcpy(&blk, result->raw_buf + off, sizeof(blk));
        if (blk.SizeOfBlock == 0) break;
        uint32_t entries = (blk.SizeOfBlock - 8) / 2;
        uint16_t *rel = (uint16_t *)(result->raw_buf + off + 8);
        for (uint32_t j = 0; j < entries && idx < total; j++) {
            uint16_t e = rel[j];
            uint8_t type = e >> 12;
            uint16_t off2 = e & 0x0FFF;
            result->reloc_items[idx * 2] = type;
            result->reloc_items[idx * 2 + 1] = blk.VirtualAddress + off2;
            idx++;
            if (type != PE_REL_BASED_ABSOLUTE) {
                int ok = 0;
                if (result->arch == PE_ARCH_X86) {
                    if (type == PE_REL_BASED_HIGHLOW || type == PE_REL_BASED_HIGH || type == PE_REL_BASED_LOW) ok = 1;
                } else {
                    if (type == PE_REL_BASED_DIR64 || type == PE_REL_BASED_HIGHLOW || type == PE_REL_BASED_HIGH) ok = 1;
                }
                if (!ok) unconv++;
            }
        }
        off += blk.SizeOfBlock;
    }
    result->total_relocs = idx;
    result->num_reloc_items = idx;
    result->unconvertible_relocs = unconv;
    printf("[INFO] Relocs: %u total, %u unconvertible\n", idx, unconv);
    if (unconv > 0) printf("[WARN] %u relocs cannot be directly converted\n", unconv);
    return 0;
}

static int pe_parse_imports(pe_parse_result_t *result)
{
    uint32_t rva = 0, sz = 0;
    if (result->arch == PE_ARCH_X86) {
        rva = result->nt.nt32->OptionalHeader.DataDirectory[PE_DIR_IMPORT].VirtualAddress;
        sz  = result->nt.nt32->OptionalHeader.DataDirectory[PE_DIR_IMPORT].Size;
    } else {
        rva = result->nt.nt64->OptionalHeader.DataDirectory[PE_DIR_IMPORT].VirtualAddress;
        sz  = result->nt.nt64->OptionalHeader.DataDirectory[PE_DIR_IMPORT].Size;
    }
    if (rva == 0 || sz == 0) { printf("[INFO] No import table\n"); return 0; }

    printf("[INFO] Parse imports: RVA=0x%08X Size=0x%08X\n", rva, sz);
    result->has_imports = 1;

    uint64_t imp_off = rva_to_file_offset(result, rva);
    if (imp_off == 0) {
        fprintf(stderr, "[WARN] Cannot resolve import RVA 0x%08X to file offset\n", rva);
        return -1;
    }

    uint32_t max_desc = sz / sizeof(pe_import_descriptor_t);
    if (max_desc == 0) return 0;

    result->import_descs = (pe_import_descriptor_t *)calloc(max_desc, sizeof(pe_import_descriptor_t));
    if (!result->import_descs) return -1;

    uint32_t count = 0;
    uint64_t cur = imp_off;
    while (cur + sizeof(pe_import_descriptor_t) <= imp_off + sz && count < max_desc) {
        pe_import_descriptor_t desc;
        memcpy(&desc, result->raw_buf + cur, sizeof(desc));
        if (desc.Name == 0 && desc.FirstThunk == 0 && desc.OriginalFirstThunk == 0) break;
        result->import_descs[count] = desc;
        count++;
        cur += sizeof(pe_import_descriptor_t);
    }
    result->num_imports = count;

    printf("[INFO] Import DLLs (%u):\n", count);
    for (uint32_t i = 0; i < count; i++) {
        uint64_t name_off = rva_to_file_offset(result, result->import_descs[i].Name);
        const char *name_str = (name_off > 0) ? (const char *)(result->raw_buf + name_off) : "<unknown>";
        printf("[INFO]   [%u] %s (OFThunk=0x%08X, FThunk=0x%08X)\n",
               i, name_str, result->import_descs[i].OriginalFirstThunk,
               result->import_descs[i].FirstThunk);
    }
    return 0;
}

static int pe_parse_exports(pe_parse_result_t *result)
{
    uint32_t rva = 0, sz = 0;
    if (result->arch == PE_ARCH_X86) {
        rva = result->nt.nt32->OptionalHeader.DataDirectory[PE_DIR_EXPORT].VirtualAddress;
        sz  = result->nt.nt32->OptionalHeader.DataDirectory[PE_DIR_EXPORT].Size;
    } else {
        rva = result->nt.nt64->OptionalHeader.DataDirectory[PE_DIR_EXPORT].VirtualAddress;
        sz  = result->nt.nt64->OptionalHeader.DataDirectory[PE_DIR_EXPORT].Size;
    }
    if (rva == 0 || sz == 0) { printf("[INFO] No export table\n"); return 0; }

    printf("[INFO] Parse exports: RVA=0x%08X Size=0x%08X\n", rva, sz);
    result->has_exports = 1;

    uint64_t exp_off = rva_to_file_offset(result, rva);
    if (exp_off == 0) {
        fprintf(stderr, "[WARN] Cannot resolve export RVA 0x%08X to file offset\n", rva);
        return -1;
    }

    result->export_dir = (pe_export_directory_t *)(result->raw_buf + exp_off);
    printf("[INFO]   Base=0x%08X Functions=%u Names=%u\n",
           result->export_dir->Base, result->export_dir->NumberOfFunctions,
           result->export_dir->NumberOfNames);
    return 0;
}

static int pe_parse_debug(pe_parse_result_t *result)
{
    uint32_t rva = 0, sz = 0;
    if (result->arch == PE_ARCH_X86) {
        rva = result->nt.nt32->OptionalHeader.DataDirectory[PE_DIR_DEBUG].VirtualAddress;
        sz  = result->nt.nt32->OptionalHeader.DataDirectory[PE_DIR_DEBUG].Size;
    } else {
        rva = result->nt.nt64->OptionalHeader.DataDirectory[PE_DIR_DEBUG].VirtualAddress;
        sz  = result->nt.nt64->OptionalHeader.DataDirectory[PE_DIR_DEBUG].Size;
    }
    if (rva == 0 || sz == 0) { printf("[INFO] No debug directory\n"); return 0; }

    printf("[INFO] Parse debug: RVA=0x%08X Size=0x%08X (preserving)\n", rva, sz);
    result->has_debug = 1;

    uint64_t dbg_off = rva_to_file_offset(result, rva);
    if (dbg_off == 0) {
        fprintf(stderr, "[WARN] Cannot resolve debug RVA 0x%08X to file offset\n", rva);
        return -1;
    }

    uint32_t count = sz / sizeof(pe_debug_directory_t);
    if (count == 0) return 0;

    result->debug_dirs = (pe_debug_directory_t *)calloc(count, sizeof(pe_debug_directory_t));
    if (!result->debug_dirs) return -1;

    uint8_t *p = result->raw_buf + dbg_off;
    for (uint32_t i = 0; i < count; i++)
        memcpy(&result->debug_dirs[i], p + i * sizeof(pe_debug_directory_t), sizeof(pe_debug_directory_t));
    result->num_debug_dirs = count;

    printf("[INFO] Debug entries: %u\n", count);
    for (uint32_t i = 0; i < count; i++) {
        pe_debug_directory_t *d = &result->debug_dirs[i];
        printf("[INFO]   [%u] Type=%u Size=0x%08X Addr=0x%08X Ptr=0x%08X\n",
               i, d->Type, d->SizeOfData, d->AddressOfRawData, d->PointerToRawData);
    }
    return 0;
}

int pe_parse_file(const char *path, pe_parse_result_t *result)
{
    memset(result, 0, sizeof(*result));
    result->src_path = path;

    printf("\n[Phase 1] Read PE file: %s\n", path);
    if (read_file_to_memory(path, &result->raw_buf, &result->raw_size) != 0) return -1;
    printf("[INFO] File size: %zu bytes\n", result->raw_size);

    printf("[Phase 2] Parse PE headers\n");
    if (pe_parse_headers(result->raw_buf, result->raw_size, result) != 0) return -1;

    printf("[Phase 3] Parse relocations\n");
    if (pe_parse_relocations(result) != 0) return -1;

    printf("[Phase 4] Parse imports\n");
    if (pe_parse_imports(result) != 0) return -1;

    printf("[Phase 5] Parse exports\n");
    if (pe_parse_exports(result) != 0) return -1;

    printf("[Phase 6] Parse debug info\n");
    if (pe_parse_debug(result) != 0) return -1;

    printf("[INFO] PE parse complete\n");
    return 0;
}

void pe_parse_result_free(pe_parse_result_t *result)
{
    if (result->raw_buf) { free((void *)result->raw_buf); result->raw_buf = NULL; }
    if (result->import_descs) { free(result->import_descs); result->import_descs = NULL; }
    if (result->debug_dirs) { free(result->debug_dirs); result->debug_dirs = NULL; }
    if (result->reloc_items) { free(result->reloc_items); result->reloc_items = NULL; }
}

/* ================================================================
 * DLL 递归扫描
 * ================================================================ */

static int scan_dll_dir_recursive(const char *dirpath, char ***dll_list, uint32_t *dll_count, uint32_t *dll_cap)
{
    DIR *dir = opendir(dirpath);
    if (!dir) { fprintf(stderr, "[ERROR] opendir: %s (%s)\n", dirpath, strerror(errno)); return -1; }

    struct dirent *entry;
    while ((entry = readdir(dir)) != NULL) {
        char name_buf[4096];
        memset(name_buf, 0, sizeof(name_buf));
        strncpy(name_buf, entry->d_name, sizeof(name_buf) - 1);

        if (strcmp(name_buf, ".") == 0 || strcmp(name_buf, "..") == 0) continue;

        char full_path[8192];
        snprintf(full_path, sizeof(full_path), "%s/%s", dirpath, name_buf);

        struct stat st;
        if (lstat(full_path, &st) != 0) continue;

        if (S_ISDIR(st.st_mode)) {
            if (scan_dll_dir_recursive(full_path, dll_list, dll_count, dll_cap) != 0) {
                closedir(dir);
                return -1;
            }
        } else if (S_ISREG(st.st_mode)) {
            if (is_dll_file_ext(name_buf) && is_pe_file_magic(full_path)) {
                if (*dll_count >= *dll_cap) {
                    uint32_t nc = *dll_cap * 2 + 16;
                    char **nl = (char **)realloc(*dll_list, nc * sizeof(char *));
                    if (!nl) { closedir(dir); return -1; }
                    *dll_list = nl;
                    *dll_cap = nc;
                }
                (*dll_list)[*dll_count] = strdup(full_path);
                if (!(*dll_list)[*dll_count]) { closedir(dir); return -1; }
                (*dll_count)++;
            }
        }
    }
    closedir(dir);
    return 0;
}

static void find_dll_path(dll_scan_data_t *scan, const char *dll_name, char **out_path)
{
    char name_lower[256];
    size_t nl = strlen(dll_name);
    if (nl >= sizeof(name_lower)) nl = sizeof(name_lower) - 1;
    for (size_t i = 0; i < nl; i++) name_lower[i] = (char)tolower((unsigned char)dll_name[i]);
    name_lower[nl] = '\0';

    for (uint32_t i = 0; i < scan->count; i++) {
        const char *p = scan->paths[i];
        const char *bn = strrchr(p, '/');
        bn = bn ? bn + 1 : p;
        char bn_lower[256];
        size_t bl = strlen(bn);
        if (bl >= sizeof(bn_lower)) bl = sizeof(bn_lower) - 1;
        for (size_t j = 0; j < bl; j++) bn_lower[j] = (char)tolower((unsigned char)bn[j]);
        bn_lower[bl] = '\0';
        if (strcmp(name_lower, bn_lower) == 0) {
            if (*out_path) free(*out_path);
            *out_path = strdup(p);
            return;
        }
    }
}

static void dll_scan_data_init(dll_scan_data_t *scan)
{
    memset(scan, 0, sizeof(*scan));
}

static void dll_scan_data_free(dll_scan_data_t *scan)
{
    for (uint32_t i = 0; i < scan->count; i++)
        free(scan->paths[i]);
    free(scan->paths);
    for (uint32_t i = 0; i < scan->missing_count; i++)
        free(scan->missing[i]);
    free(scan->missing);
    for (uint32_t i = 0; i < scan->converted_count; i++)
        free(scan->converted[i]);
    free(scan->converted);
    for (uint32_t i = 0; i < scan->converted_src_count; i++)
        free(scan->converted_src[i]);
    free(scan->converted_src);
}

static int dll_scan_data_add_missing(dll_scan_data_t *scan, const char *name)
{
    if (scan->missing_count >= scan->missing_cap) {
        uint32_t nc = scan->missing_cap * 2 + 8;
        char **nm = (char **)realloc(scan->missing, nc * sizeof(char *));
        if (!nm) return -1;
        scan->missing = nm; scan->missing_cap = nc;
    }
    scan->missing[scan->missing_count] = strdup(name);
    if (!scan->missing[scan->missing_count]) return -1;
    scan->missing_count++;
    return 0;
}

static int dll_scan_data_add_converted(dll_scan_data_t *scan, const char *path)
{
    if (scan->converted_count >= scan->converted_cap) {
        uint32_t nc = scan->converted_cap * 2 + 8;
        char **nm = (char **)realloc(scan->converted, nc * sizeof(char *));
        if (!nm) return -1;
        scan->converted = nm; scan->converted_cap = nc;
    }
    scan->converted[scan->converted_count] = strdup(path);
    if (!scan->converted[scan->converted_count]) return -1;
    scan->converted_count++;
    return 0;
}

/* 判断某源 DLL 路径是否已转换过 (去重) */
static int dll_scan_data_is_converted_src(dll_scan_data_t *scan, const char *path)
{
    for (uint32_t i = 0; i < scan->converted_src_count; i++) {
        if (strcmp(scan->converted_src[i], path) == 0)
            return 1;
    }
    return 0;
}

/* 标记某源 DLL 路径已转换 */
static int dll_scan_data_mark_converted_src(dll_scan_data_t *scan, const char *path)
{
    if (scan->converted_src_count >= scan->converted_src_cap) {
        uint32_t nc = scan->converted_src_cap * 2 + 8;
        char **nm = (char **)realloc(scan->converted_src, nc * sizeof(char *));
        if (!nm) return -1;
        scan->converted_src = nm; scan->converted_src_cap = nc;
    }
    scan->converted_src[scan->converted_src_count] = strdup(path);
    if (!scan->converted_src[scan->converted_src_count]) return -1;
    scan->converted_src_count++;
    return 0;
}

/* ================================================================
 * ELF 32 位构建
 *
 * 映射策略:
 *   - 每个 PE 节区 -> 一个 ELF 段 (LOAD) + 一个 ELF 节区
 *   - PE 节区属性 -> ELF 段权限 (PF_R/PF_W/PF_X)
 *   - PE 虚拟地址 -> ELF 虚拟地址 (使用基址映射)
 *   - PE 入口点 -> ELF e_entry (虚拟地址换算)
 *   - 保留原始二进制数据、调试信息
 * ================================================================ */

static int build_elf32(pe_parse_result_t *result, const char *out_path, elf_out_type_t out_type,
                       char **needed_names, uint32_t num_needed)
{
    uint16_t num_sections = result->num_sections;
    int num_valid_debug = count_valid_debug_entries(result);

    printf("[Phase 7] Build ELF32: %s (%u sections, %s, %d debug entries)\n",
           out_path, num_sections, out_type == ELF_OUT_EXECUTABLE ? "executable" : "shared library",
           num_valid_debug);

    /* ELF 布局:
     * [ELF header][Program headers][Interp(可选)][LOAD段数据][SH字符串表][节头表]
     */
    uint32_t ehdr_size = 52;   /* sizeof(Elf32_Ehdr) */
    uint32_t phdr_size = 32;   /* sizeof(Elf32_Phdr) */
    uint32_t shdr_size = 40;   /* sizeof(Elf32_Shdr) */

    /* 段数量: PT_LOAD for each PE section + PT_INTERP + PT_DYNAMIC + PT_NOTE */
    /* PT_DYNAMIC 必须始终存在: glibc 2.43+ 的 audit_list_add_dynamic_tag 会
     * 无条件访问 l_info[DT_STRTAB]，缺少 PT_DYNAMIC 会导致动态链接器阶段段错误 */
    uint32_t has_dynamic = 1;
    uint32_t num_load = num_sections + (has_dynamic ? 1 : 0);
    uint32_t has_interp = (out_type == ELF_OUT_EXECUTABLE);
    /* +1 for the ELF-header PT_LOAD segment (covers Ehdr+Phdrs+interp in first page) */
    uint32_t num_phdrs = num_load + (has_interp ? 1 : 0) + (has_dynamic ? 1 : 0) + 1;

    /* 节数量: 每个 PE 节对应一个 ELF 节 + null + shstrtab + dynamic + dynsym + dynstr + rel */
    uint32_t num_additional = 1 + 1 + (has_dynamic ? 4 : 0) + (num_valid_debug > 0 ? 1 : 0); /* null + shstrtab + dyn + debug_note */
    uint32_t num_shdrs = num_sections + num_additional;

    /* ELF 虚拟地址基址 */
    uint32_t elf_base = 0x08048000; /* Linux x86 经典基址 */
    if (out_type == ELF_OUT_SHARED) elf_base = 0;

    uint32_t *seg_vaddrs = (uint32_t *)calloc(num_load, sizeof(uint32_t));
    uint32_t *seg_paddrs = (uint32_t *)calloc(num_load, sizeof(uint32_t));
    if (!seg_vaddrs || !seg_paddrs) return -1;

    uint32_t header_end = ehdr_size + num_phdrs * phdr_size;
    uint32_t cur_paddr = header_end;

    /* 解释器段 (仅 EXEC) */
    uint32_t interp_paddr = 0, interp_size = 0;
    if (has_interp) {
        interp_paddr = cur_paddr;
        interp_size = strlen(ELF_INTERPRETER_32) + 1;
        cur_paddr += interp_size;
    }

    cur_paddr = align_up_u32(cur_paddr, 0x1000);

    for (uint32_t i = 0; i < num_sections; i++) {
        pe_section_header_t *sec = &result->sections[i];
        uint32_t raw_size = sec->SizeOfRawData;
        uint32_t virt_size = sec->Misc.VirtualSize;
        uint32_t seg_size = raw_size > virt_size ? raw_size : virt_size;
        if (seg_size == 0) seg_size = 0x1000; /* 空段至少分配一页 */

        seg_paddrs[i] = cur_paddr;
        seg_vaddrs[i] = elf_base + cur_paddr;

        cur_paddr = align_up_u32(cur_paddr + seg_size, 0x1000);
    }

    uint32_t dyn_meta_paddr = 0, dyn_meta_vaddr = 0, dyn_meta_size = 0;
    uint32_t dynstr_paddr = 0, dynstr_vaddr = 0, dynstr_size = 0;
    uint32_t dynsym_paddr = 0, dynsym_vaddr = 0, dynsym_size = 0;
    uint32_t hash_paddr = 0, hash_vaddr = 0, hash_size = 0;
    uint32_t dynamic_paddr = 0, dynamic_vaddr = 0, dynamic_size = 0;
    /* 当存在 DT_NEEDED 时，加入 DT_RUNPATH=$ORIGIN 以便从可执行文件所在目录查找 .so */
    uint32_t add_runpath = (num_needed > 0) ? 1 : 0;
    if (has_dynamic) {
        uint32_t dynstr_off = 0;
        dynstr_size = 1;
        if (add_runpath) dynstr_size += (uint32_t)strlen("$ORIGIN") + 1;
        for (uint32_t i = 0; i < num_needed; i++)
            dynstr_size += (uint32_t)strlen(needed_names[i]) + 1;

        uint32_t dynsym_off = align_up_u32(dynstr_off + dynstr_size, 4);
        dynsym_size = sizeof(Elf32_Sym);

        uint32_t hash_off = align_up_u32(dynsym_off + dynsym_size, 4);
        uint32_t nbucket = 1, nchain = 1;
        hash_size = 4 * (2 + nbucket + nchain);

        uint32_t dynamic_off = align_up_u32(hash_off + hash_size, 4);
        uint32_t dyn_entries_count = 5 + num_needed + add_runpath + 1; /* tags + NEEDED + RUNPATH + NULL */
        dynamic_size = sizeof(Elf32_Dyn) * dyn_entries_count;

        dyn_meta_paddr = cur_paddr;
        dyn_meta_vaddr = elf_base + dyn_meta_paddr;
        dyn_meta_size = dynamic_off + dynamic_size;

        dynstr_paddr = dyn_meta_paddr + dynstr_off;
        dynstr_vaddr = dyn_meta_vaddr + dynstr_off;
        dynsym_paddr = dyn_meta_paddr + dynsym_off;
        dynsym_vaddr = dyn_meta_vaddr + dynsym_off;
        hash_paddr = dyn_meta_paddr + hash_off;
        hash_vaddr = dyn_meta_vaddr + hash_off;
        dynamic_paddr = dyn_meta_paddr + dynamic_off;
        dynamic_vaddr = dyn_meta_vaddr + dynamic_off;

        seg_paddrs[num_sections] = dyn_meta_paddr;
        seg_vaddrs[num_sections] = dyn_meta_vaddr;

        cur_paddr = align_up_u32(dyn_meta_paddr + dyn_meta_size, 0x1000);
    }

    /* SHSTRTAB 文件位置 */
    uint32_t shstrtab_paddr = cur_paddr;
    uint32_t shstrtab_size = 0;
    /* 计算节名字字符串表大小 */
    {
        /* null 节空字符串(1) + .shstrtab + 每个段的节名 + 额外节名 + 调试节 */
        shstrtab_size = 1; /* index 0: null string */
        shstrtab_size += strlen(".shstrtab") + 1;
        if (has_dynamic) {
            shstrtab_size += strlen(".dynstr") + 1;
            shstrtab_size += strlen(".dynsym") + 1;
            shstrtab_size += strlen(".hash") + 1;
            shstrtab_size += strlen(".dynamic") + 1;
        }
        if (num_valid_debug > 0) {
            shstrtab_size += strlen(".pe_debug") + 1;
        }
        for (uint32_t i = 0; i < num_sections; i++) {
            char nm[9] = {0}; memcpy(nm, result->sections[i].Name, 8);
            shstrtab_size += strlen(nm) + 1;
        }
    }

    /* SHDRTAB 文件位置 */
    uint32_t shdrtab_paddr = shstrtab_paddr + shstrtab_size;
    shdrtab_paddr = (shdrtab_paddr + 0x3FF) & ~0x3FF; /* 节表 16 字节对齐 */

    /* 计算调试数据总大小 (每个条目 = 调试目录头 + 原始数据) */
    uint32_t debug_data_total = 0;
    for (uint32_t i = 0; i < result->num_debug_dirs; i++) {
        if (result->debug_dirs[i].PointerToRawData != 0 &&
            result->debug_dirs[i].SizeOfData > 0) {
            debug_data_total += (uint32_t)sizeof(pe_debug_directory_t) + result->debug_dirs[i].SizeOfData;
        }
    }
    uint32_t debug_area_paddr = 0;
    if (debug_data_total > 0) {
        debug_area_paddr = shdrtab_paddr + num_shdrs * shdr_size;
        debug_area_paddr = (debug_area_paddr + 0xFFF) & ~0xFFF; /* 页对齐 */
    }

    uint32_t total_file_size = debug_data_total > 0 ?
        debug_area_paddr + debug_data_total :
        shdrtab_paddr + num_shdrs * shdr_size;

    /* 分配 ELF 文件缓冲区 */
    uint8_t *elf_buf = (uint8_t *)calloc(total_file_size, 1);
    if (!elf_buf) { free(seg_vaddrs); free(seg_paddrs); return -1; }

    /* --- 构建 ELF 头部 --- */
    Elf32_Ehdr *ehdr = (Elf32_Ehdr *)elf_buf;
    memcpy(ehdr->e_ident, ELFMAG, ELFMAG_LEN);
    ehdr->e_ident[4] = ELFCLASS32;
    ehdr->e_ident[5] = ELFDATA2LSB;
    ehdr->e_ident[6] = EV_CURRENT;
    ehdr->e_ident[7] = ELFOSABI_NONE;
    ehdr->e_type = (out_type == ELF_OUT_EXECUTABLE) ? ET_EXEC : ET_DYN;
    ehdr->e_machine = EM_386;
    ehdr->e_version = EV_CURRENT;

    /* 入口点: 在 ELF 虚拟地址空间中定位 PE 入口点 */
    {
        uint32_t ep_rva = result->nt.nt32->OptionalHeader.AddressOfEntryPoint;
        uint32_t elf_entry = 0;
        for (uint32_t s = 0; s < num_load; s++) {
            pe_section_header_t *sec = &result->sections[s];
            if (sec->VirtualAddress <= ep_rva &&
                ep_rva < sec->VirtualAddress + (sec->Misc.VirtualSize > sec->SizeOfRawData ? sec->Misc.VirtualSize : sec->SizeOfRawData)) {
                uint32_t offset_in_sec = ep_rva - sec->VirtualAddress;
                elf_entry = seg_vaddrs[s] + offset_in_sec;
                break;
            }
        }
        ehdr->e_entry = elf_entry;
        printf("[INFO] ELF entry: 0x%08X (PE RVA: 0x%08X)\n", elf_entry, ep_rva);
    }

    ehdr->e_phoff = ehdr_size;
    ehdr->e_shoff = shdrtab_paddr;
    ehdr->e_flags = 0;
    ehdr->e_ehsize = ehdr_size;
    ehdr->e_phentsize = phdr_size;
    ehdr->e_phnum = num_phdrs;
    ehdr->e_shentsize = shdr_size;
    ehdr->e_shnum = num_shdrs;
    ehdr->e_shstrndx = 1;

    /* --- 构建程序头 --- */
    Elf32_Phdr *phdrs = (Elf32_Phdr *)(elf_buf + ehdr_size);
    uint32_t ph_idx = 0;

    /*
     * PT_LOAD #0: 覆盖ELF头、程序头、.interp 等第一页元数据
     * 必须存在，否则动态链接器通过 AT_PHDR 访问程序头表时会触发段错误
     */
    {
        Elf32_Phdr *p = &phdrs[ph_idx++];
        p->p_type = PT_LOAD;
        p->p_offset = 0;
        p->p_vaddr = elf_base;
        p->p_paddr = elf_base;
        p->p_filesz = seg_paddrs[0];
        p->p_memsz = seg_paddrs[0];
        p->p_flags = PF_R;
        p->p_align = 0x1000;
        printf("[INFO]   LOAD seg: %-8s file_off=0x%08X vaddr=0x%08X filesz=0x%08X memsz=0x%08X flags=0x%X\n",
               "ELFHDR", p->p_offset, p->p_vaddr, p->p_filesz, p->p_memsz, p->p_flags);
    }

    /* PT_INTERP */
    if (has_interp) {
        Elf32_Phdr *p = &phdrs[ph_idx++];
        p->p_type = PT_INTERP;
        p->p_offset = interp_paddr;
        p->p_vaddr = elf_base + interp_paddr;
        p->p_paddr = elf_base + interp_paddr;
        p->p_filesz = interp_size;
        p->p_memsz = interp_size;
        p->p_flags = PF_R;
        p->p_align = 1;
        /* 写入解释器字符串 */
        sprintf((char *)(elf_buf + interp_paddr), "%s", ELF_INTERPRETER_32);
    }

    /* PT_LOAD for each PE section */
    for (uint32_t s = 0; s < num_sections; s++) {
        pe_section_header_t *sec = &result->sections[s];
        Elf32_Phdr *p = &phdrs[ph_idx++];

        uint32_t raw_size = sec->SizeOfRawData;
        uint32_t virt_size = sec->Misc.VirtualSize;
        uint32_t seg_file_size = raw_size > 0 ? raw_size : (virt_size > 0 ? virt_size : 0);
        uint32_t seg_mem_size = virt_size > raw_size ? virt_size : (raw_size > 0 ? raw_size : virt_size);
        if (seg_file_size == 0) seg_file_size = 0x1000;
        if (seg_mem_size == 0) seg_mem_size = 0x1000;

        /* PE 节属性 -> ELF 权限 */
        uint32_t flags = PF_R;
        if (sec->Characteristics & PE_IMAGE_SCN_MEM_WRITE) flags |= PF_W;
        if (sec->Characteristics & PE_IMAGE_SCN_MEM_EXECUTE) flags |= PF_X;

        /* 段类型判断 */
        char sec_name[9] = {0}; memcpy(sec_name, sec->Name, 8);
        p->p_type = PT_LOAD;
        p->p_offset = seg_paddrs[s];
        p->p_vaddr = seg_vaddrs[s];
        p->p_paddr = seg_vaddrs[s]; /* 物理地址 = 虚拟地址 (简化) */
        p->p_filesz = seg_file_size;
        p->p_memsz = seg_mem_size;
        p->p_flags = flags;
        p->p_align = 0x1000;

        printf("[INFO]   LOAD seg: %-8s file_off=0x%08X vaddr=0x%08X filesz=0x%08X memsz=0x%08X flags=0x%X\n",
               sec_name, p->p_offset, p->p_vaddr, p->p_filesz, p->p_memsz, p->p_flags);

        /* 复制原始段数据 */
        if (raw_size > 0 && sec->PointerToRawData + raw_size <= result->raw_size) {
            memcpy(elf_buf + seg_paddrs[s], result->raw_buf + sec->PointerToRawData, raw_size);
            /* BSS 清零 */
            if (virt_size > raw_size)
                memset(elf_buf + seg_paddrs[s] + raw_size, 0, virt_size - raw_size);
        } else {
            /* 空段: 分配一页零填充 */
            memset(elf_buf + seg_paddrs[s], 0, 0x1000);
        }
    }

    if (has_dynamic) {
        Elf32_Phdr *p = &phdrs[ph_idx++];
        p->p_type = PT_LOAD;
        p->p_offset = dyn_meta_paddr;
        p->p_vaddr = dyn_meta_vaddr;
        p->p_paddr = dyn_meta_vaddr;
        p->p_filesz = dyn_meta_size;
        p->p_memsz = dyn_meta_size;
        p->p_flags = PF_R | PF_W;
        p->p_align = 0x1000;
        printf("[INFO]   LOAD seg: %-8s file_off=0x%08X vaddr=0x%08X filesz=0x%08X memsz=0x%08X flags=0x%X\n",
               "DYNMETA", p->p_offset, p->p_vaddr, p->p_filesz, p->p_memsz, p->p_flags);
    }

    if (has_dynamic) {
        Elf32_Phdr *p = &phdrs[ph_idx++];
        p->p_type = PT_DYNAMIC;
        p->p_offset = dynamic_paddr;
        p->p_vaddr = dynamic_vaddr;
        p->p_paddr = dynamic_vaddr;
        p->p_filesz = dynamic_size;
        p->p_memsz = dynamic_size;
        p->p_flags = PF_R | PF_W;
        p->p_align = 4;
        printf("[INFO]   DYNAMIC seg: vaddr=0x%08X size=0x%08X\n", p->p_vaddr, dynamic_size);
    }

    /* --- 构建 SHDRTAB --- */
    Elf32_Shdr *shdrs = (Elf32_Shdr *)(elf_buf + shdrtab_paddr);
    memset(shdrs, 0, num_shdrs * shdr_size);

    /* 构建 .shstrtab 内容 */
    char *shstrtab = (char *)(elf_buf + shstrtab_paddr);
    memset(shstrtab, 0, shstrtab_size);
    uint32_t str_off = 1; /* skip null byte at index 0 */

    /* Section 0: null */
    shdrs[0].sh_name = 0;
    shdrs[0].sh_type = SHT_NULL;

    uint32_t sh_idx = 1;

    /* .shstrtab section */
    uint32_t shstrtab_name_off = str_off;
    strcpy(shstrtab + str_off, ".shstrtab");
    str_off += strlen(".shstrtab") + 1;

    shdrs[sh_idx].sh_name = shstrtab_name_off;
    shdrs[sh_idx].sh_type = SHT_STRTAB;
    shdrs[sh_idx].sh_flags = 0;
    shdrs[sh_idx].sh_addr = 0;
    shdrs[sh_idx].sh_offset = shstrtab_paddr;
    shdrs[sh_idx].sh_size = shstrtab_size;
    shdrs[sh_idx].sh_link = 0;
    shdrs[sh_idx].sh_info = 0;
    shdrs[sh_idx].sh_addralign = 1;
    shdrs[sh_idx].sh_entsize = 0;
    sh_idx++;

    /* PE sections as ELF sections */
    for (uint32_t s = 0; s < num_sections; s++) {
        pe_section_header_t *sec = &result->sections[s];
        char sec_name[9] = {0}; memcpy(sec_name, sec->Name, 8);

        uint32_t name_off = str_off;
        strcpy(shstrtab + str_off, sec_name);
        str_off += strlen(sec_name) + 1;

        Elf32_Shdr *sh = &shdrs[sh_idx];
        sh->sh_name = name_off;
        sh->sh_type = SHT_PROGBITS;
        sh->sh_flags = SHF_ALLOC;
        if (sec->Characteristics & PE_IMAGE_SCN_MEM_WRITE) sh->sh_flags |= SHF_WRITE;
        if (sec->Characteristics & PE_IMAGE_SCN_MEM_EXECUTE) sh->sh_flags |= SHF_EXECINSTR;
        sh->sh_addr = seg_vaddrs[s];
        sh->sh_offset = seg_paddrs[s];
        sh->sh_size = seg_paddrs[s] > 0 ?
            (sec->SizeOfRawData > 0 ? sec->SizeOfRawData : (sec->Misc.VirtualSize > 0 ? sec->Misc.VirtualSize : 0x1000))
            : 0x1000;
        sh->sh_link = 0;
        sh->sh_info = 0;
        sh->sh_addralign = 0x1000;
        sh->sh_entsize = 0;
        sh_idx++;
    }

    uint32_t dynstr_sh_idx = 0, dynsym_sh_idx = 0;
    if (has_dynamic) {
        uint32_t dynstr_name_off = str_off;
        strcpy(shstrtab + str_off, ".dynstr");
        str_off += strlen(".dynstr") + 1;
        dynstr_sh_idx = sh_idx;
        shdrs[sh_idx].sh_name = dynstr_name_off;
        shdrs[sh_idx].sh_type = SHT_STRTAB;
        shdrs[sh_idx].sh_flags = SHF_ALLOC;
        shdrs[sh_idx].sh_addr = dynstr_vaddr;
        shdrs[sh_idx].sh_offset = dynstr_paddr;
        shdrs[sh_idx].sh_size = dynstr_size;
        shdrs[sh_idx].sh_link = 0;
        shdrs[sh_idx].sh_info = 0;
        shdrs[sh_idx].sh_addralign = 1;
        shdrs[sh_idx].sh_entsize = 0;
        sh_idx++;

        uint32_t dynsym_name_off = str_off;
        strcpy(shstrtab + str_off, ".dynsym");
        str_off += strlen(".dynsym") + 1;
        dynsym_sh_idx = sh_idx;
        shdrs[sh_idx].sh_name = dynsym_name_off;
        shdrs[sh_idx].sh_type = SHT_DYNSYM;
        shdrs[sh_idx].sh_flags = SHF_ALLOC;
        shdrs[sh_idx].sh_addr = dynsym_vaddr;
        shdrs[sh_idx].sh_offset = dynsym_paddr;
        shdrs[sh_idx].sh_size = dynsym_size;
        shdrs[sh_idx].sh_link = dynstr_sh_idx;
        shdrs[sh_idx].sh_info = 1;
        shdrs[sh_idx].sh_addralign = 4;
        shdrs[sh_idx].sh_entsize = sizeof(Elf32_Sym);
        sh_idx++;

        uint32_t hash_name_off = str_off;
        strcpy(shstrtab + str_off, ".hash");
        str_off += strlen(".hash") + 1;
        shdrs[sh_idx].sh_name = hash_name_off;
        shdrs[sh_idx].sh_type = SHT_HASH;
        shdrs[sh_idx].sh_flags = SHF_ALLOC;
        shdrs[sh_idx].sh_addr = hash_vaddr;
        shdrs[sh_idx].sh_offset = hash_paddr;
        shdrs[sh_idx].sh_size = hash_size;
        shdrs[sh_idx].sh_link = dynsym_sh_idx;
        shdrs[sh_idx].sh_info = 0;
        shdrs[sh_idx].sh_addralign = 4;
        shdrs[sh_idx].sh_entsize = 4;
        sh_idx++;

        uint32_t dynamic_name_off = str_off;
        strcpy(shstrtab + str_off, ".dynamic");
        str_off += strlen(".dynamic") + 1;
        shdrs[sh_idx].sh_name = dynamic_name_off;
        shdrs[sh_idx].sh_type = SHT_DYNAMIC;
        shdrs[sh_idx].sh_flags = SHF_ALLOC | SHF_WRITE;
        shdrs[sh_idx].sh_addr = dynamic_vaddr;
        shdrs[sh_idx].sh_offset = dynamic_paddr;
        shdrs[sh_idx].sh_size = dynamic_size;
        shdrs[sh_idx].sh_link = dynstr_sh_idx;
        shdrs[sh_idx].sh_info = 0;
        shdrs[sh_idx].sh_addralign = 4;
        shdrs[sh_idx].sh_entsize = sizeof(Elf32_Dyn);
        sh_idx++;
    }

    /* .pe_debug section: 保留 PE 调试目录原始数据 */
    if (num_valid_debug > 0 && debug_data_total > 0) {
        uint32_t dbg_name_off = str_off;
        strcpy(shstrtab + str_off, ".pe_debug");
        str_off += strlen(".pe_debug") + 1;

        Elf32_Shdr *dbg_sh = &shdrs[sh_idx];
        dbg_sh->sh_name = dbg_name_off;
        dbg_sh->sh_type = SHT_PROGBITS;
        dbg_sh->sh_flags = 0;
        dbg_sh->sh_addr = 0;
        dbg_sh->sh_offset = debug_area_paddr;
        dbg_sh->sh_size = debug_data_total;
        dbg_sh->sh_link = 0;
        dbg_sh->sh_info = 0;
        dbg_sh->sh_addralign = 16;
        dbg_sh->sh_entsize = 0;

        /* 写入调试数据: 每个 debug directory 条目的原始数据块 */
        uint32_t dbg_write_ptr = debug_area_paddr;
        uint32_t dbg_entry_idx = 0;
        for (uint32_t i = 0; i < result->num_debug_dirs; i++) {
            pe_debug_directory_t *d = &result->debug_dirs[i];
            if (d->PointerToRawData != 0 && d->SizeOfData > 0) {
                if (d->PointerToRawData + d->SizeOfData <= result->raw_size) {
                    uint32_t hdr_size = sizeof(pe_debug_directory_t);
                    /* 写入调试目录头 (原始 PE_DEBUG_DIRECTORY) */
                    if (dbg_write_ptr + hdr_size + d->SizeOfData <= debug_area_paddr + debug_data_total) {
                        memcpy(elf_buf + dbg_write_ptr, d, hdr_size);
                        dbg_write_ptr += hdr_size;
                        /* 写入调试数据 */
                        memcpy(elf_buf + dbg_write_ptr,
                               result->raw_buf + d->PointerToRawData,
                               d->SizeOfData);
                        dbg_write_ptr += d->SizeOfData;
                        dbg_entry_idx++;
                        printf("[INFO]   Debug[%u]: Type=%u(%s) Size=%u Ptr=0x%08X -> ELF offset=0x%08X\n",
                               i, d->Type, pe_debug_type_name(d->Type),
                               d->SizeOfData, d->PointerToRawData,
                               dbg_write_ptr - d->SizeOfData - hdr_size);
                    }
                } else {
                    printf("[WARN]   Debug[%u]: Type=%u data out of bounds (Ptr=0x%08X Size=%u)\n",
                           i, d->Type, d->PointerToRawData, d->SizeOfData);
                }
            }
        }
        printf("[INFO]   Debug entries written: %u, total debug data: %u bytes\n",
               dbg_entry_idx, debug_data_total);
        sh_idx++;
    }

    if (has_dynamic) {
        memset(elf_buf + dyn_meta_paddr, 0, dyn_meta_size);
        elf_buf[dynstr_paddr] = 0;

        Elf32_Sym *sym = (Elf32_Sym *)(elf_buf + dynsym_paddr);
        memset(sym, 0, sizeof(Elf32_Sym));

        uint32_t *hash_words = (uint32_t *)(elf_buf + hash_paddr);
        hash_words[0] = 1;
        hash_words[1] = 1;
        hash_words[2] = 0;
        hash_words[3] = 0;

        Elf32_Dyn *dyn = (Elf32_Dyn *)(elf_buf + dynamic_paddr);
        uint32_t di = 0;
        dyn[di].d_tag = DT_HASH;   dyn[di].d_un.d_ptr = hash_vaddr; di++;
        dyn[di].d_tag = DT_STRTAB; dyn[di].d_un.d_ptr = dynstr_vaddr; di++;
        dyn[di].d_tag = DT_SYMTAB; dyn[di].d_un.d_ptr = dynsym_vaddr; di++;
        dyn[di].d_tag = DT_STRSZ;  dyn[di].d_un.d_val = dynstr_size; di++;
        dyn[di].d_tag = DT_SYMENT; dyn[di].d_un.d_val = sizeof(Elf32_Sym); di++;

        /* DT_NEEDED: 转换后的 .so 依赖 */
        uint32_t str_cur = 1; /* dynstr[0] 保留空串 */
        for (uint32_t i = 0; i < num_needed; i++) {
            size_t nlen = strlen(needed_names[i]);
            memcpy(elf_buf + dynstr_paddr + str_cur, needed_names[i], nlen + 1);
            dyn[di].d_tag = DT_NEEDED;
            dyn[di].d_un.d_val = str_cur;
            di++;
            str_cur += (uint32_t)nlen + 1;
        }

        /* DT_RUNPATH=$ORIGIN: 从可执行文件所在目录查找 .so */
        if (add_runpath) {
            const char *rp = "$ORIGIN";
            size_t rlen = strlen(rp);
            memcpy(elf_buf + dynstr_paddr + str_cur, rp, rlen + 1);
            dyn[di].d_tag = DT_RUNPATH;
            dyn[di].d_un.d_val = str_cur;
            di++;
            str_cur += (uint32_t)rlen + 1;
        }

        dyn[di].d_tag = DT_NULL;   dyn[di].d_un.d_val = 0; di++;
    }

    /* 写入文件 */
    printf("[Phase 8] Write ELF32 to disk: %s (%u bytes)\n", out_path, total_file_size);
    if (write_file_from_memory(out_path, elf_buf, total_file_size) != 0) {
        free(elf_buf); free(seg_vaddrs); free(seg_paddrs);
        return -1;
    }

    free(elf_buf); free(seg_vaddrs); free(seg_paddrs);

    /* 设置执行权限 */
    set_exec_perm(out_path);

    printf("[INFO] ELF32 created successfully: %s\n", out_path);
    return 0;
}

/* ================================================================
 * ELF 64 位构建
 *
 * 映射策略与 32 位相同，但使用 Elf64_* 结构体:
 *   - e_ident class = ELFCLASS64
 *   - 地址使用 uint64_t
 *   - 结构体大小不同 (Ehdr=64, Phdr=56, Shdr=64)
 * ================================================================ */

static int build_elf64(pe_parse_result_t *result, const char *out_path, elf_out_type_t out_type,
                       char **needed_names, uint32_t num_needed)
{
    uint16_t num_sections = result->num_sections;
    int num_valid_debug = count_valid_debug_entries(result);

    printf("[Phase 7] Build ELF64: %s (%u sections, %s, %d debug entries)\n",
           out_path, num_sections, out_type == ELF_OUT_EXECUTABLE ? "executable" : "shared library",
           num_valid_debug);

    uint64_t ehdr_size = 64;   /* sizeof(Elf64_Ehdr) */
    uint64_t phdr_size = 56;   /* sizeof(Elf64_Phdr) */
    uint64_t shdr_size = 64;   /* sizeof(Elf64_Shdr) */

    uint32_t has_dynamic = 1;
    uint32_t num_load = num_sections + (has_dynamic ? 1 : 0);
    uint32_t has_interp = (out_type == ELF_OUT_EXECUTABLE);
    /* +1 for the ELF-header PT_LOAD segment (covers Ehdr+Phdrs+interp in first page) */
    uint32_t num_phdrs = num_load + (has_interp ? 1 : 0) + (has_dynamic ? 1 : 0) + 1;

    uint32_t num_additional = 1 + 1 + (has_dynamic ? 4 : 0) + (num_valid_debug > 0 ? 1 : 0);
    uint32_t num_shdrs = num_sections + num_additional;

    /* x86_64 虚拟地址基址 */
    uint64_t elf_base = 0x00400000; /* Linux x86_64 经典基址 */
    if (out_type == ELF_OUT_SHARED) elf_base = 0;

    uint64_t *seg_vaddrs = (uint64_t *)calloc(num_load, sizeof(uint64_t));
    uint64_t *seg_paddrs = (uint64_t *)calloc(num_load, sizeof(uint64_t));
    if (!seg_vaddrs || !seg_paddrs) return -1;

    uint64_t header_end = ehdr_size + (uint64_t)num_phdrs * phdr_size;
    uint64_t cur_paddr = header_end;

    uint64_t interp_paddr = 0, interp_size = 0;
    const char *interp_path = ELF_INTERPRETER_64;
    if (has_interp) {
        interp_paddr = cur_paddr;
        interp_size = strlen(interp_path) + 1;
        cur_paddr += interp_size;
    }

    cur_paddr = align_up_u64(cur_paddr, 0x1000ULL);

    for (uint32_t i = 0; i < num_sections; i++) {
        pe_section_header_t *sec = &result->sections[i];
        uint64_t raw_size = sec->SizeOfRawData;
        uint64_t virt_size = sec->Misc.VirtualSize;
        uint64_t seg_size = raw_size > virt_size ? raw_size : virt_size;
        if (seg_size == 0) seg_size = 0x1000;

        seg_paddrs[i] = cur_paddr;
        seg_vaddrs[i] = elf_base + cur_paddr;

        cur_paddr = align_up_u64(cur_paddr + seg_size, 0x1000ULL);
    }

    uint64_t dyn_meta_paddr = 0, dyn_meta_vaddr = 0, dyn_meta_size = 0;
    uint64_t dynstr_paddr = 0, dynstr_vaddr = 0, dynstr_size = 0;
    uint64_t dynsym_paddr = 0, dynsym_vaddr = 0, dynsym_size = 0;
    uint64_t hash_paddr = 0, hash_vaddr = 0, hash_size = 0;
    uint64_t dynamic_paddr = 0, dynamic_vaddr = 0, dynamic_size = 0;
    /* 当存在 DT_NEEDED 时，加入 DT_RUNPATH=$ORIGIN 以便从可执行文件所在目录查找 .so */
    uint32_t add_runpath = (num_needed > 0) ? 1 : 0;
    if (has_dynamic) {
        uint64_t dynstr_off = 0;
        dynstr_size = 1;
        if (add_runpath) dynstr_size += (uint64_t)strlen("$ORIGIN") + 1;
        for (uint32_t i = 0; i < num_needed; i++)
            dynstr_size += (uint64_t)strlen(needed_names[i]) + 1;

        uint64_t dynsym_off = align_up_u64(dynstr_off + dynstr_size, 8);
        dynsym_size = sizeof(Elf64_Sym);

        uint64_t hash_off = align_up_u64(dynsym_off + dynsym_size, 8);
        uint64_t nbucket = 1, nchain = 1;
        hash_size = 4 * (2 + nbucket + nchain);

        uint64_t dynamic_off = align_up_u64(hash_off + hash_size, 8);
        uint64_t dyn_entries_count = 5 + num_needed + add_runpath + 1; /* tags + NEEDED + RUNPATH + NULL */
        dynamic_size = sizeof(Elf64_Dyn) * dyn_entries_count;

        dyn_meta_paddr = cur_paddr;
        dyn_meta_vaddr = elf_base + dyn_meta_paddr;
        dyn_meta_size = dynamic_off + dynamic_size;

        dynstr_paddr = dyn_meta_paddr + dynstr_off;
        dynstr_vaddr = dyn_meta_vaddr + dynstr_off;
        dynsym_paddr = dyn_meta_paddr + dynsym_off;
        dynsym_vaddr = dyn_meta_vaddr + dynsym_off;
        hash_paddr = dyn_meta_paddr + hash_off;
        hash_vaddr = dyn_meta_vaddr + hash_off;
        dynamic_paddr = dyn_meta_paddr + dynamic_off;
        dynamic_vaddr = dyn_meta_vaddr + dynamic_off;

        seg_paddrs[num_sections] = dyn_meta_paddr;
        seg_vaddrs[num_sections] = dyn_meta_vaddr;

        cur_paddr = align_up_u64(dyn_meta_paddr + dyn_meta_size, 0x1000ULL);
    }

    uint64_t shstrtab_paddr = cur_paddr;
    uint64_t shstrtab_size = 0;
    {
        shstrtab_size = 1;
        shstrtab_size += strlen(".shstrtab") + 1;
        if (has_dynamic) {
            shstrtab_size += strlen(".dynstr") + 1;
            shstrtab_size += strlen(".dynsym") + 1;
            shstrtab_size += strlen(".hash") + 1;
            shstrtab_size += strlen(".dynamic") + 1;
        }
        if (num_valid_debug > 0) {
            shstrtab_size += strlen(".pe_debug") + 1;
        }
        for (uint32_t i = 0; i < num_sections; i++) {
            char nm[9] = {0}; memcpy(nm, result->sections[i].Name, 8);
            shstrtab_size += strlen(nm) + 1;
        }
    }

    uint64_t shdrtab_paddr = shstrtab_paddr + shstrtab_size;
    shdrtab_paddr = (shdrtab_paddr + 0x3FF) & ~0x3FFULL;

    /* 计算调试数据总大小 */
    uint64_t debug_data_total = 0;
    for (uint32_t i = 0; i < result->num_debug_dirs; i++) {
        if (result->debug_dirs[i].PointerToRawData != 0 &&
            result->debug_dirs[i].SizeOfData > 0) {
            debug_data_total += (uint64_t)sizeof(pe_debug_directory_t) + result->debug_dirs[i].SizeOfData;
        }
    }
    uint64_t debug_area_paddr = 0;
    if (debug_data_total > 0) {
        debug_area_paddr = shdrtab_paddr + (uint64_t)num_shdrs * shdr_size;
        debug_area_paddr = (debug_area_paddr + 0xFFFULL) & ~0xFFFULL;
    }

    uint64_t total_file_size = debug_data_total > 0 ?
        debug_area_paddr + debug_data_total :
        shdrtab_paddr + (uint64_t)num_shdrs * shdr_size;

    uint8_t *elf_buf = (uint8_t *)calloc(total_file_size, 1);
    if (!elf_buf) { free(seg_vaddrs); free(seg_paddrs); return -1; }

    /* --- ELF 头部 --- */
    Elf64_Ehdr *ehdr = (Elf64_Ehdr *)elf_buf;
    memcpy(ehdr->e_ident, ELFMAG, ELFMAG_LEN);
    ehdr->e_ident[4] = ELFCLASS64;
    ehdr->e_ident[5] = ELFDATA2LSB;
    ehdr->e_ident[6] = EV_CURRENT;
    ehdr->e_ident[7] = ELFOSABI_NONE;
    ehdr->e_type = (out_type == ELF_OUT_EXECUTABLE) ? ET_EXEC : ET_DYN;
    ehdr->e_machine = EM_X86_64;
    ehdr->e_version = EV_CURRENT;

    {
        uint32_t ep_rva = result->nt.nt64->OptionalHeader.AddressOfEntryPoint;
        uint64_t elf_entry = 0;
        for (uint32_t s = 0; s < num_load; s++) {
            pe_section_header_t *sec = &result->sections[s];
            uint32_t sec_end = sec->VirtualAddress +
                (sec->Misc.VirtualSize > sec->SizeOfRawData ? sec->Misc.VirtualSize : sec->SizeOfRawData);
            if (sec->VirtualAddress <= ep_rva && ep_rva < sec_end) {
                uint64_t offset_in_sec = ep_rva - sec->VirtualAddress;
                elf_entry = seg_vaddrs[s] + offset_in_sec;
                break;
            }
        }
        ehdr->e_entry = elf_entry;
        printf("[INFO] ELF entry: 0x%016llX (PE RVA: 0x%08X)\n", (unsigned long long)elf_entry, ep_rva);
    }

    ehdr->e_phoff = ehdr_size;
    ehdr->e_shoff = shdrtab_paddr;
    ehdr->e_flags = 0;
    ehdr->e_ehsize = ehdr_size;
    ehdr->e_phentsize = phdr_size;
    ehdr->e_phnum = num_phdrs;
    ehdr->e_shentsize = shdr_size;
    ehdr->e_shnum = num_shdrs;
    ehdr->e_shstrndx = 1;

    /* --- 程序头 --- */
    Elf64_Phdr *phdrs = (Elf64_Phdr *)(elf_buf + ehdr_size);
    uint32_t ph_idx = 0;

    /*
     * PT_LOAD #0: 覆盖ELF头、程序头、.interp 等第一页元数据
     * 必须存在，否则动态链接器通过 AT_PHDR 访问程序头表时会触发段错误
     */
    {
        Elf64_Phdr *p = &phdrs[ph_idx++];
        p->p_type = PT_LOAD;
        p->p_flags = PF_R;
        p->p_offset = 0;
        p->p_vaddr = elf_base;
        p->p_paddr = elf_base;
        p->p_filesz = seg_paddrs[0];
        p->p_memsz = seg_paddrs[0];
        p->p_align = 0x1000;
        printf("[INFO]   LOAD seg: %-8s file_off=0x%016llX vaddr=0x%016llX filesz=0x%016llX memsz=0x%016llX flags=0x%X\n",
               "ELFHDR", (unsigned long long)p->p_offset, (unsigned long long)p->p_vaddr,
               (unsigned long long)p->p_filesz, (unsigned long long)p->p_memsz, (unsigned)p->p_flags);
    }

    if (has_interp) {
        Elf64_Phdr *p = &phdrs[ph_idx++];
        p->p_type = PT_INTERP;
        p->p_flags = PF_R;
        p->p_offset = interp_paddr;
        p->p_vaddr = elf_base + interp_paddr;
        p->p_paddr = elf_base + interp_paddr;
        p->p_filesz = interp_size;
        p->p_memsz = interp_size;
        p->p_align = 1;
        sprintf((char *)(elf_buf + interp_paddr), "%s", interp_path);
    }

    for (uint32_t s = 0; s < num_sections; s++) {
        pe_section_header_t *sec = &result->sections[s];
        Elf64_Phdr *p = &phdrs[ph_idx++];

        uint64_t raw_size = sec->SizeOfRawData;
        uint64_t virt_size = sec->Misc.VirtualSize;
        uint64_t seg_file_size = raw_size > 0 ? raw_size : (virt_size > 0 ? virt_size : 0);
        uint64_t seg_mem_size = virt_size > raw_size ? virt_size : (raw_size > 0 ? raw_size : virt_size);
        if (seg_file_size == 0) seg_file_size = 0x1000;
        if (seg_mem_size == 0) seg_mem_size = 0x1000;

        uint32_t flags = PF_R;
        if (sec->Characteristics & PE_IMAGE_SCN_MEM_WRITE) flags |= PF_W;
        if (sec->Characteristics & PE_IMAGE_SCN_MEM_EXECUTE) flags |= PF_X;

        char sec_name[9] = {0}; memcpy(sec_name, sec->Name, 8);
        p->p_type = PT_LOAD;
        p->p_flags = flags;
        p->p_offset = seg_paddrs[s];
        p->p_vaddr = seg_vaddrs[s];
        p->p_paddr = seg_vaddrs[s];
        p->p_filesz = seg_file_size;
        p->p_memsz = seg_mem_size;
        p->p_align = 0x1000;

        printf("[INFO]   LOAD seg: %-8s file_off=0x%016llX vaddr=0x%016llX filesz=0x%016llX memsz=0x%016llX flags=0x%X\n",
               sec_name, (unsigned long long)p->p_offset, (unsigned long long)p->p_vaddr,
               (unsigned long long)p->p_filesz, (unsigned long long)p->p_memsz, flags);

        if (raw_size > 0 && sec->PointerToRawData + raw_size <= result->raw_size) {
            memcpy(elf_buf + seg_paddrs[s], result->raw_buf + sec->PointerToRawData, raw_size);
            if (virt_size > raw_size)
                memset(elf_buf + seg_paddrs[s] + raw_size, 0, virt_size - raw_size);
        } else {
            memset(elf_buf + seg_paddrs[s], 0, 0x1000);
        }
    }

    if (has_dynamic) {
        Elf64_Phdr *p = &phdrs[ph_idx++];
        p->p_type = PT_LOAD;
        p->p_flags = PF_R | PF_W;
        p->p_offset = dyn_meta_paddr;
        p->p_vaddr = dyn_meta_vaddr;
        p->p_paddr = dyn_meta_vaddr;
        p->p_filesz = dyn_meta_size;
        p->p_memsz = dyn_meta_size;
        p->p_align = 0x1000;
        printf("[INFO]   LOAD seg: %-8s file_off=0x%016llX vaddr=0x%016llX filesz=0x%016llX memsz=0x%016llX flags=0x%X\n",
               "DYNMETA", (unsigned long long)p->p_offset, (unsigned long long)p->p_vaddr,
               (unsigned long long)p->p_filesz, (unsigned long long)p->p_memsz, (unsigned)p->p_flags);
    }

    if (has_dynamic) {
        Elf64_Phdr *p = &phdrs[ph_idx++];
        p->p_type = PT_DYNAMIC;
        p->p_flags = PF_R | PF_W;
        p->p_offset = dynamic_paddr;
        p->p_vaddr = dynamic_vaddr;
        p->p_paddr = dynamic_vaddr;
        p->p_filesz = dynamic_size;
        p->p_memsz = dynamic_size;
        p->p_align = 8;
        printf("[INFO]   DYNAMIC seg: vaddr=0x%016llX size=0x%016llX\n",
               (unsigned long long)p->p_vaddr, (unsigned long long)dynamic_size);
    }

    /* --- SHDRTAB --- */
    Elf64_Shdr *shdrs = (Elf64_Shdr *)(elf_buf + shdrtab_paddr);
    memset(shdrs, 0, num_shdrs * shdr_size);

    char *shstrtab = (char *)(elf_buf + shstrtab_paddr);
    memset(shstrtab, 0, shstrtab_size);
    uint64_t str_off = 1;

    shdrs[0].sh_name = 0;
    shdrs[0].sh_type = SHT_NULL;

    uint32_t sh_idx = 1;

    uint64_t shstrtab_name_off = str_off;
    strcpy(shstrtab + str_off, ".shstrtab");
    str_off += strlen(".shstrtab") + 1;

    shdrs[sh_idx].sh_name = shstrtab_name_off;
    shdrs[sh_idx].sh_type = SHT_STRTAB;
    shdrs[sh_idx].sh_flags = 0;
    shdrs[sh_idx].sh_addr = 0;
    shdrs[sh_idx].sh_offset = shstrtab_paddr;
    shdrs[sh_idx].sh_size = shstrtab_size;
    shdrs[sh_idx].sh_link = 0;
    shdrs[sh_idx].sh_info = 0;
    shdrs[sh_idx].sh_addralign = 1;
    shdrs[sh_idx].sh_entsize = 0;
    sh_idx++;

    for (uint32_t s = 0; s < num_sections; s++) {
        pe_section_header_t *sec = &result->sections[s];
        char sec_name[9] = {0}; memcpy(sec_name, sec->Name, 8);

        uint64_t name_off = str_off;
        strcpy(shstrtab + str_off, sec_name);
        str_off += strlen(sec_name) + 1;

        Elf64_Shdr *sh = &shdrs[sh_idx];
        sh->sh_name = name_off;
        sh->sh_type = SHT_PROGBITS;
        sh->sh_flags = SHF_ALLOC;
        if (sec->Characteristics & PE_IMAGE_SCN_MEM_WRITE) sh->sh_flags |= SHF_WRITE;
        if (sec->Characteristics & PE_IMAGE_SCN_MEM_EXECUTE) sh->sh_flags |= SHF_EXECINSTR;
        sh->sh_addr = seg_vaddrs[s];
        sh->sh_offset = seg_paddrs[s];
        sh->sh_size = seg_paddrs[s] > 0 ?
            (sec->SizeOfRawData > 0 ? sec->SizeOfRawData : (sec->Misc.VirtualSize > 0 ? sec->Misc.VirtualSize : 0x1000))
            : 0x1000;
        sh->sh_link = 0;
        sh->sh_info = 0;
        sh->sh_addralign = 0x1000;
        sh->sh_entsize = 0;
        sh_idx++;
    }

    uint32_t dynstr_sh_idx = 0, dynsym_sh_idx = 0;
    if (has_dynamic) {
        uint64_t dynstr_name_off = str_off;
        strcpy(shstrtab + str_off, ".dynstr");
        str_off += strlen(".dynstr") + 1;
        dynstr_sh_idx = sh_idx;
        shdrs[sh_idx].sh_name = (uint32_t)dynstr_name_off;
        shdrs[sh_idx].sh_type = SHT_STRTAB;
        shdrs[sh_idx].sh_flags = SHF_ALLOC;
        shdrs[sh_idx].sh_addr = dynstr_vaddr;
        shdrs[sh_idx].sh_offset = dynstr_paddr;
        shdrs[sh_idx].sh_size = dynstr_size;
        shdrs[sh_idx].sh_link = 0;
        shdrs[sh_idx].sh_info = 0;
        shdrs[sh_idx].sh_addralign = 1;
        shdrs[sh_idx].sh_entsize = 0;
        sh_idx++;

        uint64_t dynsym_name_off = str_off;
        strcpy(shstrtab + str_off, ".dynsym");
        str_off += strlen(".dynsym") + 1;
        dynsym_sh_idx = sh_idx;
        shdrs[sh_idx].sh_name = (uint32_t)dynsym_name_off;
        shdrs[sh_idx].sh_type = SHT_DYNSYM;
        shdrs[sh_idx].sh_flags = SHF_ALLOC;
        shdrs[sh_idx].sh_addr = dynsym_vaddr;
        shdrs[sh_idx].sh_offset = dynsym_paddr;
        shdrs[sh_idx].sh_size = dynsym_size;
        shdrs[sh_idx].sh_link = dynstr_sh_idx;
        shdrs[sh_idx].sh_info = 1;
        shdrs[sh_idx].sh_addralign = 8;
        shdrs[sh_idx].sh_entsize = sizeof(Elf64_Sym);
        sh_idx++;

        uint64_t hash_name_off = str_off;
        strcpy(shstrtab + str_off, ".hash");
        str_off += strlen(".hash") + 1;
        shdrs[sh_idx].sh_name = (uint32_t)hash_name_off;
        shdrs[sh_idx].sh_type = SHT_HASH;
        shdrs[sh_idx].sh_flags = SHF_ALLOC;
        shdrs[sh_idx].sh_addr = hash_vaddr;
        shdrs[sh_idx].sh_offset = hash_paddr;
        shdrs[sh_idx].sh_size = hash_size;
        shdrs[sh_idx].sh_link = dynsym_sh_idx;
        shdrs[sh_idx].sh_info = 0;
        shdrs[sh_idx].sh_addralign = 8;
        shdrs[sh_idx].sh_entsize = 4;
        sh_idx++;

        uint64_t dynamic_name_off = str_off;
        strcpy(shstrtab + str_off, ".dynamic");
        str_off += strlen(".dynamic") + 1;
        shdrs[sh_idx].sh_name = (uint32_t)dynamic_name_off;
        shdrs[sh_idx].sh_type = SHT_DYNAMIC;
        shdrs[sh_idx].sh_flags = SHF_ALLOC | SHF_WRITE;
        shdrs[sh_idx].sh_addr = dynamic_vaddr;
        shdrs[sh_idx].sh_offset = dynamic_paddr;
        shdrs[sh_idx].sh_size = dynamic_size;
        shdrs[sh_idx].sh_link = dynstr_sh_idx;
        shdrs[sh_idx].sh_info = 0;
        shdrs[sh_idx].sh_addralign = 8;
        shdrs[sh_idx].sh_entsize = sizeof(Elf64_Dyn);
        sh_idx++;
    }

    /* .pe_debug section: 保留 PE 调试目录原始数据 */
    if (num_valid_debug > 0 && debug_data_total > 0) {
        uint64_t dbg_name_off = str_off;
        strcpy(shstrtab + str_off, ".pe_debug");
        str_off += strlen(".pe_debug") + 1;

        Elf64_Shdr *dbg_sh = &shdrs[sh_idx];
        dbg_sh->sh_name = dbg_name_off;
        dbg_sh->sh_type = SHT_PROGBITS;
        dbg_sh->sh_flags = 0;
        dbg_sh->sh_addr = 0;
        dbg_sh->sh_offset = debug_area_paddr;
        dbg_sh->sh_size = debug_data_total;
        dbg_sh->sh_link = 0;
        dbg_sh->sh_info = 0;
        dbg_sh->sh_addralign = 16;
        dbg_sh->sh_entsize = 0;

        uint64_t dbg_write_ptr = debug_area_paddr;
        uint32_t dbg_entry_idx = 0;
        for (uint32_t i = 0; i < result->num_debug_dirs; i++) {
            pe_debug_directory_t *d = &result->debug_dirs[i];
            if (d->PointerToRawData != 0 && d->SizeOfData > 0) {
                if (d->PointerToRawData + d->SizeOfData <= result->raw_size) {
                    uint64_t hdr_size = sizeof(pe_debug_directory_t);
                    if (dbg_write_ptr + hdr_size + d->SizeOfData <= debug_area_paddr + debug_data_total) {
                        memcpy(elf_buf + dbg_write_ptr, d, hdr_size);
                        dbg_write_ptr += hdr_size;
                        memcpy(elf_buf + dbg_write_ptr,
                               result->raw_buf + d->PointerToRawData,
                               d->SizeOfData);
                        dbg_write_ptr += d->SizeOfData;
                        dbg_entry_idx++;
                        printf("[INFO]   Debug[%u]: Type=%u(%s) Size=%u Ptr=0x%08X -> ELF offset=0x%016llX\n",
                               i, d->Type, pe_debug_type_name(d->Type),
                               d->SizeOfData, d->PointerToRawData,
                               (unsigned long long)(dbg_write_ptr - d->SizeOfData - hdr_size));
                    }
                } else {
                    printf("[WARN]   Debug[%u]: Type=%u data out of bounds (Ptr=0x%08X Size=%u)\n",
                           i, d->Type, d->PointerToRawData, d->SizeOfData);
                }
            }
        }
        printf("[INFO]   Debug entries written: %u, total debug data: %llu bytes\n",
               dbg_entry_idx, (unsigned long long)debug_data_total);
        sh_idx++;
    }

    if (has_dynamic) {
        memset(elf_buf + dyn_meta_paddr, 0, dyn_meta_size);
        elf_buf[dynstr_paddr] = 0;

        Elf64_Sym *sym = (Elf64_Sym *)(elf_buf + dynsym_paddr);
        memset(sym, 0, sizeof(Elf64_Sym));

        uint32_t *hash_words = (uint32_t *)(elf_buf + hash_paddr);
        hash_words[0] = 1;
        hash_words[1] = 1;
        hash_words[2] = 0;
        hash_words[3] = 0;

        Elf64_Dyn *dyn = (Elf64_Dyn *)(elf_buf + dynamic_paddr);
        uint64_t di = 0;
        dyn[di].d_tag = DT_HASH;   dyn[di].d_un.d_ptr = hash_vaddr; di++;
        dyn[di].d_tag = DT_STRTAB; dyn[di].d_un.d_ptr = dynstr_vaddr; di++;
        dyn[di].d_tag = DT_SYMTAB; dyn[di].d_un.d_ptr = dynsym_vaddr; di++;
        dyn[di].d_tag = DT_STRSZ;  dyn[di].d_un.d_val = dynstr_size; di++;
        dyn[di].d_tag = DT_SYMENT; dyn[di].d_un.d_val = sizeof(Elf64_Sym); di++;

        /* DT_NEEDED: 转换后的 .so 依赖 */
        uint64_t str_cur = 1; /* dynstr[0] 保留空串 */
        for (uint32_t i = 0; i < num_needed; i++) {
            size_t nlen = strlen(needed_names[i]);
            memcpy(elf_buf + dynstr_paddr + str_cur, needed_names[i], nlen + 1);
            dyn[di].d_tag = DT_NEEDED;
            dyn[di].d_un.d_val = str_cur;
            di++;
            str_cur += (uint64_t)nlen + 1;
        }

        /* DT_RUNPATH=$ORIGIN: 从可执行文件所在目录查找 .so */
        if (add_runpath) {
            const char *rp = "$ORIGIN";
            size_t rlen = strlen(rp);
            memcpy(elf_buf + dynstr_paddr + str_cur, rp, rlen + 1);
            dyn[di].d_tag = DT_RUNPATH;
            dyn[di].d_un.d_val = str_cur;
            di++;
            str_cur += (uint64_t)rlen + 1;
        }

        dyn[di].d_tag = DT_NULL;   dyn[di].d_un.d_val = 0; di++;
    }

    printf("[Phase 8] Write ELF64 to disk: %s (%llu bytes)\n", out_path, (unsigned long long)total_file_size);
    if (write_file_from_memory(out_path, elf_buf, total_file_size) != 0) {
        free(elf_buf); free(seg_vaddrs); free(seg_paddrs);
        return -1;
    }

    free(elf_buf); free(seg_vaddrs); free(seg_paddrs);
    set_exec_perm(out_path);

    printf("[INFO] ELF64 created successfully: %s\n", out_path);
    return 0;
}

/* ================================================================
 * 通用转换入口 (根据架构分派)
 * ================================================================ */

static int convert_pe_to_elf(pe_parse_result_t *result, const char *out_path, elf_out_type_t out_type,
                             char **needed_names, uint32_t num_needed)
{
    if (result->arch == PE_ARCH_X86) {
        return build_elf32(result, out_path, out_type, needed_names, num_needed);
    } else {
        return build_elf64(result, out_path, out_type, needed_names, num_needed);
    }
}

/* ================================================================
 * 资源文件复制 (非 PE 文件)
 * ================================================================ */

static void copy_resource_files(const char *src_dir, const char *dst_dir, const char *skip_dir)
{
    DIR *dir = opendir(src_dir);
    if (!dir) return;

    struct dirent *entry;
    while ((entry = readdir(dir)) != NULL) {
        char name_buf[4096];
        memset(name_buf, 0, sizeof(name_buf));
        strncpy(name_buf, entry->d_name, sizeof(name_buf) - 1);

        if (strcmp(name_buf, ".") == 0 || strcmp(name_buf, "..") == 0) continue;

        char src_path[8192], dst_path[8192];
        snprintf(src_path, sizeof(src_path), "%s/%s", src_dir, name_buf);
        snprintf(dst_path, sizeof(dst_path), "%s/%s", dst_dir, name_buf);

        struct stat st;
        if (lstat(src_path, &st) != 0) continue;

        if (S_ISDIR(st.st_mode)) {
            /* 不递归进输出目录, 避免把已转换的 .so/ELF 又复制到子目录里 */
            if (skip_dir && strcmp(src_path, skip_dir) == 0) continue;
            mkdir(dst_path, 0755);
            copy_resource_files(src_path, dst_path, skip_dir);
        } else if (S_ISREG(st.st_mode)) {
            if (!is_pe_file_ext(name_buf) || !is_pe_file_magic(src_path)) {
                printf("[INFO] Copy resource: %s -> %s\n", src_path, dst_path);
                file_copy_binary(src_path, dst_path);
            }
        }
    }
    closedir(dir);
}

/* ================================================================
 * 主转换流程
 * ================================================================ */

/* 计算 pe_path 相对于 src_root 的子目录 (不含文件名, 直接位于 src_root 下则为空串)。
 * 用于在输出目录中保留源目录的相对结构。 */
static void get_rel_subdir(const char *pe_path, const char *src_root, char *out, size_t out_sz)
{
    out[0] = '\0';
    if (!src_root || out_sz == 0) return;

    size_t rl = strlen(src_root);
    if (strncmp(pe_path, src_root, rl) != 0) return; /* 前缀不匹配, 退回平铺 */
    if (pe_path[rl] != '/') return;                  /* 前缀不完整 */
    const char *rest = pe_path + rl + 1;             /* 跳过 src_root/ */

    const char *slash = strrchr(rest, '/');
    if (!slash) return;                              /* 直接位于 src_root 下 */

    size_t dlen = (size_t)(slash - rest);
    if (dlen >= out_sz) dlen = out_sz - 1;
    memcpy(out, rest, dlen);
    out[dlen] = '\0';
}

static int convert_file_or_dll(const char *pe_path, const char *out_dir, const char *src_root,
                                dll_scan_data_t *scan, int is_main_exe, int depth)
{
    pe_parse_result_t result;
    printf("\n%s[Convert] %s%s\n", depth > 0 ? "  " : "", pe_path, depth > 0 ? " (DLL)" : "");

    /* 源路径去重: 同一 DLL 只转换一次 (防止重复转换与循环依赖死递归) */
    if (!is_main_exe) {
        if (dll_scan_data_is_converted_src(scan, pe_path))
            return 0;
        dll_scan_data_mark_converted_src(scan, pe_path);
    }

    if (pe_parse_file(pe_path, &result) != 0) {
        fprintf(stderr, "[ERROR] Failed to parse PE: %s\n", pe_path);
        return -1;
    }

    /* 确定输出路径 */
    const char *base_name = strrchr(pe_path, '/');
    base_name = base_name ? base_name + 1 : pe_path;
    char out_name[4096];
    strncpy(out_name, base_name, sizeof(out_name) - 1);
    out_name[sizeof(out_name) - 1] = '\0';

    elf_out_type_t out_type;
    if (is_main_exe) {
        out_type = ELF_OUT_EXECUTABLE;
        /* EXE 扩展名保持不变, 但 ELF 没有扩展名 */
        char *dot = strrchr(out_name, '.');
        if (dot) *dot = '\0';
    } else {
        out_type = ELF_OUT_SHARED;
        /* DLL -> .so */
        char *dot = strrchr(out_name, '.');
        if (dot) strcpy(dot, ".so");
        else strcat(out_name, ".so");
    }

    /* 输出路径: 保留 pe_path 相对 src_root 的子目录结构, 使子目录里的 DLL 也落到对应子目录 */
    char out_path[8192];
    char rel_dir[4096];
    get_rel_subdir(pe_path, src_root, rel_dir, sizeof(rel_dir));
    if (rel_dir[0])
        snprintf(out_path, sizeof(out_path), "%s/%s/%s", out_dir, rel_dir, out_name);
    else
        snprintf(out_path, sizeof(out_path), "%s/%s", out_dir, out_name);

    /* 创建输出目录 */
    char *out_dir_copy = strdup(out_path);
    char *last_slash = strrchr(out_dir_copy, '/');
    if (last_slash) { *last_slash = '\0'; make_dirs_recursive(out_dir_copy); }
    free(out_dir_copy);

    /* 处理导入的 DLL 依赖 (仅主 EXE 和 DLL 的递归依赖) */
    if (result.has_imports && depth < 5) {
        printf("\n[Phase 9] Process import dependencies (%u DLLs)\n", result.num_imports);
        for (uint32_t i = 0; i < result.num_imports; i++) {
            uint64_t name_off = rva_to_file_offset(&result, result.import_descs[i].Name);
            const char *name_str = (name_off > 0) ? (const char *)(result.raw_buf + name_off) : "<unknown>";
            char dll_name[256];
            strncpy(dll_name, name_str, sizeof(dll_name) - 1);
            dll_name[sizeof(dll_name) - 1] = '\0';

            printf("[INFO] Import DLL: %s\n", dll_name);

            char *dll_path = NULL;
            find_dll_path(scan, dll_name, &dll_path);

            if (dll_path) {
                printf("[INFO]   Found at: %s\n", dll_path);
                convert_file_or_dll(dll_path, out_dir, src_root, scan, 0, depth + 1);
                free(dll_path);
            } else {
                printf("[WARN]   NOT FOUND in directory tree: %s (skipping)\n", dll_name);
                dll_scan_data_add_missing(scan, dll_name);
            }
        }
    } else if (result.has_imports) {
        printf("[INFO]   (max recursion depth reached, skipping further DLL deps)\n");
    }

    /* 主程序: 从已转换的 DLL 列表构建 DT_NEEDED (导入表)
     * 必须在此处转换之后执行，此时 scan->converted 已包含全部转换出的 .so */
    char **needed = NULL;
    uint32_t num_needed = 0;
    if (is_main_exe && scan->converted_count > 0) {
        uint32_t cap = scan->converted_count;
        needed = (char **)calloc(cap, sizeof(char *));
        if (needed) {
            for (uint32_t i = 0; i < cap; i++) {
                const char *p = scan->converted[i];
                /* DT_NEEDED 用相对 out_dir 的路径, 配合 RUNPATH=$ORIGIN
                 * 才能解析到子目录里的 .so (如 platforms/qwindows.so) */
                const char *rel = p;
                size_t odlen = strlen(out_dir);
                if (strncmp(p, out_dir, odlen) == 0 && p[odlen] == '/')
                    rel = p + odlen + 1;
                int dup = 0;
                for (uint32_t j = 0; j < num_needed; j++) {
                    if (strcmp(needed[j], rel) == 0) { dup = 1; break; }
                }
                if (dup) continue;
                needed[num_needed] = strdup(rel);
                if (needed[num_needed]) num_needed++;
            }
            if (num_needed > 0) {
                printf("\n[INFO] DT_NEEDED (converted .so) libraries (%u):\n", num_needed);
                for (uint32_t i = 0; i < num_needed; i++)
                    printf("[INFO]   %s\n", needed[i]);
            }
        } else {
            num_needed = 0;
        }
    }

    /* 执行转换 */
    if (convert_pe_to_elf(&result, out_path, out_type, needed, num_needed) != 0) {
        fprintf(stderr, "[ERROR] Failed to convert: %s\n", pe_path);
        for (uint32_t i = 0; i < num_needed; i++) free(needed[i]);
        free(needed);
        pe_parse_result_free(&result);
        return -1;
    }

    /* 如果是 DLL, 记录已转换 */
    if (!is_main_exe) {
        dll_scan_data_add_converted(scan, out_path);
    }

    for (uint32_t i = 0; i < num_needed; i++) free(needed[i]);
    free(needed);

    pe_parse_result_free(&result);
    return 0;
}

/* ================================================================
 * main
 * ================================================================ */

int main(int argc, char *argv[])
{
    if (argc < 2) {
        fprintf(stderr, "Usage: %s <target.exe>\n", argv[0]);
        fprintf(stderr, "  PE to ELF offline binary converter\n");
        fprintf(stderr, "  Supports: x86 (32-bit) and x86_64 (64-bit) PE files\n");
        return 1;
    }

    const char *pe_file = argv[1];

    printf("========================================\n");
    printf("  PE -> ELF 离线二进制转换工具\n");
    printf("  Target: %s\n", pe_file);
    printf("========================================\n");

    /* 检查文件 */
    if (!is_pe_file_magic(pe_file)) {
        fprintf(stderr, "[ERROR] Not a valid PE file (MZ magic check failed): %s\n", pe_file);
        return 1;
    }

    /* 获取 EXE 所在目录 */
    char *pe_dir = strdup(pe_file);
    char *slash = strrchr(pe_dir, '/');
    if (slash) *slash = '\0';
    else strcpy(pe_dir, ".");

    /* 获取 EXE 基名 */
    const char *base_name = strrchr(pe_file, '/');
    base_name = base_name ? base_name + 1 : pe_file;

    /* 构建输出目录: 原文件名_elf */
    char out_dir[8192];
    snprintf(out_dir, sizeof(out_dir), "%s/%s_elf", pe_dir, base_name);
    char *dot = strrchr(out_dir, '.');
    if (dot) *dot = '\0';

    printf("[INFO] Source directory: %s\n", pe_dir);
    printf("[INFO] Output directory: %s\n", out_dir);

    /* 创建输出目录 */
    if (make_dirs_recursive(out_dir) != 0) {
        fprintf(stderr, "[ERROR] Failed to create output directory: %s\n", out_dir);
        free(pe_dir);
        return 1;
    }

    /* 扫描 DLL 文件 */
    printf("\n[Phase 0] Scan for DLL files recursively in: %s\n", pe_dir);
    dll_scan_data_t scan;
    dll_scan_data_init(&scan);

    char **dll_list = NULL;
    uint32_t dll_count = 0, dll_cap = 0;
    if (scan_dll_dir_recursive(pe_dir, &dll_list, &dll_count, &dll_cap) != 0) {
        fprintf(stderr, "[WARN] DLL scan encountered errors\n");
    }

    /* 将扫描结果存入 scan 结构 */
    scan.paths = dll_list;
    scan.count = dll_count;
    scan.cap = dll_cap;

    printf("[INFO] Found %u DLL files\n", dll_count);
    for (uint32_t i = 0; i < dll_count; i++)
        printf("[INFO]   DLL[%u]: %s\n", i, dll_list[i]);

    /* 先转换所有扫描到的 DLL (含子目录里的 Qt 插件等, 不依赖导入链),
     * 并按相对目录结构落到输出子目录。去重逻辑保证每个 DLL 只转一次。 */
    printf("\n[Phase 9] Convert all scanned DLLs (%u)\n", scan.count);
    for (uint32_t i = 0; i < scan.count; i++) {
        convert_file_or_dll(scan.paths[i], out_dir, pe_dir, &scan, 0, 0);
    }

    /* 最后转换主程序: 此时所有 DLL 已转换, DT_NEEDED 将包含全部 .so 的相对路径 */
    int rc = convert_file_or_dll(pe_file, out_dir, pe_dir, &scan, 1, 0);

    /* 复制资源文件 (跳过输出目录本身, 避免把转换结果又拷进去) */
    printf("\n[Phase 10] Copy non-PE resource files\n");
    copy_resource_files(pe_dir, out_dir, out_dir);

    /* 输出缺失 DLL 清单 */
    if (scan.missing_count > 0) {
        printf("\n========================================\n");
        printf("  MISSING DLL LIST (%u):\n", scan.missing_count);
        for (uint32_t i = 0; i < scan.missing_count; i++)
            printf("    - %s\n", scan.missing[i]);
        printf("  These imports have been removed from the ELF.\n");
        printf("========================================\n");
    }

    /* 输出统计 */
    printf("\n========================================\n");
    printf("  Conversion complete!\n");
    printf("  Output: %s\n", out_dir);
    printf("  Converted DLLs: %u\n", scan.converted_count);
    printf("  Missing DLLs:   %u\n", scan.missing_count);
    printf("  Status: %s\n", rc == 0 ? "SUCCESS" : "PARTIAL FAILURE");
    printf("========================================\n");

    dll_scan_data_free(&scan);
    free(pe_dir);
    return rc == 0 ? 0 : 1;
}

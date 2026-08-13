/*
 * pe_to_elf.h - PE → ELF 离线转换工具核心头文件
 *
 * 本文件包含:
 *   1. PE (Windows Portable Executable) 完整结构体定义
 *      - 同时支持 PE32 (x86 32位) 与 PE32+ (x86_64 64位)
 *      - 所有结构体使用 uint8_t/uint16_t/uint32_t/uint64_t 定宽类型
 *      - 使用 __attribute__((packed)) 确保无编译器填充
 *
 *   2. ELF (Executable and Linkable Format) 完整结构体定义
 *      - 同时支持 Elf32 (32位) 与 Elf64 (64位)
 *      - 所有结构体使用定宽类型
 *
 *   3. PE → ELF 转换所需的所有常量、标志位、枚举
 *
 * 设计原则:
 *   - 手动定义所有结构体，不依赖 <elf.h> 系统头文件
 *   - 两套架构 (32/64位) 独立处理，字段宽度严格区分
 *   - 最大限度保留原始 PE 信息，减少转换损失
 */

#ifndef PE_TO_ELF_H
#define PE_TO_ELF_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ================================================================
 * 第一部分: PE 结构与常量
 * ================================================================ */

/* --- PE 基础常量 --- */
#define PE_DOS_MAGIC            0x5A4D      /* MZ */
#define PE_SIGNATURE            0x00004550U /* PE\0\0 */
#define PE_MACHINE_I386         0x014C      /* x86 32位 */
#define PE_MACHINE_AMD64        0x8664      /* x86_64 64位 */
#define PE_MAGIC_PE32           0x010B      /* PE32 可选头 Magic */
#define PE_MAGIC_PE32_PLUS      0x020B      /* PE32+ 可选头 Magic */
#define PE_SECTION_NAME_LEN     8
#define PE_NUM_DATA_DIRECTORIES 16

/* --- PE 段属性标志位 --- */
#define PE_SCN_MEM_EXECUTE      0x20000000U
#define PE_SCN_MEM_READ         0x40000000U
#define PE_SCN_MEM_WRITE        0x80000000U
/* 完整名称别名 (对齐 PE 规范 IMAGE_SCN_*) */
#define PE_IMAGE_SCN_MEM_EXECUTE  PE_SCN_MEM_EXECUTE
#define PE_IMAGE_SCN_MEM_READ     PE_SCN_MEM_READ
#define PE_IMAGE_SCN_MEM_WRITE    PE_SCN_MEM_WRITE

/* --- PE COFF 文件属性 --- */
#define PE_FILE_EXECUTABLE_IMAGE  0x0002
#define PE_FILE_DLL               0x2000

/* --- PE 数据目录索引 --- */
#define PE_DIR_EXPORT       0
#define PE_DIR_IMPORT       1
#define PE_DIR_RESOURCE     2
#define PE_DIR_EXCEPTION    3
#define PE_DIR_SECURITY     4
#define PE_DIR_BASERELOC    5
#define PE_DIR_DEBUG        6
#define PE_DIR_ARCH_DATA    7
#define PE_DIR_GLOBAL_PTR   8
#define PE_DIR_TLS          9
#define PE_DIR_LOAD_CONFIG  10
#define PE_DIR_BOUND_IMPORT 11
#define PE_DIR_IAT          12
#define PE_DIR_DELAY_IMPORT 13
#define PE_DIR_COM_DESCRIPTOR 14

/* --- PE 重定位类型 --- */
#define PE_REL_BASED_ABSOLUTE   0
#define PE_REL_BASED_HIGH       1
#define PE_REL_BASED_LOW        2
#define PE_REL_BASED_HIGHLOW    3   /* 32位: 完整 32 位地址 */
#define PE_REL_BASED_HIGHADJ    4
#define PE_REL_BASED_MIPS_JMPADDR 5
#define PE_REL_BASED_MIPS_JMPADDR16 9
#define PE_REL_BASED_DIR64     10   /* 64位: 完整 64 位地址 */
#define PE_REL_BASED_IA64_IMM64 9   /* IA64 */

/* ================================================================
 * PE 结构体定义 (32/64位通用 + PE32 专用 + PE32+ 专用)
 * ================================================================ */

/* DOS 头部 - 32/64位完全相同 */
typedef struct {
    uint16_t e_magic;
    uint16_t e_cblp;
    uint16_t e_cp;
    uint16_t e_crlc;
    uint16_t e_cparhdr;
    uint16_t e_minalloc;
    uint16_t e_maxalloc;
    uint16_t e_ss;
    uint16_t e_sp;
    uint16_t e_csum;
    uint16_t e_ip;
    uint16_t e_cs;
    uint16_t e_lfarlc;
    uint16_t e_ovno;
    uint16_t e_res[4];
    uint16_t e_oemid;
    uint16_t e_oeminfo;
    uint16_t e_res2[10];
    int32_t  e_lfanew;
} __attribute__((packed)) pe_dos_header_t;

/* 数据目录项 - 32/64位通用 */
typedef struct {
    uint32_t VirtualAddress;
    uint32_t Size;
} __attribute__((packed)) pe_data_directory_t;

/* COFF 文件头 - 32/64位完全相同 */
typedef struct {
    uint16_t Machine;
    uint16_t NumberOfSections;
    uint32_t TimeDateStamp;
    uint32_t PointerToSymbolTable;
    uint32_t NumberOfSymbols;
    uint16_t SizeOfOptionalHeader;
    uint16_t Characteristics;
} __attribute__((packed)) pe_coff_header_t;

/* 段/节表 - 32/64位完全相同 */
typedef struct {
    uint8_t  Name[PE_SECTION_NAME_LEN];
    union {
        uint32_t PhysicalAddress;
        uint32_t VirtualSize;
    } Misc;
    uint32_t VirtualAddress;
    uint32_t SizeOfRawData;
    uint32_t PointerToRawData;
    uint32_t PointerToRelocations;
    uint32_t PointerToLinenumbers;
    uint16_t NumberOfRelocations;
    uint16_t NumberOfLinenumbers;
    uint32_t Characteristics;
} __attribute__((packed)) pe_section_header_t;

/* PE32 可选头 (32位) - Magic = 0x10B */
typedef struct {
    uint16_t Magic;
    uint8_t  MajorLinkerVersion;
    uint8_t  MinorLinkerVersion;
    uint32_t SizeOfCode;
    uint32_t SizeOfInitializedData;
    uint32_t SizeOfUninitializedData;
    uint32_t AddressOfEntryPoint;
    uint32_t BaseOfCode;
    uint32_t BaseOfData;
    uint32_t ImageBase;
    uint32_t SectionAlignment;
    uint32_t FileAlignment;
    uint16_t MajorOperatingSystemVersion;
    uint16_t MinorOperatingSystemVersion;
    uint16_t MajorImageVersion;
    uint16_t MinorImageVersion;
    uint16_t MajorSubsystemVersion;
    uint16_t MinorSubsystemVersion;
    uint32_t Win32VersionValue;
    uint32_t SizeOfImage;
    uint32_t SizeOfHeaders;
    uint32_t CheckSum;
    uint16_t Subsystem;
    uint16_t DllCharacteristics;
    uint32_t SizeOfStackReserve;
    uint32_t SizeOfStackCommit;
    uint32_t SizeOfHeapReserve;
    uint32_t SizeOfHeapCommit;
    uint32_t LoaderFlags;
    uint32_t NumberOfRvaAndSizes;
    pe_data_directory_t DataDirectory[PE_NUM_DATA_DIRECTORIES];
} __attribute__((packed)) pe32_optional_header_t;

/* PE32+ 可选头 (64位) - Magic = 0x20B */
typedef struct {
    uint16_t Magic;
    uint8_t  MajorLinkerVersion;
    uint8_t  MinorLinkerVersion;
    uint32_t SizeOfCode;
    uint32_t SizeOfInitializedData;
    uint32_t SizeOfUninitializedData;
    uint32_t AddressOfEntryPoint;
    uint32_t BaseOfCode;
    uint64_t ImageBase;
    uint32_t SectionAlignment;
    uint32_t FileAlignment;
    uint16_t MajorOperatingSystemVersion;
    uint16_t MinorOperatingSystemVersion;
    uint16_t MajorImageVersion;
    uint16_t MinorImageVersion;
    uint16_t MajorSubsystemVersion;
    uint16_t MinorSubsystemVersion;
    uint32_t Win32VersionValue;
    uint32_t SizeOfImage;
    uint32_t SizeOfHeaders;
    uint32_t CheckSum;
    uint16_t Subsystem;
    uint16_t DllCharacteristics;
    uint64_t SizeOfStackReserve;
    uint64_t SizeOfStackCommit;
    uint64_t SizeOfHeapReserve;
    uint64_t SizeOfHeapCommit;
    uint32_t LoaderFlags;
    uint32_t NumberOfRvaAndSizes;
    pe_data_directory_t DataDirectory[PE_NUM_DATA_DIRECTORIES];
} __attribute__((packed)) pe64_optional_header_t;

/* PE32 NT 头 (32位) */
typedef struct {
    uint32_t               Signature;
    pe_coff_header_t       FileHeader;
    pe32_optional_header_t OptionalHeader;
} __attribute__((packed)) pe32_nt_headers_t;

/* PE32+ NT 头 (64位) */
typedef struct {
    uint32_t               Signature;
    pe_coff_header_t       FileHeader;
    pe64_optional_header_t OptionalHeader;
} __attribute__((packed)) pe64_nt_headers_t;

/* 重定位块头 */
typedef struct {
    uint32_t VirtualAddress;
    uint32_t SizeOfBlock;
} __attribute__((packed)) pe_base_relocation_t;

/* 导入表 IMAGE_IMPORT_DESCRIPTOR */
typedef struct {
    uint32_t OriginalFirstThunk;
    uint32_t TimeDateStamp;
    uint32_t ForwarderChain;
    uint32_t Name;
    uint32_t FirstThunk;
} __attribute__((packed)) pe_import_descriptor_t;

/* 导出目录 IMAGE_EXPORT_DIRECTORY */
typedef struct {
    uint32_t Characteristics;
    uint32_t TimeDateStamp;
    uint16_t MajorVersion;
    uint16_t MinorVersion;
    uint32_t Name;
    uint32_t Base;
    uint32_t NumberOfFunctions;
    uint32_t NumberOfNames;
    uint32_t AddressOfFunctions;
    uint32_t AddressOfNames;
    uint32_t AddressOfNameOrdinals;
} __attribute__((packed)) pe_export_directory_t;

/* 调试目录 IMAGE_DEBUG_DIRECTORY */
typedef struct {
    uint32_t Characteristics;
    uint32_t TimeDateStamp;
    uint16_t MajorVersion;
    uint16_t MinorVersion;
    uint32_t Type;
    uint32_t SizeOfData;
    uint32_t AddressOfRawData;
    uint32_t PointerToRawData;
} __attribute__((packed)) pe_debug_directory_t;

/* 调试类型 */
#define PE_DEBUG_TYPE_UNKNOWN        0
#define PE_DEBUG_TYPE_COFF           1
#define PE_DEBUG_TYPE_CODEVIEW       2
#define PE_DEBUG_TYPE_FPO            3
#define PE_DEBUG_TYPE_MISC           4
#define PE_DEBUG_TYPE_EXCEPTION      5
#define PE_DEBUG_TYPE_SECURITY       6
#define PE_DEBUG_TYPE_BORLAND        9
#define PE_DEBUG_TYPE_CLSID          12
#define PE_DEBUG_TYPE_VC_FEATURE     13
#define PE_DEBUG_TYPE_POGO           14
#define PE_DEBUG_TYPE_ILTCG          15
#define PE_DEBUG_TYPE_MPX            16
#define PE_DEBUG_TYPE_REPRO          17

/* ANSI 字符串 (7字节长度) 用于导入/导出名称 */
typedef struct { uint8_t Length; uint8_t Name[1]; } __attribute__((packed)) pe_import_by_name_t;

/* ================================================================
 * 第二部分: ELF 结构与常量
 * ================================================================ */

/* --- ELF 基础常量 --- */
#define ELFMAG0         0x7F
#define ELFMAG1         'E'
#define ELFMAG2         'L'
#define ELFMAG3         'F'
#define ELFMAG          "\177ELF"
#define ELFMAG_LEN      4

#define ELFCLASS32      1
#define ELFCLASS64      2

#define ELFDATA2LSB     1   /* Little endian */
#define ELFDATA2MSB     2   /* Big endian */

#define EV_CURRENT      1

#define ELFOSABI_NONE   0   /* No OS/ABI */

/* ELF 动态链接器路径 */
#define ELF_INTERPRETER_32 "/lib/ld-linux.so.2"
#define ELF_INTERPRETER_64 "/lib64/ld-linux-x86-64.so.2"
#ifndef ELF_INTERPRETER
#define ELF_INTERPRETER ELF_INTERPRETER_32
#endif

/* ELF 类型 */
#define ET_NONE         0
#define ET_REL          1   /* 可重定位文件 */
#define ET_EXEC         2   /* 可执行文件 */
#define ET_DYN          3   /* 共享库/PIE */
#define ET_CORE         4

/* ELF 机器类型 */
#define EM_386          3   /* x86 */
#define EM_X86_64       62  /* x86_64 */

/* 程序头类型 */
#define PT_NULL         0
#define PT_LOAD         1
#define PT_DYNAMIC      2
#define PT_INTERP       3
#define PT_NOTE         4
#define PT_PHDR         6
#define PT_TLS          7
#define PT_GNU_EH_FRAME 0x6474E550
#define PT_GNU_STACK    0x6474E551
#define PT_GNU_RELRO    0x6474E552

/* 段权限 */
#define PF_X            0x1
#define PF_W            0x2
#define PF_R            0x4

/* 节头类型 */
#define SHT_NULL        0
#define SHT_PROGBITS    1
#define SHT_SYMTAB      2
#define SHT_STRTAB      3
#define SHT_RELA        4
#define SHT_HASH        5
#define SHT_DYNAMIC     6
#define SHT_NOTE        7
#define SHT_NOBITS      8
#define SHT_REL         9
#define SHT_SHLIB       10
#define SHT_DYNSYM      11
#define SHT_INIT_ARRAY  14
#define SHT_FINI_ARRAY  15
#define SHT_GNU_HASH    0x6FFFFFF6
#define SHT_GNU_VERSYM  0x6FFFFFFF
#define SHT_GNU_VERNEED 0x6FFFFFFE
#define SHT_GNU_VERDEF  0x6FFFFFFD

/* 节头标志 */
#define SHF_WRITE       0x1
#define SHF_ALLOC       0x2
#define SHF_EXECINSTR   0x4
#define SHF_INFO_LINK   0x40
#define SHF_TLS         0x400

/* 符号绑定 */
#define STB_LOCAL       0
#define STB_GLOBAL      1
#define STB_WEAK        2

/* 符号类型 */
#define STT_NOTYPE      0
#define STT_OBJECT      1
#define STT_FUNC        2
#define STT_SECTION     3
#define STT_FILE        4
#define STT_COMMON      5
#define STT_TLS         6
#define STT_GNU_IFUNC   10

/* 符号可见性 */
#define STV_DEFAULT     0
#define STV_INTERNAL    1
#define STV_HIDDEN      2
#define STV_PROTECTED   3

/* ELF 重定位类型 - x86 (32位) */
#define R_386_NONE      0
#define R_386_32        1   /* 绝对 32 位 */
#define R_386_PC32      2   /* 相对 32 位 */
#define R_386_GOT32     3
#define R_386_PLT32     4
#define R_386_COPY      5
#define R_386_GLOB_DAT  6
#define R_386_JMP_SLOT  7
#define R_386_RELATIVE  8
#define R_386_GOTOFF    9
#define R_386_GOTPC     10
#define R_386_IRELATIVE 42

/* ELF 重定位类型 - x86_64 (64位) */
#define R_X86_64_NONE       0
#define R_X86_64_64         1   /* 绝对 64 位 */
#define R_X86_64_PC32       2   /* 相对 32 位 */
#define R_X86_64_GOT32      3
#define R_X86_64_PLT32      4
#define R_X86_64_COPY       5
#define R_X86_64_GLOB_DAT   6
#define R_X86_64_JMP_SLOT   7
#define R_X86_64_RELATIVE   8
#define R_X86_64_GOTPCREL   9
#define R_X86_64_32         10  /* 绝对 32 位零扩展 */
#define R_X86_64_32S        11  /* 绝对 32 位符号扩展 */
#define R_X86_64_16         12
#define R_X86_64_PC16       13
#define R_X86_64_8          14
#define R_X86_64_PC8        15
#define R_X86_64_GOTPCRELX  41
#define R_X86_64_GOTPCRELXZ 42
#define R_X86_64_IRELATIVE  37

/* 动态数组标签 */
#define DT_NULL         0
#define DT_NEEDED       1
#define DT_PLTRELSZ     2
#define DT_PLTGOT       3
#define DT_HASH         4
#define DT_STRTAB       5
#define DT_SYMTAB       6
#define DT_RELA         7
#define DT_RELASZ       8
#define DT_RELAENT      9
#define DT_STRSZ        10
#define DT_SYMENT       11
#define DT_INIT         12
#define DT_FINI         13
#define DT_SONAME       14
#define DT_RPATH        15
#define DT_SYMBOLIC     16
#define DT_REL          17
#define DT_RELSZ        18
#define DT_RELENT       19
#define DT_PLTREL       20
#define DT_DEBUG        21
#define DT_TEXTREL      22
#define DT_JMPREL       23
#define DT_INIT_ARRAY   25
#define DT_FINI_ARRAY   26
#define DT_INIT_ARRAYSZ 27
#define DT_FINI_ARRAYSZ 28
#define DT_RUNPATH      29
#define DT_FLAGS        30
#define DT_ENCODING     32
#define DT_PREINIT_ARRAY 32
#define DT_PREINIT_ARRAYSZ 33
#define DT_GNU_HASH     0x6FFFFEF5
#define DT_VERSYM       0x6FFFFEFF
#define DT_VERNEED      0x6FFFFEFE
#define DT_VERNEEDNUM   0x6FFFFEFD

/* ELF note 类型 */
#define NT_GNU_ABI_TAG  1
#define NT_GNU_HWCAP    2
#define NT_GNU_BUILD_ID 3
#define NT_GNU_GOLD_VERSION 4
#define NT_GNU_PROPERTY_TYPE_0 5

/* ELF note 描述符类型 */
#define ELF_PROPERTY_X86_FEATURE_1_AND 0xc0000002

/* ================================================================
 * ELF 结构体定义 (32位)
 * ================================================================ */

/* ELF32 头部 */
typedef struct {
    uint8_t  e_ident[16];
    uint16_t e_type;
    uint16_t e_machine;
    uint32_t e_version;
    uint32_t e_entry;
    uint32_t e_phoff;
    uint32_t e_shoff;
    uint32_t e_flags;
    uint16_t e_ehsize;
    uint16_t e_phentsize;
    uint16_t e_phnum;
    uint16_t e_shentsize;
    uint16_t e_shnum;
    uint16_t e_shstrndx;
} __attribute__((packed)) Elf32_Ehdr;

/* ELF32 程序头 */
typedef struct {
    uint32_t p_type;
    uint32_t p_offset;
    uint32_t p_vaddr;
    uint32_t p_paddr;
    uint32_t p_filesz;
    uint32_t p_memsz;
    uint32_t p_flags;
    uint32_t p_align;
} __attribute__((packed)) Elf32_Phdr;

/* ELF32 节头 */
typedef struct {
    uint32_t sh_name;
    uint32_t sh_type;
    uint32_t sh_flags;
    uint32_t sh_addr;
    uint32_t sh_offset;
    uint32_t sh_size;
    uint32_t sh_link;
    uint32_t sh_info;
    uint32_t sh_addralign;
    uint32_t sh_entsize;
} __attribute__((packed)) Elf32_Shdr;

/* ELF32 符号表项 */
typedef struct {
    uint32_t st_name;
    uint32_t st_value;
    uint32_t st_size;
    uint8_t  st_info;
    uint8_t  st_other;
    uint16_t st_shndx;
} __attribute__((packed)) Elf32_Sym;

/* ELF32 重定位项 (带显式 addend) */
typedef struct {
    uint32_t r_offset;
    uint32_t r_info;
    int32_t  r_addend;
} __attribute__((packed)) Elf32_Rela;

/* ELF32 重定位项 (无 addend) */
typedef struct {
    uint32_t r_offset;
    uint32_t r_info;
} __attribute__((packed)) Elf32_Rel;

/* ELF32 动态条目 */
typedef struct {
    int32_t d_tag;
    union {
        uint32_t d_val;
        uint32_t d_ptr;
    } d_un;
} __attribute__((packed)) Elf32_Dyn;

/* ELF32 Note 头 */
typedef struct {
    uint32_t namesz;
    uint32_t descsz;
    uint32_t type;
} __attribute__((packed)) Elf32_Nhdr;

/* ================================================================
 * ELF 结构体定义 (64位)
 * ================================================================ */

/* ELF64 头部 */
typedef struct {
    uint8_t  e_ident[16];
    uint16_t e_type;
    uint16_t e_machine;
    uint32_t e_version;
    uint64_t e_entry;
    uint64_t e_phoff;
    uint64_t e_shoff;
    uint32_t e_flags;
    uint16_t e_ehsize;
    uint16_t e_phentsize;
    uint16_t e_phnum;
    uint16_t e_shentsize;
    uint16_t e_shnum;
    uint16_t e_shstrndx;
} __attribute__((packed)) Elf64_Ehdr;

/* ELF64 程序头 */
typedef struct {
    uint32_t p_type;
    uint32_t p_flags;
    uint64_t p_offset;
    uint64_t p_vaddr;
    uint64_t p_paddr;
    uint64_t p_filesz;
    uint64_t p_memsz;
    uint64_t p_align;
} __attribute__((packed)) Elf64_Phdr;

/* ELF64 节头 */
typedef struct {
    uint32_t sh_name;
    uint32_t sh_type;
    uint64_t sh_flags;
    uint64_t sh_addr;
    uint64_t sh_offset;
    uint64_t sh_size;
    uint32_t sh_link;
    uint32_t sh_info;
    uint64_t sh_addralign;
    uint64_t sh_entsize;
} __attribute__((packed)) Elf64_Shdr;

/* ELF64 符号表项 */
typedef struct {
    uint32_t st_name;
    uint8_t  st_info;
    uint8_t  st_other;
    uint16_t st_shndx;
    uint64_t st_value;
    uint64_t st_size;
} __attribute__((packed)) Elf64_Sym;

/* ELF64 重定位项 (带显式 addend) */
typedef struct {
    uint64_t r_offset;
    uint64_t r_info;
    int64_t  r_addend;
} __attribute__((packed)) Elf64_Rela;

/* ELF64 重定位项 (无 addend) */
typedef struct {
    uint64_t r_offset;
    uint64_t r_info;
} __attribute__((packed)) Elf64_Rel;

/* ELF64 动态条目 */
typedef struct {
    int64_t d_tag;
    union {
        uint64_t d_val;
        uint64_t d_ptr;
    } d_un;
} __attribute__((packed)) Elf64_Dyn;

/* ELF64 Note 头 */
typedef struct {
    uint32_t namesz;
    uint32_t descsz;
    uint32_t type;
} __attribute__((packed)) Elf64_Nhdr;

/* ================================================================
 * 第三部分: 辅助宏 - 符号/重定位信息编码
 * ================================================================ */

/* 32位 ELF 符号信息编码 */
#define ELF32_ST_BIND(i)     ((i)>>4)
#define ELF32_ST_TYPE(i)     ((i)&0xf)
#define ELF32_ST_INFO(b,t)   (((b)<<4)+((t)&0xf))
#define ELF32_ST_VISIBILITY(o) ((o)&0x3)

/* 64位 ELF 符号信息编码 */
#define ELF64_ST_BIND(i)     ((i)>>4)
#define ELF64_ST_TYPE(i)     ((i)&0xf)
#define ELF64_ST_INFO(b,t)   (((b)<<4)+((t)&0xf))
#define ELF64_ST_VISIBILITY(o) ((o)&0x3)

/* 32位 ELF 重定位信息编码 */
#define ELF32_R_SYM(i)       ((i)>>8)
#define ELF32_R_TYPE(i)      ((uint8_t)(i))
#define ELF32_R_INFO(s,t)    (((s)<<8)+(uint8_t)(t))

/* 64位 ELF 重定位信息编码 */
#define ELF64_R_SYM(i)       ((i)>>32)
#define ELF64_R_TYPE(i)      ((uint32_t)(i))
#define ELF64_R_INFO(s,t)    (((uint64_t)(s)<<32)+(uint32_t)(t))

/* ================================================================
 * 第四部分: 转换数据结构 (运行时使用)
 * ================================================================ */

/* PE 架构识别结果 */
typedef enum {
    PE_ARCH_UNKNOWN = 0,
    PE_ARCH_X86    = 1,  /* PE32, Machine=i386 */
    PE_ARCH_X86_64 = 2   /* PE32+, Machine=AMD64 */
} pe_arch_t;

/* ELF 输出类型 */
typedef enum {
    ELF_OUT_EXECUTABLE = 0,  /* ET_EXEC */
    ELF_OUT_SHARED     = 1,  /* ET_DYN (.so) */
    ELF_OUT_SHARED_LIB = 1   /* alias */
} elf_out_type_t;

/* DLL 扫描结果数据结构 */
typedef struct {
    char   **paths;          /* 找到的 DLL 文件路径列表 */
    uint32_t count;          /* DLL 数量 */
    uint32_t cap;            /* 容量 */

    char   **missing;        /* 缺失的 DLL 名称列表 */
    uint32_t missing_count;
    uint32_t missing_cap;

    char   **converted;      /* 已转换的 DLL 输出路径 */
    uint32_t converted_count;
    uint32_t converted_cap;

    char   **converted_src;  /* 已转换的 DLL 源路径 (去重用, 避免重复转换/无限递归) */
    uint32_t converted_src_count;
    uint32_t converted_src_cap;
} dll_scan_data_t;

/* 转换上下文 - 包含解析后的所有 PE 数据 */
typedef struct {
    /* 原始文件数据 */
    uint8_t      *raw_buf;
    size_t         raw_size;
    const char    *src_path;

    /* PE 架构识别 */
    pe_arch_t      arch;

    /* 通用 PE 头部 (联合存储) */
    pe_dos_header_t  *dos;
    pe_coff_header_t *coff;
    union {
        pe32_nt_headers_t  *nt32;
        pe64_nt_headers_t  *nt64;
    } nt;

    /* 段表 */
    pe_section_header_t *sections;
    uint16_t             num_sections;

    /* 解析标志 */
    int has_imports;
    int has_exports;
    int has_relocations;
    int has_debug;

    /* 导入表数据 */
    pe_import_descriptor_t *import_descs;
    uint32_t               num_imports;

    /* 导出表数据 */
    pe_export_directory_t  *export_dir;

    /* 调试目录数据 */
    pe_debug_directory_t   *debug_dirs;
    uint32_t               num_debug_dirs;

    /* 重定位数据 (解析后存储) */
    uint32_t              *reloc_items;  /* 紧凑重定位条目数组: [type, offset] */
    uint32_t               num_reloc_items;
    uint32_t              *reloc_blocks; /* 重定位块头数组 */
    uint32_t               num_reloc_blocks;

    /* 统计信息 */
    uint32_t              unconvertible_relocs;
    uint32_t              total_relocs;
} pe_parse_result_t;

/* ELF 段构建描述符 */
typedef struct {
    char     name[PE_SECTION_NAME_LEN + 1];
    uint32_t pe_characteristics;
    uint64_t elf_vaddr;
    uint64_t elf_offset;
    uint64_t elf_size;
    uint32_t elf_flags;
    int      is_loadable;
} elf_section_desc_t;

/* 导入 DLL 信息 (供递归转换使用) */
typedef struct {
    char    *pe_name;       /* DLL 原始名 (如 "kernel32.dll") */
    char    *pe_path;       /* DLL 在磁盘上的绝对路径 */
    char    *elf_rel_path;  /* 转换后 .so 相对于输出目录的路径 */
    pe_arch_t arch;         /* DLL 架构 */
    int      converted;     /* 是否已转换 */
    int      found;         /* 是否在目录中找到 */
} dll_dep_t;

/* 资源文件 (非 PE) 拷贝项 */
typedef struct {
    char *src_path;
    char *dst_rel_path;
} resource_copy_t;

/* ================================================================
 * 第五部分: 公共 API 声明
 * ================================================================ */

/* 解析 PE 文件，填充 pe_parse_result_t */
int pe_parse_file(const char *path, pe_parse_result_t *result);

/* 释放解析结果中的动态内存 */
void pe_parse_result_free(pe_parse_result_t *result);

/* PE 文件 MZ 魔数检查 */
int is_pe_file_magic(const char *path);

/* DLL 文件扩展名检查 (大小写不敏感) */
int is_dll_file_ext(const char *filename);

/* PE 文件扩展名检查 (exe/dll) */
int is_pe_file_ext(const char *filename);

#ifdef __cplusplus
}
#endif

#endif /* PE_TO_ELF_H */
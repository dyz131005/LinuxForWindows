#!/usr/bin/env bash
# ============================================================
# PE -> ELF 离线二进制转换工具 构建脚本
# 编译器优先级: clang > gcc
# 运行环境: WSL Ubuntu / 原生 Linux
# ============================================================
set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$SCRIPT_DIR"

if [ -n "${CC:-}" ]; then
    if ! command -v "$CC" >/dev/null 2>&1; then
        echo "[ERROR] 指定的编译器不可用: CC=$CC"
        exit 1
    fi
else
    CC=""
    if command -v clang >/dev/null 2>&1; then
        CC=clang
    elif command -v gcc >/dev/null 2>&1; then
        CC=gcc
    else
        echo "[ERROR] 未找到编译器，请先安装 clang 或 gcc"
        echo "  Ubuntu/Debian: sudo apt-get install -y clang"
        exit 1
    fi
fi

echo "============================================"
echo " PE -> ELF Converter Build"
echo " 编译器: $CC"
echo " $($CC --version | head -1)"
echo "============================================"

SRC="$SCRIPT_DIR/src/pe_to_elf.c"
OUT="$SCRIPT_DIR/LinuxForWindows"

if [ ! -f "$SRC" ]; then
    echo "[ERROR] 找不到源码: $SRC"
    exit 1
fi

CFLAGS_COMMON="-std=c11 -O2 -Wall -Wextra -Wno-unused-parameter -Wno-unused-function -D_FILE_OFFSET_BITS=64"

ARCH="${1:-32}"

case "$ARCH" in
    32|x86|i386)
        CFLAGS_ARCH="-m32"
        ARCH_LABEL="x86 (32-bit)"
        ;;
    64|x86_64|amd64)
        CFLAGS_ARCH="-m64"
        ARCH_LABEL="x86_64 (64-bit)"
        ;;
    *)
        echo "用法: $0 [32|64]"
        echo "  32  - 编译 32 位静态版本 (默认)"
        echo "  64  - 编译 64 位静态版本"
        exit 1
        ;;
esac

build_static() {
    echo ""
    local out="$SCRIPT_DIR/LinuxForWindows_${ARCH}"
    echo "[1/1] 静态链接构建 -> $(basename "$out") (静态, $ARCH_LABEL)"
    local cmd="$CC $CFLAGS_COMMON $CFLAGS_ARCH -static -o $out $SRC"
    echo "  > $cmd"
    $cmd
    echo "  [OK] 构建完成"
    file "$out" | sed 's/^/        /'
    echo "  验证静态链接:"
    if ldd "$out" 2>&1 | grep -q "not a dynamic executable"; then
        echo "  [OK] 确认为静态链接，无动态库依赖"
    else
        echo "  [WARN] 仍有动态库依赖"
        ldd "$out" 2>&1 | sed 's/^/        /'
    fi
}

build_static

echo ""
echo "============================================"
echo " 构建完成！"
echo "--------------------------------------------"
for f in "$SCRIPT_DIR"/LinuxForWindows_*; do
    if [ -f "$f" ]; then
        sz=$(du -h "$f" | awk '{print $1}')
        arch=$(file "$f" | grep -oE "ELF (32|64)-bit" | head -1)
        printf "  %-24s  %-12s  %s\n" "$(basename "$f")" "$arch" "$sz"
    fi
done
echo "============================================"
echo ""
echo " 使用方法:"
echo "   ./LinuxForWindows_64 /path/to/target.exe"
echo "   ./LinuxForWindows_32 /path/to/target.exe"
echo ""
echo " 示例:"
echo "   ./LinuxForWindows_64 /mnt/c/Windows/System32/notepad.exe"
echo ""

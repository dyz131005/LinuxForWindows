# LinuxForWindows — PE → ELF 离线二进制转换器

将 Windows PE 可执行文件（EXE / DLL）**离线**转换为 Linux ELF 格式的静态工具。
**不做任何 Win32 API / ABI 仿真**——直接从二进制层面重写文件头、节表、程序头、动态段（`.dynamic`）等结构。

> ⚠️ **预期行为说明**：转换结果能保证**动态链接/加载期不崩溃**，但运行时可能段错误。
> 由于离线转换不应用 Windows loader 的基址重定位与 IAT 修复，程序执行到依赖这些修复的指令时会产生运行时崩溃（段错误）。这是本项目的设计边界，不是加载失败。

## 特性

- **32 位 / 64 位全支持**：PE32 (x86) 与 PE32+ (x86_64) 均可转换
- **纯离线**：读取 PE → 直接写出 ELF，无运行时翻译层、无依赖注入
- **完整导入表**：主程序 `DT_NEEDED` 包含全部转换出的 `.so`，且使用**相对路径**引用
- **保留目录结构**：源目录子文件夹里的 DLL（如 Qt 插件 `platforms/qwindows.dll`）会转换到输出目录的对应子文件夹，**任意深度不丢失**
- **`RUNPATH=$ORIGIN`**：动态链接器从可执行文件所在目录解析依赖
- **资源文件复制**：非 PE 的资源文件自动复制到输出目录
- **缺失依赖报告**：未找到的（通常是系统）DLL 会从导入表移除，并在结尾汇总列出

## 目录结构

```
LinuxForWindows/
├── src/
│   ├── pe_to_elf.h          # PE / ELF 结构定义与数据结构
│   └── pe_to_elf.c          # 主实现
├── build.sh                 # 构建脚本 (32 / 64)
├── LinuxForWindows_32       # 编译产物 (i386 静态链接)
├── LinuxForWindows_64       # 编译产物 (x86_64 静态链接)
└── test/
    └── Kill.exe             # 测试用例 (Qt6 GUI 应用 + 21 个 DLL)
```

## 构建

依赖：`clang` 或 `gcc`；编译 32 位需安装 multilib（如 Ubuntu: `sudo apt install gcc-multilib`）。

```bash
./build.sh 64     # 编译 x86_64 版本 -> LinuxForWindows_64
./build.sh 32     # 编译 i386 版本   -> LinuxForWindows_32
```

产物均为**静态链接**的独立可执行文件，无动态库依赖。

## 使用

```bash
./LinuxForWindows_64 /path/to/YourApp.exe
./LinuxForWindows_32 /path/to/YourApp.exe
```

转换器会在源目录下创建 `<EXE名>` 文件夹作为输出目录（例如 `test/Kill.exe` → `test/Kill/`），将全部扫描到的 DLL 转换为 `.so` 并保留相对目录结构，同时复制非 PE 资源文件。

### 输出示例

以 `test/Kill.exe` 为例（Qt6 应用 + 21 个 DLL）：

```
test/Kill/
├── Kill                         # 转换后的主程序 ELF
├── Qt6Core.so                   # 根目录 DLL -> 根目录 .so
├── Qt6Gui.so
├── Qt6Network.so
├── Qt6Svg.so
├── Qt6Widgets.so
├── D3Dcompiler_47.so
├── opengl32sw.so
├── libgcc_s_seh-1.so
├── libstdc++-6.so
├── libwinpthread-1.so
├── updatelog.txt                # 复制的资源文件
├── generic/
│   └── qtuiotouchplugin.so      # 子目录 DLL -> 对应子目录 .so
├── iconengines/
│   └── qsvgicon.so
├── imageformats/
│   ├── qgif.so
│   ├── qico.so
│   ├── qjpeg.so
│   └── qsvg.so
├── networkinformation/
│   └── qnetworklistmanager.so
├── platforms/
│   └── qwindows.so
├── styles/
│   └── qmodernwindowsstyle.so
└── tls/
    ├── qcertonlybackend.so
    └── qschannelbackend.so
```

主程序导入表（`DT_NEEDED`）会列出全部 21 个 `.so`，子目录用相对路径（如 `platforms/qwindows.so`），配合 `RUNPATH=$ORIGIN` 由动态链接器解析。

## 验证方法

```bash
# 1) 查看导入表与运行路径
readelf -d test/Kill/Kill | grep -E 'NEEDED|RUNPATH'

# 2) 确认所有依赖可解析 (无 "not found")
cd test/Kill && ldd ./Kill

# 3) 观察加载过程 (所有 .so 都应 "calling init")
LD_DEBUG=libs ./Kill

# 4) 定位崩溃位置 (应位于 exe 自身 .text)
gdb -q -batch -ex run -ex bt ./Kill
```

## 已知限制

1. **运行时可能段错误**：离线转换不应用 Windows loader 的基址重定位与 IAT 修复，转换出的二进制中的数据指针可能保留着"待修复"的原始值，程序执行到这些指令时可能崩溃。
2. **系统 DLL 不打包**：`KERNEL32.dll`、`USER32.dll` 等系统库不随转换分发，其导入项会被移除并在结尾汇总报告。
3. **gdb `info sharedlibrary` 显示不全**：手工构造的 `.dynamic` 缺少 `DT_DEBUG`，gdb 的 r_debug 探测受限，可能只显示 `ld-linux`；请用 `LD_DEBUG=libs` 观察实际加载情况。

## 测试

```bash
./LinuxForWindows_64 test/Kill.exe
```

已实测：21 个 DLL 全部转换、子目录结构完整保留、`ldd` 全部解析、`LD_DEBUG=libs` 显示全部 `calling init`（加载期不崩溃）、gdb 崩溃点位于 exe 自身 `.text`。

## 许可证

[MIT](LICENSE)

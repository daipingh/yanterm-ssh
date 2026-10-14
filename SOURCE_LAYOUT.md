# 源码结构规范：header-only + 静态库双模式

## 0. 适用范围与用词

本文规定 `yanterm-ssh` 的目录布局、文件类型划分与编译模式切换机制。库同时支持两种消费方式，二者共用同一份 `include/` 树：

- **header-only**：使用者只把 `include/` 加入头文件搜索路径，不链接任何库产物。
- **静态库**：使用者链接 `yanterm::ssh-static`。

规范性用词：**必须** / **禁止** 为强制要求；**应当** / **不应** 为强烈建议，偏离时需在代码中就近注释说明理由；**可以** 表示允许。

每条规则带编号（如 `[M-1]`），供代码评审、脚本检查和其他文档引用。文中示例统一以 `keys/public_key` 组件为样板。

---

## 1. 编译模式

### 1.1 三种翻译单元状态

`[M-1]` 任何一个翻译单元（TU）必定处于下表三种状态之一，`.hpp` 对 `.ipp` 的处理方式随之不同：

| TU 类型 | `YANTERM_SSH_SEPARATE_COMPILATION` | `YANTERM_SSH_SOURCE` | `YANTERM_SSH_HEADER_ONLY` | `.ipp` 由谁引入 |
| --- | --- | --- | --- | --- |
| header-only 使用者 | 未定义 | 未定义 | 自动推导为已定义 | 宿主 `.hpp` 尾部条件包含 |
| 静态库自身的 TU | 已定义 | 已定义 | 未定义 | `src/` 下的 `.cpp` 直接包含 |
| 链接静态库的使用者 | 已定义 | 未定义 | 未定义 | 不引入，只见到声明 |

这条区分是整套规范的地基。第三种状态若错误地引入了 `.ipp`，链接期会出现重复定义；第二种状态若漏掉 `.ipp`，则符号缺失。

`[M-2]` 默认模式是 header-only。使用者不定义任何宏、不链接任何产物即可使用整个库。

`[M-3]` `YANTERM_SSH_HEADER_ONLY` 是派生宏，只能由 `detail/config.hpp` 推导得到，**禁止**任何人手工定义。切换模式的唯一开关是 `YANTERM_SSH_SEPARATE_COMPILATION`。

`[M-4]` `YANTERM_SSH_SOURCE` **只允许**出现在 `src/**/*.cpp` 的第一行，用于标记"这是库自身的编译单元"。

`[M-5]` 同一个可执行文件或共享库内的所有 TU **必须**使用同一模式。混用即 ODR 违规。该约束由 CMake 的 `PUBLIC` 编译定义传播来保证（见 `[S-4]`），使用者不需要也不应该手写模式宏。

`[M-6]` 任何影响类型布局或函数行为的配置宏（缓冲区大小、异常开关等）**必须**在构建库和使用库时取值一致，并集中声明在 `detail/config.hpp` 中。分散在各处的行为开关会让 `[M-5]` 无法审计。

### 1.2 `include/yanterm-ssh/detail/config.hpp`

`[M-7]` 模式判定**必须**集中在这一个文件里，其它任何文件禁止自行推导模式：

```cpp
#pragma once

#if defined(YANTERM_SSH_HEADER_ONLY)
#error "YANTERM_SSH_HEADER_ONLY is derived, not user-settable. \
Use YANTERM_SSH_SEPARATE_COMPILATION to opt into the static library."
#endif

#if defined(YANTERM_SSH_SOURCE) && !defined(YANTERM_SSH_SEPARATE_COMPILATION)
#error "yanterm-ssh library sources must be compiled with \
YANTERM_SSH_SEPARATE_COMPILATION defined (see the yanterm-ssh-static target)."
#endif

#if !defined(YANTERM_SSH_SEPARATE_COMPILATION)
#define YANTERM_SSH_HEADER_ONLY 1
#endif

#if defined(YANTERM_SSH_HEADER_ONLY)
#define YANTERM_SSH_INLINE inline
#else
#define YANTERM_SSH_INLINE
#endif
```

两处 `#error` 都是刻意的：配置错误必须在编译期炸掉，而不是留到链接期变成一堆重复定义或未定义符号。

`[M-8]` `YANTERM_SSH_INLINE` **只**出现在 `.ipp` 里的定义上，**不**出现在 `.hpp` 里的声明上。

这样做是合法且更省事的：C++ 只禁止"定义早于首个 `inline` 声明"，先在 `.hpp` 里写不带 `inline` 的声明、再在 `.ipp` 里写带 `inline` 的定义是允许的。而 header-only 模式下每个见到声明的 TU 也必然见到 `.ipp` 中的定义，`inline` 的可见性要求自然满足。

`[M-9]` 本规范只覆盖静态库。若将来需要共享库，`YANTERM_SSH_INLINE` 的三态展开（`inline` / 空 / `dllexport`+`dllimport`）**必须**仍然只在 `detail/config.hpp` 内部完成，其余规则不变。

---

## 2. 目录布局

### 2.1 顶层

`[D-1]` 顶层只有三个源码目录：

```
include/yanterm-ssh/   全部头文件：公开头、私有头、实现文件
src/                   静态库的编译单元
tests/                 测试
```

`[D-2]` `include/` 是使用者唯一的头文件搜索根。库自身也只用这一个搜索根，不额外给自己开私有搜索路径——这样库内代码和使用者代码写出来的 include 路径完全一致。

`[D-3]` `src/` **禁止**存放任何头文件。所有头文件（含私有头）都在 `include/` 下，因为 header-only 模式要求它们随包发布。

这一点与 Pitchfork Layout 的 separate placement 有意不同：Pitchfork 把私有头放进 `src/` 以确保使用者拿不到，而 header-only 库做不到这件事。本规范中"私有"的含义是**不承诺稳定、不属于支持的 API**，而不是**不可见**。

### 2.2 `include/` 内部的四类文件

`[D-4]` `include/yanterm-ssh/` 下只存在四类文件：

| 位置 | 类型 | 稳定性 | 由谁包含 |
| --- | --- | --- | --- |
| `<域>/foo.hpp` | 公开头 | 公开 API | 使用者、其它头文件 |
| `<域>/detail/bar.hpp` | 私有头 | 无承诺 | 仅库内部 |
| `<域>/impl/foo.hpp` | 模板 / inline 实现（**可选**，见 `[H-9]`） | 无承诺 | 仅 `foo.hpp` 尾部，**无条件** |
| `<域>/impl/foo.ipp` | 编译实现 | 无承诺 | `foo.hpp` 尾部（**条件**）或 `src/` 的 `.cpp` |

`impl/foo.hpp` 是可选的：实现量小时直接写在 `foo.hpp` 里，不必为了形式统一而拆文件。

`[D-5]` 公开头与私有头**禁止**同目录。私有头一律位于 `detail/` 子目录下。目录本身就是可见性边界，不依赖命名约定或注释。

`[D-6]` 实现文件（`impl/*.hpp`、`impl/*.ipp`）一律位于**宿主头文件所在目录**的 `impl/` 子目录中。私有头的实现文件相应地位于 `detail/impl/`：

```
include/yanterm-ssh/keys/public_key.hpp
include/yanterm-ssh/keys/impl/public_key.ipp

include/yanterm-ssh/keys/detail/base64.hpp
include/yanterm-ssh/keys/detail/impl/base64.ipp
```

`[D-7]` `impl/` 只放"某个宿主头文件的另一半"，文件主干名**必须**以宿主头文件的主干名开头。`detail/` 则放独立的私有组件（有自己的类型和接口）。两者语义不同，不要混用。

`[D-8]` `impl/` 与 `detail/` 下的内容都不属于支持的 API，但**必须**随包发布（见 `[P-1]`），因为 header-only 模式依赖它们。

### 2.3 一个头文件对应多个 `.ipp`

`[D-9]` 允许一个 `.hpp` 拆出多个 `.ipp`，按功能切面切分以控制单文件规模。命名为 `impl/<宿主主干>_<切面>.ipp`：

```
include/yanterm-ssh/core/connection.hpp
include/yanterm-ssh/core/impl/connection_lifecycle.ipp
include/yanterm-ssh/core/impl/connection_transport.ipp
include/yanterm-ssh/core/impl/connection_kex.ipp
```

`[D-10]` 每个 `.ipp` **有且仅有**一个宿主 `.hpp` 包含它，且**恰好被一个** `src/` 下的 `.cpp` 包含。

这是链接正确性的核心不变式：0 个 `.cpp` 包含它会让静态库缺符号，2 个会重复定义。两者都在链接期暴露，但 `[V-5]` 的脚本能在编译前就抓住。注意这条**不**要求 `.ipp` 与 `.cpp` 一一对应，一个 `.cpp` 可以包含多个 `.ipp`（见 `[S-1]`）。

`[D-11]` `.ipp` **禁止**包含其它 `.ipp`。`hpp → ipp` 保持单层关系，否则 `[D-10]` 立刻失效。

---

## 3. 头文件规则

`[H-1]` 每个 `.hpp` **必须**以 `#pragma once` 开头。

`[H-2]` **自包含**：公开头和 `detail/` 下的私有头**必须**能被单独包含并编译通过，不要求包含者前置包含任何东西。

`impl/` 下的文件不在此列，它们是"半个文件"，天然依赖宿主：

- `impl/*.hpp` 只被宿主 `.hpp` 无条件包含，永远处在宿主的上下文里，**不要求**自包含，也**不应**反过来包含宿主 `.hpp`——那是一个多余的循环。
- `.ipp` 另当别论：它还会被 `src/` 的 `.cpp` 直接包含，因此 `[I-3]` 要求它首行包含宿主 `.hpp`。那一行是功能性的，不是为了自包含。

`[H-3]` 第一个 include **必须**是 `<yanterm-ssh/detail/config.hpp>`，保证 `YANTERM_SSH_INLINE` 和模式宏在任何路径下都已就绪。

`[H-4]` 公开头**只**包含自身**声明**所需的头文件。**实现**所需的头文件由 `impl/*.hpp` 和 `impl/*.ipp` 自行包含。

`[H-5]` Include-what-you-use：**禁止**依赖传递包含。用到的每个名字都要有对应的直接 include。

`[H-6]` 全部使用尖括号加从 `include/` 根算起的完整路径（`#include <yanterm-ssh/keys/public_key.hpp>`），**禁止**相对路径引号形式。同一份路径写法在库内代码和使用者代码中通用，搬动文件时不需要跟着调整 `../` 深度，也让 grep、IWYU、clangd 的 include 修复保持一致。

`[H-7]` 以下实体的定义**必须**留在 `.hpp`（含 `impl/*.hpp`），这是技术约束而非风格选择——静态库模式下使用者看不到 `.ipp`，放进去就无法实例化或常量求值：

- 模板（函数模板、类模板及其成员）
- `constexpr` / `consteval` 函数
- `inline constexpr` 常量

其余非模板函数体放 `.hpp` 还是 `.ipp`，由作者按**编译边界**判断：

- 放 `.ipp`：该函数成为库产物中的符号，编译期不对使用者可见，将来支持动态库时它属于 ABI 面。短函数如果属于稳定接口，同样应该放 `.ipp`。
- 放 `.hpp`：该函数被编进使用者的 TU，不构成 ABI 面，可以随版本自由改动。长函数如果明确不打算进库产物，就该留在 `.hpp`。

`[H-8]` 尾部包含块位于所有命名空间关闭之后、文件末尾，形式和顺序固定：先**无条件**包含 `impl/*.hpp`（0 或 1 个），再**条件**包含 `impl/*.ipp`（0 或多个）。两者都可以没有。

```cpp
#pragma once

#include <yanterm-ssh/detail/config.hpp>

#include <span>          // 仅声明所需
#include <string>
#include <system_error>

namespace yanterm::ssh::keys {

class public_key {
public:
    static std::error_code parse_blob(std::span<const std::byte> blob, public_key& out);
    [[nodiscard]] std::string_view algorithm_name() const noexcept;
    [[nodiscard]] std::span<const std::byte> blob() const noexcept;

    template <class Sink>
    void write_to(Sink& sink) const;

private:
    std::vector<std::byte> blob_;
};

[[nodiscard]] inline std::span<const std::byte> public_key::blob() const noexcept {
    return blob_;
}

}  // namespace yanterm::ssh::keys

#include <yanterm-ssh/keys/impl/public_key.hpp>   // 可选，见 [H-9]

#if defined(YANTERM_SSH_HEADER_ONLY)
#include <yanterm-ssh/keys/impl/public_key.ipp>
#endif
```

`[H-9]` 模板与 inline 实现**默认直接写在** `foo.hpp` 里。只有当它们的体量已经影响到 `foo.hpp` 的可读性时，才**应当**拆到 `impl/<主干>.hpp`。注意 `impl/<主干>.hpp` 是**无条件**包含的——模板定义在两种模式下都必须对使用者可见，不能放进 `.ipp`。

`[H-10]` `detail/` 头文件**禁止**包含伞形头文件（如 `<yanterm-ssh/session.hpp>`），避免包含环。依赖方向始终从外层指向内层。

---

## 4. `.ipp` 规则

`[I-1]` `.ipp` 存放且仅存放**会被编进静态库的定义**：非模板函数、类的非模板成员函数、以及 `[I-2]` 例外中允许的显式实例化。

`[I-2]` `.ipp` **禁止**放模板定义、`constexpr` / `consteval` 函数和类定义。静态库模式下使用者看不到 `.ipp`，这些实体无法被实例化或常量求值。

唯一例外是**显式实例化定义**（`template class foo<bar>;`）：它本就是要落进库产物的符号，**可以**放进 `.ipp`，此时宿主 `.hpp` 中相应地写 `extern template`。

`[I-3]` `.ipp` 的文件头形式固定：`#pragma once` → 包含宿主 `.hpp` → 误用保护 → 实现所需的 include。

```cpp
#pragma once

#include <yanterm-ssh/keys/public_key.hpp>

#if !defined(YANTERM_SSH_HEADER_ONLY) && !defined(YANTERM_SSH_SOURCE)
#error "yanterm-ssh/keys/impl/public_key.ipp is an implementation file, not a public header."
#endif

#include <yanterm-ssh/error.hpp>   // 仅实现所需
#include <utility>

namespace yanterm::ssh::keys {

YANTERM_SSH_INLINE std::error_code public_key::parse_blob(std::span<const std::byte> blob,
                                                          public_key& out) {
    // ...
}

}  // namespace yanterm::ssh::keys
```

先包含宿主 `.hpp` 有三个作用：`src/` 的 `.cpp` 只需一行 include 就能编译；编辑器和 clangd 单独打开 `.ipp` 时能正确解析；误用保护所依赖的模式宏此时已经就绪。header-only 模式下这次包含是被 `#pragma once` 挡掉的空操作，不构成循环。

`[I-4]` `.ipp` 中每个命名空间作用域的函数定义和成员函数定义**必须**带 `YANTERM_SSH_INLINE`。

`[I-5]` `.ipp` **禁止**匿名命名空间，也**禁止**命名空间作用域的 `static` 函数与变量。header-only 模式下它们会在每个 TU 里各存一份拷贝；一旦被 `inline` 函数引用即构成 ODR 违规。文件内部的辅助函数**必须**放进 `detail` 命名空间并加 `YANTERM_SSH_INLINE`。

`[I-6]` `.ipp` **禁止**定义命名空间作用域的可变变量和非 `constexpr` 静态数据成员——两种模式下它们的链接语义不同。需要惰性单例时，用一个 `YANTERM_SSH_INLINE` 函数包住函数内的局部 `static`。

`[I-7]` `.ipp` 自行开闭命名空间，不依赖宿主 `.hpp` 留下的命名空间上下文。

`[I-8]` 平台差异在 `.ipp` **内部**用 `#if` 处理，或让整个文件体被平台宏包裹（不匹配平台时文件为空）。`.ipp` 在宿主 `.hpp` 和 `src/` 的 `.cpp` 两侧都**必须**是无条件出现的（前者的条件只能是 `YANTERM_SSH_HEADER_ONLY`）；**禁止**在包含处做平台判断，否则同一份平台条件要维护两遍，且极易在两侧写歪。

`[I-9]` `.ipp` 内定义的辅助宏**必须**在文件末尾 `#undef`。

`[I-10]` **实现依赖泄漏是本方案的固有代价**，规范无法消除，只能要求你正视：header-only 模式下 `.ipp` 被宿主 `.hpp` 拉进使用者的 TU，`.ipp` 所包含的重量级头文件（`<windows.h>`、OpenSSL 头等）同样进入使用者 TU。

若某项依赖绝对不能泄漏给使用者，该组件就**不能**支持 header-only——必须改用 pimpl 把依赖挡在实现侧，或者明确放弃该组件的双模式支持。不要指望 `[H-4]` 能隔离实现依赖，它隔离的只是**静态库模式下**的依赖。

---

## 5. `src/` 与构建

`[S-1]` `.cpp` 与 `.ipp` **不要求**一一对应。唯一的硬约束是 `[D-10]`：每个 `.ipp` 恰好被一个 `.cpp` 包含。

分组方式**应当**跟随 `include/` 的目录结构，例如 `src/keys.cpp` 收 `keys/**/impl/*.ipp`。这样新增或删除 `.ipp` 只是在既有 `.cpp` 里增删一行 include，构建脚本不动。

有个你可能需要知道的细节：`.cpp` 越多，静态库的链接粒度越细（链接器可按需拉 `.o`，最终二进制更小）、增量编译越快；`.cpp` 越少，重复解析头文件的总量越小，全量构建可能更快。如果使用者几乎会用到库的全部功能，细粒度带来的体积收益就有限。

`[S-2]` 每个 `.cpp` 的内容只有一行 `#define` 加若干行 include，**禁止**在 `.cpp` 里写任何定义。需要新增定义时写进对应的 `.ipp`：

```cpp
#define YANTERM_SSH_SOURCE

#include <yanterm-ssh/keys/impl/authorized_keys.ipp>
#include <yanterm-ssh/keys/impl/fingerprint.ipp>
#include <yanterm-ssh/keys/impl/public_key.ipp>
#include <yanterm-ssh/keys/detail/impl/base64.ipp>
```

`[S-3]` `src/` 下的 `.cpp` **必须**逐个显式列进 CMake，**禁止** `file(GLOB)`。

`[S-4]` 静态库目标**必须**把模式宏声明为 `PUBLIC`，由 CMake 向使用者传播：

```cmake
# header-only：只提供 include 搜索路径
add_library(yanterm-ssh-core INTERFACE)
add_library(yanterm::ssh-core ALIAS yanterm-ssh-core)
target_include_directories(yanterm-ssh-core INTERFACE
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
    $<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}>)
target_compile_features(yanterm-ssh-core INTERFACE cxx_std_20)

# 静态库：复用同一份 include，并向使用者传播模式宏
add_library(yanterm-ssh-static STATIC
    src/keys.cpp
    # ... 逐个列出
)
add_library(yanterm::ssh-static ALIAS yanterm-ssh-static)
target_link_libraries(yanterm-ssh-static PUBLIC yanterm-ssh-core)
target_compile_definitions(yanterm-ssh-static PUBLIC YANTERM_SSH_SEPARATE_COMPILATION)
set_target_properties(yanterm-ssh-static PROPERTIES UNITY_BUILD OFF)
```

`PUBLIC` 同时作用于库自身的 TU 和使用者的 TU，这正是 `[M-5]` 所要求的一致性，也让 `[M-7]` 的第二个 `#error` 永远不会在正常构建中触发。

`[S-5]` 静态库目标**应当**设置 `UNITY_BUILD OFF`。合并 TU 虽然不会破坏正确性（`#pragma once` 挡住了重复包含），但会抵消 `[S-1]` 所选粒度带来的链接与增量编译收益。

`[S-6]` 两种模式**必须**通过选择 CMake 目标来切换，使用者链 `yanterm::ssh-core` 得到 header-only，链 `yanterm::ssh-static` 得到静态库。

---

## 6. 命名与命名空间

`[N-1]` 全部宏以 `YANTERM_SSH_` 前缀。

`[N-2]` `detail` 目录对应 `detail` 命名空间：`include/yanterm-ssh/keys/detail/base64.hpp` 中的实体位于 `yanterm::ssh::keys::detail`。

`[N-3]` `impl/` 目录**不**引入命名空间层级，其中的实体属于宿主头文件所在的命名空间。

`[N-4]` 除 `impl/` 外，头文件的目录层级与命名空间层级一一对应。

---

## 7. 安装与发布

`[P-1]` `include/yanterm-ssh/` **整棵树必须安装**，包括 `detail/` 和 `impl/`（含全部 `.ipp`）。缺任何一个文件都会让 header-only 模式失效。

`[P-2]` 安装包**必须**同时导出 header-only 的 INTERFACE 目标和静态库目标。

`[P-3]` `.ipp` **必须**在工具链中被识别为 C++ 头文件：`.gitattributes` 中加 `*.ipp linguist-language=C++`，`.clang-format` 与 `.clangd` 的文件关联同理。

---

## 8. 验证

`[V-1]` CI **必须**在两种模式下都完整构建并跑完测试。只测一种模式等于只测一半代码路径。

`[V-2]` **ODR 冒烟测试**：至少两个 TU 各自包含全部公开头文件，再链接成一个可执行文件。header-only 和静态库两种模式各需一份。这是唯一能可靠抓到"该加 `YANTERM_SSH_INLINE` 却漏了"的手段。

`[V-3]` **自包含检查**：为 `include/yanterm-ssh/` 下每个公开头和 `detail/` 私有头自动生成一个只包含它的 TU 做 `-fsyntax-only`，覆盖 `[H-2]`。`impl/` 下的文件按 `[H-2]` 不要求自包含，从检查范围中排除。生成过程必须自动发现头文件，新增头文件不需要手工登记。

`[V-4]` 把任何定义在 `.hpp` 与 `.ipp` 之间搬动之后，**必须**重跑 `[V-1]` 的两种模式，不能只跑当前正在用的那种。

`[V-5]` **结构一致性检查**（脚本化，纳入 CI）：

- 每个 `.ipp` 恰好被一个 `.hpp` 和恰好一个 `src/` 下的 `.cpp` 包含（`[D-10]`）
- 每个包含 `.ipp` 的 `.cpp` 都已列入 CMake（`[S-3]`）
- 每个 `.ipp` 的首个 include 是自己的宿主 `.hpp`，且带有 `[I-3]` 的误用保护
- `.ipp` 中不出现 `template <`、匿名命名空间、命名空间作用域 `static`（`[I-2]` `[I-5]`）
- `.hpp` 中不出现 `#include` 任何 `.ipp`，除非位于 `#if defined(YANTERM_SSH_HEADER_ONLY)` 块内（`[H-8]`）
- `src/` 下不存在头文件（`[D-3]`）

---

## 9. 参考

- Boost.Asio [`detail/config.hpp`](https://github.com/boostorg/asio/blob/master/include/boost/asio/detail/config.hpp)：`BOOST_ASIO_HEADER_ONLY` / `BOOST_ASIO_DECL` 的三态推导，本规范 `[M-1]` `[M-7]` 的原型。
- [Using, Building, and Configuring Boost.Asio](https://www.boost.org/doc/libs/latest/doc/html/boost_asio/using.html)：默认 header-only、可选分离编译的用户侧契约。
- [Boost.JSON](https://www.boost.org/doc/libs/develop/libs/json/doc/html/index.html)：默认分离编译、`src.hpp` 可选 header-only，与 Asio 相反的默认值选择。

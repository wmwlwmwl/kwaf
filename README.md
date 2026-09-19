# kwaf

`kwaf` 是 Kangle Web Server 的防 CC 扩展。

## 编译要求

- Linux 或 Windows
- CMake 3.12 或更高版本（部分发行版中的命令名为 `cmake3`）
- 支持 C++14 的编译器
- 已安装的 Kangle，以及与该安装版本一致的 Kangle 源代码

构建参数：

- `KANGLE_DIR`：Kangle **安装目录**，例如 `/vhs/kangle`。
- `KANGLE_SOURCE_DIR`：Kangle **源代码目录**。若源码位于 `kwaf` 同级的 `kangle` 目录，可省略该参数。

## 编译和安装

```sh
git clone https://github.com/netcccyun/kwaf.git
cd kwaf

cmake -S . -B build \
  -DKANGLE_DIR=/vhs/kangle \
  -DKANGLE_SOURCE_DIR=/path/to/kangle-source \
  -DCMAKE_BUILD_TYPE=Release
cmake --build build -j
cmake --build build --target install
```

安装完成后应生成：

- `/vhs/kangle/bin/kwaf.so`
- `/vhs/kangle/ext/kwaf.dso.xml`

最后重启或重载 Kangle，使扩展配置生效。升级 Kangle 后应使用对应版本的源码重新编译本扩展，避免内部接口不一致。

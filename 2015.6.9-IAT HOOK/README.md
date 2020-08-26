+ 这个程序在VS里面运行会有编码的问题，我改成 `wprintf` 也不行，不知道为什么。请在 `vc6` 环境下实验。

+ `GetModuleInformation` 在 `psapi.h` 里面，需要使用请先将附带的压缩包解压到项目目录下然后加上

  ```cpp
  #include "psapi.h"
  #pragma commnet(lib, "psapi.lib")
  ```
+ 这个程序有一个需要解决的问题。我使用 `VirtualAllocEX` 在0x400000申请内存申请不了。但是在0x600000网上的内存空间都可以申请。我这个程序设定为在0x2000000上跑，0x400000上并没有东西。

  [这是我遇到问题的时候发的推特](https://twitter.com/smallzhong/status/1297203019994431489)

  [这是我查到的stackoverflow回答（但是并没有解决问题）](https://stackoverflow.com/questions/21368429/error-code-487-error-invalid-address-when-using-virtualallocex)

  
+ 在自己测试的时候请将 `FILEPATH_IN` 改成自己的函数地址
+ `GetRVAFunctionAddrByName` 和 `GetRVAFunctionAddrByOrdinals` 两个函数都已经封装好了，可以直接用。

# p.s.

+ 捉虫一小时血泪史！！序号表里每个元素的大小是2字节，也就是一个 `WORD` ，千万不要用 `PDWORD` 来指向它！！！！！！

  ![](https://raw.githubusercontent.com/smallzhong/picgo-pic-bed/master/20200709174725.png)
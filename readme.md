# 滴水三期视频的课后作业

+ 里面都是自己写的滴水三期的课后作业

  ## 2020.8.18更新

+ 新增节的时候一个节的 `VirtualSize` 是有可能大于 `SizeOfRawData` 的，要判断一下。如果前一个节的`VirtualSize` 大于其 `SizeOfRawData` ，那么要

  ```cpp
(pSectionHeader + numOfSec)->VirtualAddress =
    (pSectionHeader + numOfSec - 1)->VirtualAddress +
    ((((pSectionHeader + numOfSec - 1)->Misc.VirtualSize / 0x1000) + 1)) *
        0x1000;
  ```

  这样才能正确设置新增的节表里面填的 `VirtualAddress`

  ## 2020.8.17更新

+ 重构了自动新增节的代码。原来的代码可能有小bug。重构后的代码放在了[**原来的文件夹**](./2015.3.19-自动在EXE中新增节)中。

+ 另外发现了原来代码中的一个小问题，原来这里没有加括号，在使用的时候很可能会出现错误。在使用宏的时候还是要小心。

  ![image-20200817105545275](https://raw.githubusercontent.com/smallzhong/picgo-pic-bed/master/image-20200817105545275.png)

  ## 2020.8.6更新

+ 重构了打印导入表的代码，放在了 [**打印导入表-重构**](./打印导入表-重构) 中。半个月前写的代码今天居然跑不起来，不知道哪里出了问题，索性重构了。

  ## 2020.8.3更新

+ 更新了2015.4.27-打印资源表，把读取 `DOS` 头、 `NT` 头、节表的函数以及进行 `RVA` 和 `FOA` 互转的函数重构了一下。

  ## 2020.7.21更新

+ 导入表注入一直跑不起来，以后有时间再重新研究吧，写了一天半写不出来。明明都已经能够成功注进去了，但是就是跑不起来

  ![看不见图请爬梯子](https://raw.githubusercontent.com/smallzhong/picgo-pic-bed/master/20200715211020.png)

  ![看不见图请爬梯子](https://raw.githubusercontent.com/smallzhong/picgo-pic-bed/master/20200715211212.png)

  而且运行写的代码的时候也是出错，初步判断是指针的问题，但是debug不出来(ノへ￣、)

  ![看不见图请爬梯子](https://raw.githubusercontent.com/smallzhong/picgo-pic-bed/master/20200715211242.png)

  但是能正常写到导入表里面说明大体是没问题的。。如果有人想看看大体是怎么做的可以看看，要是能顺便帮我debug一下提个issue告诉我就最好了qwq

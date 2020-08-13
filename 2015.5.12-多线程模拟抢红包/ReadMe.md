## 做这次作业之前觉得挺简单， 做了才发现有不少坑

+ 效果如下

  ![image-20200813203554666](https://raw.githubusercontent.com/smallzhong/picgo-pic-bed/master/image-20200813203554666.png)

+ 如果把每个线程的函数中的这一行去掉，那么在下一次点击抢红包的时候 `cs` 仍是阻塞着的。就会导致程序执行一次只能按一次按钮抢一次红包。下一次点击的时候因为仍阻塞着，文本框内的文字并不会发生任何改变。

  ![image-20200813203730088](https://raw.githubusercontent.com/smallzhong/picgo-pic-bed/master/image-20200813203730088.png)

- 如果把 `while (1)` 换成 `while (g_total >= 0)` ，那么就会出现抢得红包的总数比输入的数字大，最后 `g_total` 小于 `-50` 的情况。原因是如果前面一个线程在 `g_total -= 50` 之前挂起并切换到这个线程，那么循环的条件就是成立的，就会进到循环里面去等待阻塞解除。而虽然前面的进程又将 `g_total` 减去了50，此时已经不可以再抢红包了，但是已经进到循环里面的这个线程也不可能退出，所以会出现 `g_total` 被减多次的情况。

  ![image-20200813203714244](https://raw.githubusercontent.com/smallzhong/picgo-pic-bed/master/image-20200813203714244.png)
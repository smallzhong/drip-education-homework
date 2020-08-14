## 这是根据海哥上课讲的内容写的对事件进行练习的代码

+ 按下 **Button1** 之后第一个文本框内的内容会递增至1000，然后每隔两秒下面三个文本框中的一个也会被设置为1000，最后四个文本框都被设置为1000


  ![image-20200815000514534](https://raw.githubusercontent.com/smallzhong/picgo-pic-bed/master/image-20200815000514534.png)

![image-20200815000709173](https://raw.githubusercontent.com/smallzhong/picgo-pic-bed/master/image-20200815000709173.png)

+ 创建事件的代码如下

  ```cpp
  // 默认安全属性  自动设置通知状态(FALSE)  初始状态未通知 没有名字 
  g_hEvent = CreateEvent(NULL, FALSE, FALSE, NULL);
  ```

  


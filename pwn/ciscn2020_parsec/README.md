# README

- ParseC is a simple C interpreter
- `example` is a sample for this ParseC
- You will give your source code file in base64 to remote server

# exp

比较可惜，打比赛的时候有事，只打了几个小时，最后20分钟前本地打通了，远程不行，最后发现是因为远程把输入输出缓冲去关了，本地没关，导致本地堆布局和远程不一样，emmm。  

漏洞是字符串uaf。  

构造两个tcache loop，第一个用于指向第二个来partial overwrite使它指向堆上提前布置好的free_hook地址，然后常规操作。  

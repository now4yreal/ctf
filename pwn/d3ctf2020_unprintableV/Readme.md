题目给了很多次的printf格式化字符串漏洞，但是关闭了stdout。  

利用格式化字符串漏洞：  

```
栈上有很多指针有下面的形式：  

stack_addr      :stack_addr+0x30
stack_addr+0x10 :
stack_addr+0x20 :
stack_addr+0x30 :stack_addr+0x20
stack_addr+0x40 :
...
```

利用这种栈上指向栈上的指针可以先修改指针的值指向想要修改的值，然后就是常规利用。  

另外利用修改在bss段上的stdout指针为stderr指针来进行打印输出（printf里利用bss上的stdout指针来作输出用，可以借助stderr来常规打印）  

ropper使用：ropper -f [file] --nocolor > out.txt  

栈迁移

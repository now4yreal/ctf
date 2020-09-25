vm pwn题  

mov指令未过滤产生漏洞  

首先利用mov指令修改stack_ptr指向environ(就在global_max_fast下面)，然后pop到mg1当中，再show泄露出来，泄露出来的是栈上的一个指针，应该指向的是env

然后修改stack_ptr指向ret_addr，利用push mg1将构造好的rop链布置到栈上，最后再程序返回的时候get shell
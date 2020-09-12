UAF洞  

限制申请出来的堆块在堆上0x600范围内  

首先unsorted bin attack打global_max_fast使得所有chunk都成为fastbin进而可以用fastbin attack  

然后fast bin attack 分配到urandom的FILE结构体  

在urandom的FILE结构体上构造SROP（setcontext）,覆盖vtable指针，伪造一个vtable表  

栈迁移到堆上ORW
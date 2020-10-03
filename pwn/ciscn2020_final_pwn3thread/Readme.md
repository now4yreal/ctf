输入全a测试一下可以发现程序在buffered_vfprintf+230处发生异常，原因是call rax，而rax是非法指针。  

buffered_vfprintf中调用的函数指针是从下面取来的  

```c
0x7ffa959088a8 <__libc_pthread_functions+360>:  0x98910e0977e31735      0x98910e0977231735
0x7ffa959088b8 <__libc_pthread_functions+376>:  0x98910e4e2bb31735      0x98910e0973431735
0x7ffa959088c8 <__libc_pthread_functions+392>:  0x98910e0849031735      0x98910e0bb6a31735
0x7ffa959088d8 <__libc_pthread_functions+408>:  0x98910e09ece31735      0x98910e0b97c31735
```

这是加密过的，解密过程是：  

```c
   0x7f90be404693 <buffered_vfprintf+195>    mov    rax, qword ptr [rip + 0x39220e] <0x7f90be7968a8>
   0x7f90be40469a <buffered_vfprintf+202>    lea    rdi, [rsp + 0x10]
   0x7f90be40469f <buffered_vfprintf+207>    mov    rdx, rbx
   0x7f90be4046a2 <buffered_vfprintf+210>    ror    rax, 0x11
 ► 0x7f90be4046a6 <buffered_vfprintf+214>    xor    rax, qword ptr fs:[0x30]
   0x7f90be4046af <buffered_vfprintf+223>    mov    rsi, qword ptr [rip + 0x38c8aa]
   0x7f90be4046b6 <buffered_vfprintf+230>    call   rax
```

ror是循环右移，fs:[0x30]是teb的某个值，栈溢出可以覆盖。  

思路就是先泄露fs:[0x30]，然后改为fs:[0x30]^原来的值^one，就可以get_shell
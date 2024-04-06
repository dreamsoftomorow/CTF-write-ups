

The first thing i did was i trie to run the script.
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

i needed to change `./qemu` to `./qemu-x86_64` and to install dependencies using

```
sudo apt install libcapstone-dev

sudo apt update
sudo apt install libc6
 
```


now I could run the program using `./run`!


# Anylizing the code
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

As we can see, we first map a ptr using mmap.

Calling mmap
---
*a cool trick i like using to understand the flags is just running the program with strace:
```
$ strace ./chal
...

mmap(NULL, 65536, PROT_READ|PROT_WRITE|PROT_EXEC, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0) = 0x7c1c3cf83000
...
```
___

So we create a new mapping, of size 0x10000 to a kernel-chosen address.
We can write, read and exec in that memory location.

We read all of our data into that buffer and than we jump to it.

### Doing shit with fd-s
Also, for some reason with close the `STDIN_FILENO` (0) and the `STDERR_FILENO` (1). we copy the `STDOUT_FILENO` to fd number 13.

That seems unimportant to me, but maybe we will return to that later.


### Filter function
After all of that we call the filter function, it seems like IDA struggles to decompile it so let's look at the assembly code:

![[Pasted image 20240406135930.png]]
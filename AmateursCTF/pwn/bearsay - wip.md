
# Blackbox checking

The first thing I usually do when approaching a new problem is trying to look at the program from a user's prespective, that will help me figure out attack patterns and the ways i can interact with the program as a user.

When extracting the `dist.tar.xz` file I was presented with the `chal` binary.

Running `file` on it will show us that it's an ELF 64-bit executable.

```
$ file ./chal
./chal: ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV), dynamically linked, interpreter ./lib/ld-linux-x86-64.so.2, BuildID[sha1]=79f746f54fb4d78fd8a9f34901ee607acdd0f0db, for GNU/Linux 4.4.0, not stripped
```

So we can just run it

```
$ ./chal
🧸 say: a
*****
* a *
*****
|
ʕ •ɷ•ʔฅ
```

As we can see, the program asks for an input and it outputs it back at us, Pretty simple!

One of the first thing I always check when getting a "echo" program like that is to check if the input is handled correctly.

I tried inputting `%llx %llx %llx` as my input and saw that this program is vulnrable to a format string exploit.

```
$ ./chal
🧸 say: %llx %llx %llx
******************
* 1 1 715862714887 *
******************
       |
       ʕ •ɷ•ʔฅ
🧸
```

let's look how that my is handled in the program

# Analyzing the code

# WIP
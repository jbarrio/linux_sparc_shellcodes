# Linux SPARC Shellcodes

> "The number of UNIX installations has grown to 10, with more expected."

(The *UNIX Programmer's Manual*, 2nd Edition, June, 1972)

## TOC

1. [Bibliography](#bibliography)
2. [License](#original-license-text-now-gpl-v3)
3. [Gratitude](#gratitude)
4. [Motivation](#motivation)
5. [Architecture](#architecture)
    1. [RISC](#risc)
    2. [Load/Store](#loadstore)
    3. [Pipelining](#pipelining)
    4. [Endianness: the NUXI problem](#endianness-the-nuxi-problem)
    5. [Traps](#traps)
6. [Shellcodes](#shellcodes)
    1. [Basic Exec shellcode](#basic-exec-shellcode)
    2. [Bind shellcode](#bind-shellcode)
        1. [SPARC Stack](#sparc-stack)
        2. [Optimization](#optimization)
    3. Client shellcode (connect-back)
    4. Obfuscated shellcode (polymorphic)
7. End words

## Bibliography

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

## (original) License text (now GPL v3)

*"THE BEER-WARE LICENSE" (Revision 42):
Javier Barrio wrote this file. As long as you retain this notice you can do whatever you want with this stuff. If we meet some day, and you think this stuff is worth it, you can buy me a beer in return.*

## Motivation

There are many documents explaining the creation of shellcodes. At Phrack they don't even accept any more articles on this matter. However, it is the right time to help relaunch the (NetSearch) ezine with a text that covers a gap, the shellcodes in Linux SPARC in Spanish (original version), as well as deepen the knowledge of the CPU -mainly v9- and understand its assembler.

## Gratitude

+ Sic transit gloria mundi, rwlock_t.
+ To my 48bits fellows and friends, for publishing this article.
+ To Twiz from Phrack.
+ To pancake (radare) for forcing me to add extra NOPs.
+ To Logan for not saying anything during work hours when watching me playing with ASM.
+ To Overdrive and Zosen, for special reasons.
+ On the top of the world: QSR.
+ To Richard W. Stevens, Jon B. Postel, Ken Thompson, Brian W. Kernighan, Dennis Ritchie and Mel because they are the real computer magicians.
+ To all usual suspects. They know who they are.

## Architecture

The SPARC architecture -Scalable Processor ARChitecture- is a CPU that was designed originally by SUN Microsystems in 1985. It was based on the first RISC designs from both IBM and Berkeley from the beginning of the eighties, emphasizing a minimalistic instruction set -opcodes- with the ability of being executed at high speeds.

It is a trully open non-proprietary architecture which comercial brand was established in 1989 when the SPARC International Inc. organisation was created, when they gave licenses to build the chips to companies like Fujitsu, Texas or, of course, SUN.

### RISC

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

### Load/Store

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

### Pipelining

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

### Endianness: the NUXI problem

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

### Traps

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

## Shellcodes

As per Wikipedia, a shellcode is a piece of machine code embedded as the payload of an exploit to get a shell. This is a reasonable definition but I believe it to be incomplete.

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

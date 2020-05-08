# Linux SPARC Shellcodes

> "The number of UNIX installations has grown to 10, with more expected."

(The *UNIX Programmer's Manual*, 2nd Edition, June, 1972)

## TOC

1. Bibliography
2. License
3. Gratitude
4. Motivation
5. Architecture
    1. RISC
    2. Load/Store
    3. Pipelining
    4. Endianness: the NUXI problem
    5. Traps
6. Shellcodes
    1. Basic Exec shellcode
    2. Bind shellcode
        1. SPARC Stack
        2. Optimization
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

## (original) License (now GPL v3)

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

``ld  [%o0], %o1``
``sub %o1, %o2, %o3``

When it does the ``load`` and gets the datum from memory, it would be performing the substraction **at the same time** and thus, being a parallel execution, the datum loaded could not be the expected one. The processor can detect this and wait a clock cycle before getting the right value, but then it will be wasting resources. This is where the compiler optimization comes in place, as it was mentioned before, putting in its hands the decision of inserting between these two instructions a third one that doesn't affect the the substraction and allows to not waste the CPU cycle. This is known as 'load delay slot'.

The second issue, known as the 'branching delay slot', occurs when an instruction modifies the programme flux. For instance, a ``call`` instruction to execute a subroutine *is* a branching delay slot. What happens in this case is that the processor is not capable of waiting a cycle by itself and executes the next instruction. This, like in the previous case, instead of being a problem, can be used as an advantage to optimize code to its maximum, but as usual this is also in the hands of the programmer and, as nowadays assembler is not a widely used language, it is a task carried almost exclusively by the compiler. Nevertheless, maybe the reader understands know why we can find lots of NOP instructions in lots of codes *just after a* ``call``, emulating how the CPU behaves in the case of the load delay slot. Maybe in lieu of a NOP we could assign a value to an output register that will be used by the callee function and thus, not wasting the cycle.

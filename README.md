# Linux **SPARC** Shellcodes

"The number of UNIX installations has grown to 10, with more expected."

(The *UNIX Programmer's Manual*, 2nd Edition, June, 1972)

1. Bibliography
2. License
3. Gratitude
4. Motivation
5. Architecture
    5.1. RISC
    5.2. Load/Store
    5.3. Pipelining
    5.4. Endianness: the NUXI problem
    5.5. Traps
6. Shellcodes
    6.1. Basic Exec shellcode
    6.2. Bind shellcode
        6.2.1. SPARC Stack
        6.2.2. Optimization
    6.3. Client shellcode (connect-back)
    6.4. Obfuscated shellcode (polymorphic)
7. End words

## Bibliography

I consider important to expose as a first point the bibliography used as support to write this document, so the reader can quickly check the links provided or can purchase the referenced books. In this way, it will also help the reader to know what she will find in this text.

- SPARC Architecture, Assembly Language Programming, and C, 2nd Ed.
    Richard P. Paul 1994, 2000 -Prentice Hall
    ISBN 0-13-025596-3

- The SPARC Architecture Manual, version 9
    David L. Weaver / Tom Germond, 1994 -Prentice Hall
    ISBN 0-13-099227-5

- SPARC Assembly Language Reference Manual
    http://www.cs.umu.se/kurser/5DV074/HT07/mom2/816-1681.pdf

- Intel 64 and IA-32 Intel Architecture Software Developer's Manual, Vol 1
    Intel, 1997-2002 -Intel
    Not a joke, it's quite handy

- System V Application Binary Interface, SPARC Processor Suplement, 3rd Ed
    http://www.sparc.org/standards/psABI3rd.pdf

- Phrack

- NetSearch

## License

"THE BEER-WARE LICENSE" (Revision 42):
<coder/A/fluzo/D/org> wrote this file. As long as you retain this notice you can do whatever you want with this stuff. If we meet some day, and you think this stuff is worth it, you can buy me a beer in return. Javier Barrio

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
+ Too all usual suspects. They know who they are.

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

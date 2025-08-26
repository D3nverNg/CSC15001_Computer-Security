Note: this README.txt is the same as the one in challenge LEGv8

The program is based on a book about Computer Organization:
https://drive.google.com/file/d/1lHkHTj9_vwPEB-a912YliDRIgE0PlwIN/view?usp=sharing

I reimplemented the datapath in Figure 4.17 (page 361), Chapter 4. It supports the following instructions:
- R-type: ADD, SUB, AND, ORR
- LDUR, STUR
- CBZ

Some information you might need:
- Format of a 32-bit instruction: See Figure 4.14 (page 358)
  + For our four R-type instructions, the shamt (shift amount) field is not used. It’s only used in instructions like LSR/LSL.
  + The Sign-extend component takes the immediate value from the 32-bit instruction (if any) and sign-extends it to 64 bits.
  + For example, in Figure 4.14, for LDUR/STUR, it takes the address field [20:12] and sign-extends it.
- For the CBZ instruction, the address field [23:5] is relative to the current PC, not an absolute address.
  For example, if the address field is -4, it means to jump back 4 instructions. The new PC is calculated as: newPC = PC + (-4) * 4
- Signal calculation based on OPCODE (function decodeAndSetControl): See Figure 4.22 (page 365)
- ALU control (function generateALUControl): See Figure 4.12 (page 356)
- XZR is X31 — it's always zero.

There’s an assembler.py file included in the .zip (written by AI), and an example.py script to interact with the program.

I’m writing this so you players don’t waste too much time struggling to understand the datapath.
That’s all I have to say. Good luck.

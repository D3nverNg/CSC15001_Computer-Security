import re

class LegV8Assembler:
    """
    A two-pass assembler for a subset of the LEGv8 instruction set.
    """

    def __init__(self):
        # Define the instruction set details: opcode and format
        self.instructions = {
            # RRR-Format
            'ADD':  {'opcode': '10001011000', 'format': 'RRR'},
            'SUB':  {'opcode': '11001011000', 'format': 'RRR'},
            'AND':  {'opcode': '10001010000', 'format': 'RRR'},
            'ORR':  {'opcode': '10101010000', 'format': 'RRR'},
            # RM-Format (D-Format)
            'LDUR': {'opcode': '11111000010', 'format': 'RM'},
            'STUR': {'opcode': '11111000000', 'format': 'RM'},
            # RL-Format (CB-Format)
            'CBZ':  {'opcode': '10110100', 'format': 'RL'},
        }
        self.symbol_table = {}

    def assemble(self, code: str) -> list[str]:
        """
        Assembles LEGv8 source code into binary machine code.

        Args:
            code: A string containing the LEGv8 assembly code.

        Returns:
            A list of strings, where each string is a 32-bit binary instruction.
        """
        # Clean and parse lines into an intermediate representation
        parsed_lines = self._parse_source(code)

        # Pass 1: Build the symbol table for labels
        self._build_symbol_table(parsed_lines)

        # Pass 2: Generate machine code
        machine_code = self._generate_machine_code(parsed_lines)

        return machine_code

    def assemble_bytes(self, code: str) -> bytes:
        binary_code = self.assemble(code)
        all_bytes = b''
        for instruction_str in binary_code:
            instruction_val = int(instruction_str, 2)
            instruction_bytes = instruction_val.to_bytes(4, byteorder='little')
            all_bytes += instruction_bytes

        return all_bytes

    def _parse_source(self, code: str) -> list[dict]:
        """
        Parses raw code into a list of dictionaries.
        This new version correctly handles label-only lines.
        """
        parsed_lines = []
        for line_num, line_str in enumerate(code.strip().split('\n'), 1):
            # Remove comments and strip whitespace
            line = line_str.split('//')[0].strip().upper()
            if not line:
                continue

            label = None
            # Check for a label and strip it from the line if present
            if ':' in line:
                parts = line.split(':', 1)
                label_candidate = parts[0].strip()
                if re.match(r"^[A-Z_][A-Z0-9_]*$", label_candidate):
                    label = label_candidate
                    line = parts[1].strip() # The rest of the line is the instruction
                else:
                    raise ValueError(f"Invalid label format on line {line_num}: '{label_candidate}'")
            
            # If the line is now empty, it was a label-only line
            if not line:
                parsed_lines.append({'label': label, 'mnemonic': None, 'args_str': None})
                continue

            # Parse the remaining part for mnemonic and args
            parts = line.split(maxsplit=1)
            mnemonic = parts[0]
            args_str = parts[1] if len(parts) > 1 else ""

            if mnemonic not in self.instructions:
                raise ValueError(f"Unsupported instruction on line {line_num}: '{mnemonic}'")

            parsed_lines.append({
                'label': label,
                'mnemonic': mnemonic,
                'args_str': args_str.replace(" ", "")
            })
        return parsed_lines

    def _build_symbol_table(self, parsed_lines: list[dict]):
        """First pass: Populate the symbol table with labels and their addresses."""
        self.symbol_table = {}
        instruction_address = 0
        for line in parsed_lines:
            if line['label']:
                if line['label'] in self.symbol_table:
                    raise ValueError(f"Duplicate label defined: '{line['label']}'")
                # The label points to the address of the *next* instruction
                self.symbol_table[line['label']] = instruction_address
            
            # Only increment the address if there is an actual instruction on the line
            if line['mnemonic']:
                instruction_address += 1

    def _generate_machine_code(self, parsed_lines: list[dict]) -> list[str]:
        """Second pass: Generate binary code for each instruction."""
        machine_code = []
        current_address = 0
        for line in parsed_lines:
            # Skip label-only lines, as they don't produce machine code
            if not line['mnemonic']:
                continue

            mnemonic = line['mnemonic']
            instr_info = self.instructions[mnemonic]
            instr_format = instr_info['format']
            
            # Dispatch to the correct encoding function based on format
            if instr_format == 'RRR':
                binary_instr = self._encode_rrr(line)
            elif instr_format == 'RM':
                binary_instr = self._encode_rm(line)
            elif instr_format == 'RL':
                binary_instr = self._encode_rl(line, current_address)
            else:
                raise NotImplementedError(f"Encoding for format '{instr_format}' not implemented.")

            machine_code.append(binary_instr)
            current_address += 1
        return machine_code

    # --- Helper methods for parsing and binary conversion (unchanged) ---

    def _parse_register(self, reg_str: str) -> int:
        if reg_str == 'XZR': return 31
        if reg_str.startswith('X'): return int(reg_str[1:])
        raise ValueError(f"Invalid register format: '{reg_str}'")

    def _to_binary(self, num: int, bits: int, signed: bool = False) -> str:
        if signed and num < 0:
            num = (1 << bits) + num
        elif not signed and (num < 0 or num >= (1 << bits)):
             raise ValueError(f"Unsigned value {num} out of range for {bits} bits.")
        elif signed and (num < -(1 << (bits - 1)) or num >= (1 << (bits - 1))):
            raise ValueError(f"Signed value {num} out of range for {bits} bits.")
        return format(num, f'0{bits}b')

    # --- Encoding functions for each instruction format (unchanged) ---
    def _encode_rrr(self, line: dict) -> str:
        opcode = self.instructions[line['mnemonic']]['opcode']
        args = line['args_str'].split(',')
        if len(args) != 3: raise ValueError(f"Invalid arguments for R-Format: {line['args_str']}")
        rd, rn, rm = (self._to_binary(self._parse_register(arg), 5) for arg in args)
        shamt = '000000'
        return f"{opcode}{rm}{shamt}{rn}{rd}"

    def _encode_rm(self, line: dict) -> str:
        opcode = self.instructions[line['mnemonic']]['opcode']
        match = re.match(r"(X\d+|XZR),\[(X\d+|XZR)(?:,#(-?\d+))?\]", line['args_str'])
        if not match: raise ValueError(f"Invalid arguments for D-Format: {line['args_str']}")
        rt_str, rn_str, imm_str = match.groups()
        rt = self._to_binary(self._parse_register(rt_str), 5)
        rn = self._to_binary(self._parse_register(rn_str), 5)
        immediate = int(imm_str) if imm_str else 0
        if not (-256 <= immediate <= 255): raise ValueError(f"Immediate {immediate} out of range for LDUR/STUR. Must be [-256, 255].")
        dt_address = self._to_binary(immediate, 9, signed=True)
        op2 = '00'
        return f"{opcode}{dt_address}{op2}{rn}{rt}"

    def _encode_rl(self, line: dict, current_address: int) -> str:
        opcode = self.instructions[line['mnemonic']]['opcode']
        args = line['args_str'].split(',')
        if len(args) != 2: raise ValueError(f"Invalid arguments for CB-Format: {line['args_str']}")
        rt = self._to_binary(self._parse_register(args[0]), 5)
        label = args[1]
        if label not in self.symbol_table: raise ValueError(f"Undefined label: '{label}'")
        target_address = self.symbol_table[label]
        offset = target_address - current_address
        cond_br_address = self._to_binary(offset, 19, signed=True)
        return f"{opcode}{cond_br_address}{rt}"

if __name__ == '__main__':
    # example usage, a program that calculate sum from 0 to 10, and save to memory
    # init: X2 = 1, X1 = 10, X10 = 0x50100 (rw memory region)
    assembly_code = """
        ORR X0, XZR, XZR    // sum = 0
    LOOP:
        ADD X0, X0, X1      // sum = sum + counter
        SUB X1, X1, X2      // counter = counter - 1 (using X2 as 1)
        CBZ X1, END         // if counter is zero, go to end.
        CBZ XZR, LOOP       // always jump to LOOP if reach this line
    
    END:
        STUR X0, [X10, #8]     // save sum to 0x50108
        LDUR X0, [X10, #-200]  // X0 = *(long*)(X10 - 200)
    """

    print("--- Assembling Final Valid Code ---")
    assembler = LegV8Assembler()
    
    try:
        binary_code_bytes = assembler.assemble_bytes(assembly_code)
        print(len(binary_code_bytes), binary_code_bytes.hex())
        print("Assembly Successful!")
        print(binary_code_bytes.hex())
    except ValueError as e:
        print(f"Assembly Failed: {e}")

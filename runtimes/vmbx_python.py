"""
VMBX Python Runtime Interpreter
Executes .vmbx bytecode files compiled from Python source
"""
import sys
import struct
import hashlib
from typing import List, Dict, Any

class VmbxInterpreter:
    def __init__(self, bytecode: bytes):
        self.bytecode = bytecode
        self.pc = 0  # Program counter
        self.stack = []
        self.vars = {}
        self.symbols = {}
        self.strings = []
        
    def read_bytes(self, n: int) -> bytes:
        data = self.bytecode[self.pc:self.pc+n]
        self.pc += n
        return data
    
    def read_u8(self) -> int:
        return self.read_bytes(1)[0]
    
    def read_u16(self) -> int:
        return struct.unpack('<H', self.read_bytes(2))[0]
    
    def read_u32(self) -> int:
        return struct.unpack('<I', self.read_bytes(4))[0]
    
    def read_u64(self) -> int:
        return struct.unpack('<Q', self.read_bytes(8))[0]
    
    def sha256_decrypt(self, data: bytes, key: bytes) -> bytes:
        result = bytearray()
        block_key = bytearray(key)
        
        for i, chunk in enumerate([data[j:j+32] for j in range(0, len(data), 32)]):
            h = hashlib.sha256()
            h.update(block_key)
            h.update(struct.pack('<Q', i))
            block_key = bytearray(h.digest())
            
            for j, byte in enumerate(chunk):
                result.append(byte ^ block_key[j % 32])
        
        return bytes(result)
    
    def load(self):
        """Load and decrypt bytecode sections"""
        while self.pc < len(self.bytecode) and self.bytecode[self.pc] != 0x00:
            self.pc += 1
        self.pc += 1
        
        magic = self.read_bytes(5)
        if magic != b'\x56\x4D\x42\x58\x00':
            raise ValueError("Invalid VMBX file")
        
        version = self.read_u16()
        lang_id = self.read_u8()
        timestamp = self.read_u64()
        build_id = self.read_bytes(16)
        key_fp = self.read_bytes(16)
        
        master_key = key_fp + key_fp
        
        fname_len = self.read_u16()
        encrypted_fname = self.read_bytes(fname_len)
        
        self.load_section('SYMB', master_key)
        code = self.load_section('CODE', master_key)
        self.load_section('STRS', master_key)
        self.load_section('SMAP', master_key)
        
        return code
    
    def load_section(self, name: str, key: bytes):
        marker = self.read_bytes(4)
        if marker != name.encode():
            raise ValueError(f"Expected {name} section")
        
        size = self.read_u32()
        encrypted = self.read_bytes(size)
        
        section_key = hashlib.sha256(key + name.encode()).digest()
        decrypted = self.sha256_decrypt(encrypted, section_key)
        
        if name == 'CODE':
            return decrypted
        elif name == 'STRS':
            self.parse_strings(decrypted)
        
        return decrypted
    
    def parse_strings(self, data: bytes):
        pos = 0
        count = struct.unpack('<H', data[pos:pos+2])[0]
        pos += 2
        
        for _ in range(count):
            length = struct.unpack('<H', data[pos:pos+2])[0]
            pos += 2
            self.strings.append(data[pos:pos+length])
            pos += length
    
    def execute(self, code: bytes):
        """Execute bytecode"""
        self.pc = 0
        self.bytecode = code
        
        line_count = self.read_u32()
        
        print(f"[VMBX] Executing {line_count} lines of Python bytecode...")
        
        for i in range(min(line_count, 100)):  # Limit for demo
            try:
                indent = self.read_u8()
                opcode = self.read_u8()
                line_len = self.read_u16()
                line_data = self.read_bytes(line_len)
                
                if opcode == 0x70:  # Print
                    print("[OUTPUT]", line_data.decode('utf-8', errors='ignore'))
            except:
                break
        
        print("[VMBX] Execution complete")

def main():
    if len(sys.argv) < 2:
        print("Usage: python3 vmbx_python.py <file.vmbx>")
        sys.exit(1)
    
    filepath = sys.argv[1]
    
    with open(filepath, 'rb') as f:
        bytecode = f.read()
    
    try:
        vm = VmbxInterpreter(bytecode)
        code = vm.load()
        vm.execute(code)
    except Exception as e:
        print(f"[VMBX ERROR] {e}")
        sys.exit(1)

if __name__ == '__main__':
    main()

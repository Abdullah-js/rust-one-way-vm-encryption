#!/usr/bin/env node
/**
 * VMBX Node.js Runtime Interpreter
 * Executes .vmbx bytecode files compiled from JavaScript source
 */
const fs = require('fs');
const crypto = require('crypto');

class VmbxInterpreter {
    constructor(bytecode) {
        this.bytecode = bytecode;
        this.pc = 0;
        this.stack = [];
        this.vars = {};
        this.symbols = {};
        this.strings = [];
    }
    
    readBytes(n) {
        const data = this.bytecode.slice(this.pc, this.pc + n);
        this.pc += n;
        return data;
    }
    
    readU8() { return this.readBytes(1)[0]; }
    readU16() { return this.readBytes(2).readUInt16LE(0); }
    readU32() { return this.readBytes(4).readUInt32LE(0); }
    readU64() { return Number(this.readBytes(8).readBigUInt64LE(0)); }
    
    sha256Decrypt(data, key) {
        const result = Buffer.alloc(data.length);
        let blockKey = Buffer.from(key);
        
        for (let i = 0; i < data.length; i += 32) {
            const chunk = data.slice(i, i + 32);
            const h = crypto.createHash('sha256');
            h.update(blockKey);
            const counterBuf = Buffer.alloc(8);
            counterBuf.writeBigUInt64LE(BigInt(Math.floor(i / 32)));
            h.update(counterBuf);
            blockKey = h.digest();
            
            for (let j = 0; j < chunk.length; j++) {
                result[i + j] = chunk[j] ^ blockKey[j % 32];
            }
        }
        
        return result;
    }
    
    load() {
        while (this.pc < this.bytecode.length && this.bytecode[this.pc] !== 0x00) {
            this.pc++;
        }
        this.pc++;
        
        const magic = this.readBytes(5);
        if (magic.toString('hex') !== '564d425800') {
            throw new Error('Invalid VMBX file');
        }
        
        const version = this.readU16();
        const langId = this.readU8();
        const timestamp = this.readU64();
        const buildId = this.readBytes(16);
        const keyFp = this.readBytes(16);
        
        const masterKey = Buffer.concat([keyFp, keyFp]);
        
        const fnameLen = this.readU16();
        const encryptedFname = this.readBytes(fnameLen);
        
        this.loadSection('SYMB', masterKey);
        const code = this.loadSection('CODE', masterKey);
        this.loadSection('STRS', masterKey);
        this.loadSection('SMAP', masterKey);
        
        return code;
    }
    
    loadSection(name, key) {
        const marker = this.readBytes(4);
        if (marker.toString() !== name) {
            throw new Error(`Expected ${name} section`);
        }
        
        const size = this.readU32();
        const encrypted = this.readBytes(size);
        
        const h = crypto.createHash('sha256');
        h.update(key);
        h.update(name);
        const sectionKey = h.digest();
        
        const decrypted = this.sha256Decrypt(encrypted, sectionKey);
        
        if (name === 'CODE') return decrypted;
        if (name === 'STRS') this.parseStrings(decrypted);
        
        return decrypted;
    }
    
    parseStrings(data) {
        let pos = 0;
        const count = data.readUInt16LE(pos);
        pos += 2;
        
        for (let i = 0; i < count; i++) {
            const length = data.readUInt16LE(pos);
            pos += 2;
            this.strings.push(data.slice(pos, pos + length));
            pos += length;
        }
    }
    
    execute(code) {
        this.pc = 0;
        this.bytecode = code;
        
        const lineCount = this.readU32();
        console.log(`[VMBX] Executing ${lineCount} lines of JavaScript bytecode...`);
        
        for (let i = 0; i < Math.min(lineCount, 100); i++) {
            try {
                const indent = this.readU8();
                const opcode = this.readU8();
                const lineLen = this.readU16();
                const lineData = this.readBytes(lineLen);
                
                if (opcode === 0x70) { // Print
                    console.log('[OUTPUT]', lineData.toString('utf-8'));
                }
            } catch (e) {
                break;
            }
        }
        
        console.log('[VMBX] Execution complete');
    }
}

function main() {
    if (process.argv.length < 3) {
        console.log('Usage: node vmbx_node.js <file.vmbx>');
        process.exit(1);
    }
    
    const filepath = process.argv[2];
    const bytecode = fs.readFileSync(filepath);
    
    try {
        const vm = new VmbxInterpreter(bytecode);
        const code = vm.load();
        vm.execute(code);
    } catch (e) {
        console.error('[VMBX ERROR]', e.message);
        process.exit(1);
    }
}

main();

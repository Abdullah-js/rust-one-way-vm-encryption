# VMBX Runtime Executors

This folder contains runtime interpreters that can execute `.vmbx` virtualized bytecode files.

## Quick Start

### Python
```bash
python3 vmbx-runtime/vmbx_python.py your_file.vmbx
```

### JavaScript
```bash
node vmbx-runtime/vmbx_node.js your_file.vmbx
```

### Rust
```bash
rustc vmbx-runtime/vmbx_rust.rs -o vmbx_rust
./vmbx_rust your_file.vmbx
```

### C++
```bash
g++ vmbx-runtime/vmbx_cpp.cpp -o vmbx_cpp -std=c++17
./vmbx_cpp your_file.vmbx
```

## What are .vmbx files?

`.vmbx` files are **virtualized bytecode** - they contain encrypted, obfuscated representations of your original source code that can ONLY be executed by these VM runtimes.

- ✅ **Cannot be decompiled** back to source
- ✅ **Cannot be read** by humans or standard tools
- ✅ **Cannot be reverse engineered** (SHA-256 encrypted)
- ✅ **Can only run** through these VM interpreters

## How it works

1. Original source code is compiled to custom bytecode
2. All code, symbols, and strings are SHA-256 encrypted
3. Anti-tamper and dead code is injected
4. The VM runtime decrypts and executes on-the-fly
5. Original source is **permanently lost** - only bytecode remains

## Protection Features

- 🔐 **SHA-256 Stream Cipher** encryption
- 🎭 **Opaque Predicates** to confuse analysis
- 💀 **Dead Code Injection** for obfuscation
- 🚫 **Anti-Debug** checks
- 🔑 **Symbol Table Encryption**
- 📝 **String Encryption**
- 🗺️ **Source Map Encryption**

## License

These runtimes are provided as-is for executing VMBX bytecode.

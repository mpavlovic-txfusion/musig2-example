# 🔐 MuSig2 Example

A simple demonstration of MuSig2 signing functionality.

For technical details about the MuSig2 protocol, see the [original paper](https://eprint.iacr.org/2020/1261).


## 🛠️ Prerequisites

- Rust toolchain
- Cargo package manager

## ⚡ Quick Start

### Non-distributed demo
Run the basic MuSig2 example:
```shell
cargo run --example basic_musig2
```

### 🌐 Distributed system with multiple signers running on different ports

Run two signers that communicate over TCP connection:

#### Terminal 1
```shell
cargo run --bin signer -- --port 8080 --peers 8081 --num-of-signers 2
```

#### Terminal 2
```shell
cargo run --bin signer -- --port 8081 --peers 8080 --num-of-signers 2
```

## 🔍 What Happens?

The demo showcases MuSig2 multi-signature protocol in action:

1. ✨ Signers establish WebSocket connections
2. 🔑 Exchange public keys
3. 📝 Initialize first and second round of MuSig2 (generating nonces and partial signatures)
4. 🤝 Collaborate to create an aggregated signature
5. ✅ Verify the resulting signature with the aggregated public key
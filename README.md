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

### 🌐 Distributed system with multiple Signers and the Operator (Coordinator) node running on different ports

Run the Operator:
#### Terminal 1
```shell
cargo run --bin operator -- --port 3030
```

Run multiple Signers (at least 2) on different ports:

#### Terminal 2
```shell
cargo run --bin signer -- --port 8080 --operator-url http://127.0.0.1:3030 
```

#### Terminal 3
```shell
cargo run --bin signer -- --port 8081 --operator-url http://127.0.0.1:3030 
```

Send HTTP request to initiate signing:
#### Terminal 4
```shell
curl -X POST http://localhost:3030/sign \
  -H "Content-Type: application/json" \
  -d '{
    "message": "Hello, this is a message to be signed!"
  }' 
```

## 🔍 What Happens?

The demo showcases MuSig2 multi-signature protocol in action:

1. 🤝 Each signer registers to the operator by sending it's public key and address.
2. 🔑 Operator handles the singing process:
    - Creates a key aggregation context with all signer public keys.
    - Sends a request to each Signer to generate nonces and return public nonce.
    - Handles the public nonce exchange between the signers and receives the partial signatures.
    - Handles the patrial signature exchange between the signers and receives the final signatures.
3. ✅ Verify the resulting signatures are the same and valid with the aggregated public key
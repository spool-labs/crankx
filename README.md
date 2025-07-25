# CrankX

![license](https://img.shields.io/badge/license-MIT-blue.svg?style=flat)
[![crates.io](https://img.shields.io/crates/v/crankx.svg?style=flat)](https://crates.io/crates/crankx)

CrankX is a Rust crate for proving access to stored data segments using the EquiX Proof-of-Work algorithm. Developed for TAPEDRIVE and optimized for Solana, it enables miners to earn rewards by demonstrating possession of specific data. The design is loosely based on Ore’s `drillx`, with an added data-verification step.

---

## Quick Start

Solve challenge,

```rust
use crankx::{solve, CrankXError};

fn main() -> Result<(), CrankXError> {
    let challenge = [0u8; 32];
    let data = [1u8; 64];
    let nonce = [0u8; 8];

    let solution = solve(&challenge, &data, &nonce)?;

    println!("Digest: {:?}", solution.d);
    println!("Difficulty: {}", solution.difficulty());
    Ok(())
}
```

Verify solution,

```rust
use crankx::{verify, CrankXError};

fn main() -> Result<(), CrankXError> {
    let challenge = [0u8; 32];
    let data = [1u8; 64];
    let nonce = [0u8; 8];
    let digest = [0u8; 16];

    verify(&challenge, &data, &nonce, &digest)?;

    println!("Valid!");
    Ok(())
}
```

Returns `Ok()` or `Err(CrankXError)`.

---

## Contributing

Contributions are welcome! Please open issues or PRs on the GitHub repo.


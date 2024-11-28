# OpenZL

![OpenZL](https://user-images.githubusercontent.com/720571/167014503-10117012-c898-4d54-802a-966eb02dab98.svg)

## Overview

OpenZL is an open-source library that helps practitioners (especially in Web3 space) to develop and deploy secure, high performance zero-knowledge proof code in production. It tries to bridge the gap between low level cryptographic primitives and developers need to build scalable protocols using zero-knowledge proof cryptography securely and quickly. More specifically, many developers today want to leverage zero-knowledge proof systems to build powerful protocols like ZCash/Manta/ZKSync. However, they are facing two less than ideal choices; first, building a protocol using high-level languages like [Circom](https://docs.circom.io) or [Cairo](https://www.cairo-lang.org) loses many performance optimization opportunities, and second, building the protocol directly using libraries like [`arkworks/groth16`](https://github.com/arkworks-rs/groth16), [`zk-garage/plonk`](https://github.com/zk-garage/plonk), or [`microsoft/nova`](https://github.com/microsoft/Nova) requires expertise in cryptography and can be very error-prone. Also, zero-knowledge proof systems are a moving target. There have been many new, and "better", proof systems coming out every 2-3 years ([BCTV](https://eprint.iacr.org/2013/879.pdf) -> [Groth16](https://eprint.iacr.org/2016/260.pdf) -> [Plonk](https://eprint.iacr.org/2019/953) -> [Nova](https://eprint.iacr.org/2021/370)). OpenZL tries to solve this problem by building flexible, proof-system agnostic, and extensible libraries for Web3 practitioners.  

OpenZL consists of 3 parts:
* *Gadget libraries*: a library of gadgets that developers can use as building blocks for their protocols. The initial range of the gadgets includes accumulators (merkle tree with zero-knowledge membership proof), zk-friendly hash functions (poseidon hash), and commitment schemes. The gadget libraries are programmed in `eclair`.
* *Embedded Circuit Language And Intermediate Representation (`eclair`)*: An embedded DSL in Rust that describes circuit logic. `eclair` leverages Rust's expressive type system to rule out certain classes of errors during the circuit construction.
* *Adaptors to Proof Systems*: Adaptors that convert circuit logic in `eclair` to the constraint systems used in different proof systems. The initial supported proof systems are [`arkworks/groth16`](https://github.com/arkworks-rs/groth16), [`zk-garage/plonk`](https://github.com/zk-garage/plonk), and [`microsoft/nova`](https://github.com/microsoft/Nova).

## OpenZL Goals and Non-Goals

### Goals

* A *production ready* and *proof-system agnostic* ZK library for blockchain applications (support [`arkworks/groth16`](https://github.com/arkworks-rs/groth16), [`zk-garage/plonk`](https://github.com/zk-garage/plonk), and [`microsoft/nova`](https://github.com/microsoft/Nova)).
* `eclair` (**E**mbedded **C**ircuit **L**anguage **A**nd **I**ntermediate **R**epresentation): A shallow embedded circuit DSL in Rust that can rule out some common errors using Rust's type systems and still allow for optimizing circuits.
* Common gadgets such as hash functions, commitment schemes, accumulators, and more in `eclair`.
* Able to compile both prover and verifier to standard WASM and substrate flavored WASMI.
* Tutorials to support substrate ecosystem zero-knowledge proof applications.

### Non-Goals

* Build high-level languages like Circom and Cairo (would love to see someone else build high-level languages that compile to `eclair` though).
* Build "yet another PLONK". 
* Create more fragmentation in ZK tooling space.

## OpenZL Design in Detail

### Gadget Library

OpenZL provides list of cryptographic primitives with *optimized* zero-knowledge proof implementations in `eclair`. 
These gadgets are composable and can be combined to build more powerful protocols such as anonymous payment (ZCash/Manta) or zk-rollups. The gadget library that OpenZL provides on its initial release includes:
* *hashing gadget*: an optimized implementation of the Poseidon Hash Function [1], with parameterized arity (2, 4, 8)
* *accumulator gadget*: Merkle tree gadget that supports zero-knowlegde membership proofs. The Merkle tree gadget supports incremental updates as well.
* *commitment gadget*: A commitment scheme that is both *binding* and *hiding*. This commitment scheme is built on top of the *hashing gadget*.

### Embedded Circuit Language And Intermediate Representation (`eclair`)

Embedded Circuit Language And Intermediate Representation (`eclair`) is a shallow embedded DSL within Rust that serves the circuit description language in the OpenZL stack. It has the following design considerations:
* *Proof system agnostic*: `eclair` is an IR that describes the circuit logic instead of lower-level proof-systems-specific semantics and optimizations.
* *Unifying native and constraint code*: Writing zero-knowledge proof code in common framework like `arkworks`, it requires programmers to write the same logic twice -- one for constraints generation, one for native execution. This creates a huge burden on developers and is also error-prone. `eclair` solves this problem elegantly (see later an example) by introducing the concept of a "compiler". Developers only need to write the circuit logic in `eclair` once, and it compiles to both native code and constraints. Developers not only write circuit logic once, they also don't have to worry about the disparity between the native code and the constraint generating code (which could certainly be an existing bug in current applications). In addition, `eclair` automatically generates sanity check code for both native execution and constraints generation.
* *ruling out common errors*: At *compile time*, `eclair` checks that private witnesses stay private and the public inputs stay public. For example, if a circuit implementer that is not using `eclair` misuses private witness allocation, this could cause a leakage of sercret key in the protocol implementation.   

Below is an example of a sub-circuit defined in `eclair` (this is Manta testnet V2 code in [manta-rs](https://github.com/Manta-Network/manta-rs)):
```rust
impl<C> SenderVar<C>
where
    C: Configuration,
{
    /// Returns the asset for `self`, checking if `self` is well-formed in the given `compiler`.
    #[inline]
    pub fn get_well_formed_asset(
        self,
        parameters: &FullParametersVar<C>,
        compiler: &mut C::Compiler,
    ) -> AssetVar<C> {
        // 1. Derive the public key from the secret spending key.
        let public_spend_key = parameters.derive(&self.secret_spend_key, compiler);
        
        // 2. Compute the UTXO by hashing together a one-time key, the public key and
        //    the asset.
        let utxo = parameters.utxo(
            &self.ephemeral_secret_key,
            &public_spend_key,
            &self.asset,
            compiler,
        );
        
        // 3. Assert that the UTXO membership proof is valid against the computed UTXO and
        //    the known Merkle root.
        self.utxo_membership_proof.assert_valid(
            &parameters.utxo_accumulator_model,
            &utxo,
            compiler,
        );
        
        // 4. Compute the void number by hashing together the secret spending key and
        //    the UTXO.
        let void_number = parameters.void_number(&self.secret_spend_key, &utxo, compiler);
        
        // 5. Assert that the void number computed in the previous step is equal to the one
        //    provided as public input.
        compiler.assert_eq(&self.void_number, &void_number);
        
        // 6. Return the asset back to the caller.
        self.asset
    }
}
```

The above code snippet describes the logic of checking well-formness of a private input in a private transfer protocol.
1. Derive the public key from the secret spending key.
2. Compute the UTXO by hashing together a one-time key, the public key and the asset.
3. Assert that the UTXO membership proof is valid against the computed UTXO and the known Merkle root.
4. Compute the void number by hashing together the secret spending key and the UTXO
5. Assert that the void number computed in the previous step is equal to the one provided as public input.
6. Return the asset back to the caller.

One observation here is that the code passed in `compiler` as an argument. When the `compiler` argument is `()`, (meaning the native Rust compiler, the default compiler), this piece of `eclair` code will perform native execution. When the `compiler` argument is `Groth16`, this piece of code generates `R1CS` constraints for a Groth16 proof system. When the `compiler` argument is `Plonk`, this piece of code generates polynomial constraints for the `Plonk` proof system.

### Adaptors to Proof Systems

OpenZL implements adaptors to different constraint systems used in different underlying proof systems. The current supported underlying constaint systems include:
* R1CS in [`arkworks/groth16`](https://github.com/arkworks-rs/groth16) (support level: production)
* Plonk constraints in [`zk-garage/plonk`](https://github.com/zk-garage/plonk) (support level: experimental)
* Relaxed R1CS in [`microsoft/nova`](https://github.com/microsoft/Nova) (support level: experimental)

These adapters compile `eclair` to the constraints in different constraint systems. This architecture is inspired by the modern compiler frameworks such as [LLVM](https://github.com/llvm/llvm-project). In addition to merely being adapters, many proof-system-specific optimizations can be implemented at the adapter level. For example, at the adapter level, we can leverage customized gates in Plonk to reduce the constraint size in Plonk, which would not be applicable in R1CS systems.

## Existing Prototype

OpenZL is not being built out of thin air. The majority of the code is live in Manta's internal infrastructure now ([manta-rs](https://github.com/Manta-Network/manta-rs)). Below is the list of existing or migratable features:

| feature  | code |  audit | 
|----------|------| -------|
| gadget/hashing |  Complete | Not started | 
| gadget/commitment |  In progress  |  Not started |
| gadget/accumulator |  Complete  |  Not started |
| eclair | Protype |  Not started |
| adapter/Groth16 | Complete | Not started |
| adapter/Plonk | In progress | Not started |
| adapter/Nova | Not started | Not started |

## Tutorials 

We will provide `substrate`-specific tutorials to show case how to code an end-to-end example using the OpenZL library. Potential examples include:
* Build a `tornado.cash` styled private IOU system.
* Build a simple zk-rollup for substrate-based payment.

## OpenZL Milestones and Deliveries

* Milestone 1 (Prototype): July, 2022
   * Code complete for all gadget libraries
   * Code complete for `eclair`
   * Code complete for `groth16` adaptor
   * End-to-end example and test using `groth16` backend
* Milestone 2 (Feature Complete): Sep, 2022
   * Code complete (experimental) for `plonk` backend
   * Code complete (experiemental) for `nova` backend
   * Spec complete for security audit 
* Milestone 3 (Audit): Nov. 2022
  Potential auditors: ABDK, Least Authority, Trail of Bits
  * Audit complete for all production level support code
  * Substrate based tutorials
  * Trusted-setup toolings 

## Project Budgets:
| Item  |  Budgets (USD) |  Remark  |
|-------|----------|---------|
| Developer Salary  | 405,000  | (4 cryptographic engineers * 6 months + 1 devop engineer * 0.5 month )  |
| Audit   | 600,000 |  `40,000` LOC (currently, `manta-rs` has about 30,000 LOC) * `15 USD/LOC` (quote from [ABDK](https://www.abdk.consulting/)) |
| CI/CD      |  5,000  |  CI/CD for OpenZL |
| Misc.   | 500 | DNS, Website Hosting, etc |

Totol budget: 1,010,500 USD (will be converted to DOT using the exchange rate on application)

## OpenZL team

### Oversight Committee

Oversight commitee will manage the overall execution and the financial budget of OpenZL:
* **Shumo Chu** (Co-founder, Manta Network)
* **Luke Pearson** (Research Partner, Polychain Capital)
* **Bryan Chen** (CTO, Acala Network)

Funding and spendings will be managed in a 2/3 multisig.

### Development Team (Alphabetical)

* **Boyuan Feng**: Cryptogrpahic Engineer at Manta, PhD Computer Science from UCSB, extensive zero-knowledge proof compiler experiences (e.g. first author of [ZEN](https://eprint.iacr.org/2021/087)).
* **Brandon H. Gomes**: Cryptographic Engineer at Manta, BS Math from Rutgers, main author of [manta-rs](https://github.com/Manta-Network/manta-rs).
* **Todd Norton**: Cryptographic Engineer at Manta, PhD Physics from Caltech.
* **Tom Shen**: Cryptographic Engineer at Manta, BS Computer Science from UC Berkeley, [arkworks](https://github.com/arkworks-rs) core contributor. 
* **Rob Thijssen**: Devop Engineer at Manta, ex-Mozilla engineer.

## References

[1]. [Poseidon Permutation](https://eprint.iacr.org/2019/458.pdf)

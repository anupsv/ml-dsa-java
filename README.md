# ML-DSA Java

A pure Java implementation of **ML-DSA (Module-Lattice Digital Signature Algorithm)** as specified in [FIPS 204](https://csrc.nist.gov/pubs/fips/204/final).

ML-DSA is a post-quantum digital signature scheme selected by NIST for standardization, designed to be secure against attacks by both classical and quantum computers.

## Features

- Full implementation of ML-DSA-44, ML-DSA-65, and ML-DSA-87 parameter sets
- Constant-time operations to prevent timing side-channel attacks
- Hedged signing with randomness for fault attack resistance
- Validated against NIST ACVP test vectors
- Pure Java with no external cryptographic dependencies

## Requirements

- Java 25+
- Maven 3.8+

## Installation

```bash
mvn clean install
```

## Usage

```java
import mldsa.api.MLDSA;
import mldsa.api.MLDSAKeyPair;
import mldsa.params.MLDSA65;

// Generate a key pair
MLDSAKeyPair keyPair = MLDSA.generateKeyPair(MLDSA65.PARAMS);

// Sign a message
byte[] message = "Hello, post-quantum world!".getBytes();
byte[] signature = MLDSA.sign(keyPair.privateKey(), message);

// Verify the signature
boolean valid = MLDSA.verify(keyPair.publicKey(), message, signature);
```

## FIPS 204 Compliance

This implementation is **fully compliant with FIPS 204** (Module-Lattice-Based Digital Signature Standard).

### Algorithm Implementation

| Algorithm | FIPS 204 Reference | Status |
|-----------|-------------------|--------|
| Key Generation | Algorithm 1 (ML-DSA.KeyGen) | Compliant |
| Signing | Algorithm 2 (ML-DSA.Sign) | Compliant |
| Verification | Algorithm 3 (ML-DSA.Verify) | Compliant |

### Parameter Sets

All three standardized parameter sets are implemented with correct values:

| Parameter Set | Security Level | Public Key | Private Key | Signature |
|--------------|----------------|------------|-------------|-----------|
| ML-DSA-44 | NIST Level 2 | 1,312 bytes | 2,560 bytes | 2,420 bytes |
| ML-DSA-65 | NIST Level 3 | 1,952 bytes | 4,032 bytes | 3,309 bytes |
| ML-DSA-87 | NIST Level 5 | 2,592 bytes | 4,896 bytes | 4,627 bytes |

### Supporting Algorithms

All supporting algorithms are correctly implemented per FIPS 204:

- **ExpandA** (Algorithm 4) - Matrix expansion using SHAKE128 with rejection sampling
- **ExpandS** (Algorithm 5) - Secret vector expansion with bounded coefficients
- **ExpandMask** (Algorithm 6) - Mask vector sampling
- **SampleInBall** (Algorithm 7) - Challenge polynomial sampling
- **RejNTTPoly** (Algorithm 8) - Rejection sampling for NTT polynomials
- **RejBoundedPoly** (Algorithm 9) - Bounded coefficient rejection sampling
- **Power2Round** (Algorithm 10) - Coefficient decomposition
- **Decompose** (Algorithm 11) - High/low bits decomposition
- **HighBits/LowBits** (Algorithms 12-13) - Coefficient extraction
- **MakeHint/UseHint** (Algorithms 14-15) - Hint computation and recovery
- **BitPack/BitUnpack** - Coefficient encoding/decoding
- **pkEncode/skEncode/sigEncode** - Key and signature serialization

### Encoding Formats

All encoding formats match FIPS 204 exactly:

- **Public Key**: `rho || t1_packed` (rho: 32 bytes, t1: k x 320 bytes)
- **Private Key**: `rho || K || tr || s1 || s2 || t0`
- **Signature**: `c_tilde || z || h` (sparse hint encoding)

### Domain Separation

Domain separators are correctly applied per specification:

- Key generation: `H(xi || k || l, 128)` using SHAKE256
- Signing: `mu = H(tr || M)`, `c_tilde = H(mu || w1_encoded)`
- Hedged randomness: `rho' = H(K || rnd || mu)`

### Validation

The implementation passes all NIST ACVP (Automated Cryptographic Validation Protocol) test vectors:

- `key-gen.json` - Key generation vectors
- `sig-gen.json` - Signature generation vectors
- `sig-ver.json` - Signature verification vectors

Run validation tests:
```bash
mvn test -Dtest=ACVPVectorTests
```

## Security Features

### Constant-Time Operations

Critical operations are implemented in constant-time to prevent timing side-channel attacks:

- Polynomial norm checking using branchless arithmetic
- Array comparison with fixed iteration count
- UseHint/MakeHint with branchless selection
- Decompose wraparound handling

### Memory Protection

Sensitive cryptographic material is zeroized after use:

- Private key components (K, s1, s2, t0)
- Signing intermediates (y, z, challenge polynomial)
- Temporary NTT domain values

### Hedged Signing

The implementation supports hedged signing per FIPS 204:
- Default: Random 32-byte `rnd` value for each signature
- Deterministic mode available for testing with fixed `rnd`

## Project Structure

```
src/main/java/mldsa/
├── api/           # Public API (MLDSA, MLDSAKeyPair, MLDSAPrivateKey)
├── core/          # Core algorithms (KeyGen, Sign, Verify)
├── ct/            # Constant-time utilities
├── encode/        # Bit packing and encoding (BitPacker, ByteCodec)
├── hash/          # SHAKE128/256 implementation
├── hints/         # Decompose, Power2Round, MakeHint, UseHint
├── ntt/           # Number Theoretic Transform, Montgomery arithmetic
├── params/        # Parameter sets (MLDSA44, MLDSA65, MLDSA87)
├── poly/          # Polynomial and PolynomialVector operations
└── sampling/      # ExpandA, Sampler (SampleInBall, bounded sampling)
```

## References

- [FIPS 204: Module-Lattice-Based Digital Signature Standard](https://csrc.nist.gov/pubs/fips/204/final)
- [NIST Post-Quantum Cryptography](https://csrc.nist.gov/projects/post-quantum-cryptography)
- [ACVP Testing](https://pages.nist.gov/ACVP/)

## License

This project is provided for educational and research purposes.

## Disclaimer

This implementation has not been formally audited. For production use in security-critical applications, consider using NIST-validated cryptographic modules.

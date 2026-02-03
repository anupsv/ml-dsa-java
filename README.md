# ML-DSA Java Implementation

A pure Java implementation of **ML-DSA (Module-Lattice-Based Digital Signature Algorithm)** as specified in [FIPS 204](https://csrc.nist.gov/pubs/fips/204/final).

ML-DSA is a post-quantum digital signature scheme standardized by NIST, designed to be secure against attacks by both classical and quantum computers.

## Features

- **Full FIPS 204 Compliance**: Implements all three parameter sets (ML-DSA-44, ML-DSA-65, ML-DSA-87)
- **Zero External Dependencies**: Pure Java implementation with no runtime dependencies
- **Constant-Time Operations**: Comprehensive timing attack mitigations using branchless arithmetic
- **Security Hardened**: Fault attack mitigations, input validation, and secure memory handling
- **Modern Java**: Requires Java 21+ (uses records, sealed classes, and modern APIs)

## Quick Start

### Installation

Add to your Maven `pom.xml`:

```xml
<dependency>
    <groupId>mldsa</groupId>
    <artifactId>mldsa</artifactId>
    <version>1.0.0-SNAPSHOT</version>
</dependency>
```

### Basic Usage

```java
import mldsa.api.*;

// Generate a key pair
MLDSAKeyPair keyPair = MLDSA.generateKeyPair(MLDSAParameterSet.ML_DSA_65);

// Sign a message
byte[] message = "Hello, post-quantum world!".getBytes();
MLDSASignature signature = MLDSA.sign(keyPair.privateKey(), message);

// Verify the signature
boolean valid = MLDSA.verify(keyPair.publicKey(), message, signature);
System.out.println("Signature valid: " + valid);

// Clean up private key when done
keyPair.destroyPrivateKey();
```

### Using Try-With-Resources

```java
MLDSAKeyPair keyPair = MLDSA.generateKeyPair(MLDSAParameterSet.ML_DSA_65);
byte[] message = "Secure message".getBytes();

// Private key is automatically destroyed when the try block exits
try (MLDSAPrivateKey privateKey = keyPair.privateKey()) {
    MLDSASignature signature = MLDSA.sign(privateKey, message);
    // ... use signature
}
```

## Parameter Sets

| Parameter Set | Security Level | Public Key | Private Key | Signature |
|--------------|----------------|------------|-------------|-----------|
| ML_DSA_44    | Level 2 (SHA-256) | 1,312 bytes | 2,560 bytes | 2,420 bytes |
| ML_DSA_65    | Level 3 (AES-192) | 1,952 bytes | 4,032 bytes | 3,309 bytes |
| ML_DSA_87    | Level 5 (AES-256) | 2,592 bytes | 4,896 bytes | 4,627 bytes |

Choose your security level based on your requirements:
- **ML_DSA_44**: Good balance of security and performance for most applications
- **ML_DSA_65**: Recommended for high-security applications
- **ML_DSA_87**: Maximum security for critical infrastructure

## Security Features

### Timing Attack Mitigations

All security-sensitive operations use constant-time implementations:
- Branchless comparisons and conditional selects
- Constant-time polynomial norm checking
- Constant-time array comparisons
- No early exits based on secret data

### Fault Attack Mitigations

- **Signature Self-Verification**: Every signature is verified before returning
- **Double Verification**: Verify operations run twice with independent computations
- **Key Consistency Checks**: Private key integrity is validated before signing

### Memory Protection

- **Secure Zeroing**: Secret material is explicitly cleared with memory fences
- **Intermediate Buffer Clearing**: Temporary buffers containing secrets are zeroed
- **AutoCloseable Keys**: Private keys can be used with try-with-resources

### Input Validation

- Public key coefficient range validation
- Private key structure and coefficient validation
- Signature canonical encoding validation
- Hint encoding validation with ascending index checks

### Randomness Security

- **Entropy Health Checks**: RNG output is validated before use
- **Periodic Reseeding**: RNG is reseeded every 1,000 signatures
- **External RNG Support**: Custom SecureRandom providers can be injected

## Advanced Usage

### Custom RNG Provider

```java
// For FIPS compliance testing or HSM integration
MLDSA.setSecureRandomProvider(() -> {
    // Return your custom SecureRandom implementation
    return new MyHSMSecureRandom();
});

// Reset to default
MLDSA.setSecureRandomProvider(null);
```

### Deterministic Key Generation (Testing Only)

```java
byte[] seed = new byte[32];
// ... fill seed with your deterministic value
MLDSAKeyPair keyPair = MLDSA.generateKeyPair(MLDSAParameterSet.ML_DSA_65, seed);
```

### Raw Byte Array Operations

```java
// Verify with raw byte arrays (useful for interoperability)
boolean valid = MLDSA.verify(
    MLDSAParameterSet.ML_DSA_65,
    publicKeyBytes,
    message,
    signatureBytes
);
```

### Key Serialization

```java
// Export keys
byte[] publicKeyBytes = keyPair.publicKey().encoded();
byte[] privateKeyBytes = keyPair.privateKey().encoded();

// Import keys
MLDSAPublicKey publicKey = new MLDSAPublicKey(MLDSAParameterSet.ML_DSA_65, publicKeyBytes);
MLDSAPrivateKey privateKey = new MLDSAPrivateKey(MLDSAParameterSet.ML_DSA_65, privateKeyBytes);
```

## API Reference

### Core Classes

| Class | Description |
|-------|-------------|
| `MLDSA` | Main entry point with static methods for key generation, signing, and verification |
| `MLDSAParameterSet` | Enum of available parameter sets (ML_DSA_44, ML_DSA_65, ML_DSA_87) |
| `MLDSAKeyPair` | Container for public and private key pair |
| `MLDSAPublicKey` | Public key for signature verification |
| `MLDSAPrivateKey` | Private key for signing (implements AutoCloseable) |
| `MLDSASignature` | Digital signature container |
| `MLDSAException` | Exception for cryptographic errors |

### Key Methods

```java
// Key Generation
MLDSAKeyPair MLDSA.generateKeyPair(MLDSAParameterSet params)
MLDSAKeyPair MLDSA.generateKeyPair(MLDSAParameterSet params, byte[] seed)

// Signing
MLDSASignature MLDSA.sign(MLDSAPrivateKey privateKey, byte[] message)
MLDSASignature MLDSA.sign(MLDSAPrivateKey privateKey, byte[] message, byte[] randomness)

// Verification
boolean MLDSA.verify(MLDSAPublicKey publicKey, byte[] message, MLDSASignature signature)
boolean MLDSA.verify(MLDSAParameterSet params, byte[] publicKey, byte[] message, byte[] signature)

// RNG Configuration
void MLDSA.setSecureRandomProvider(SecureRandomProvider provider)
void MLDSA.resetSignatureCounter()
```

## Building

### Requirements

- Java 21 or later
- Maven 3.8+

### Build Commands

```bash
# Compile
mvn compile

# Run tests
mvn test

# Package JAR
mvn package

# Install to local repository
mvn install
```

## Testing

The test suite includes:
- **73 tests** covering all functionality
- **NIST Known Answer Tests (KAT)** from ACVP test vectors
- **Constant-time verification tests** (informational)
- **Integration tests** for sign/verify roundtrips
- **Edge case tests** for empty and large messages

```bash
mvn test
```

## Project Structure

```
src/main/java/mldsa/
├── api/                 # Public API classes
│   ├── MLDSA.java          # Main entry point
│   ├── MLDSAKeyPair.java   # Key pair container
│   ├── MLDSAPrivateKey.java
│   ├── MLDSAPublicKey.java
│   ├── MLDSASignature.java
│   ├── MLDSAParameterSet.java
│   └── MLDSAException.java
├── core/                # Core algorithms
│   ├── KeyGen.java         # FIPS 204 Algorithm 1
│   ├── Sign.java           # FIPS 204 Algorithm 2
│   └── Verify.java         # FIPS 204 Algorithm 3
├── ct/                  # Constant-time utilities
│   └── ConstantTime.java
├── encode/              # Serialization
│   ├── ByteCodec.java
│   └── BitPacker.java
├── hash/                # SHAKE256/Keccak
│   ├── Shake.java
│   └── Keccak.java
├── hints/               # Decomposition helpers
│   ├── Decompose.java
│   ├── MakeHint.java
│   ├── UseHint.java
│   └── Power2Round.java
├── ntt/                 # Number Theoretic Transform
│   ├── NTT.java
│   ├── Montgomery.java
│   └── NTTTables.java
├── params/              # Parameter definitions
│   ├── Parameters.java
│   ├── MLDSA44.java
│   ├── MLDSA65.java
│   └── MLDSA87.java
├── poly/                # Polynomial arithmetic
│   ├── Polynomial.java
│   ├── PolynomialVector.java
│   └── PolyOps.java
└── sampling/            # Random sampling
    ├── Sampler.java
    └── ExpandA.java
```

## Security Considerations

### Recommended Practices

1. **Always destroy private keys** when no longer needed using `destroy()` or try-with-resources
2. **Use ML_DSA_65 or ML_DSA_87** for long-term security
3. **Don't reuse randomness** - let the library generate fresh randomness for each signature
4. **Validate inputs** at your application boundary before passing to the library

### Limitations

- **Java GC**: Despite secure zeroing, JVM garbage collection may retain copies of secret data
- **JIT Compilation**: Timing behavior may vary due to JIT optimizations
- **Side Channels**: While timing attacks are mitigated, other side channels (power, EM) are not addressed

### For Maximum Security

Consider:
- Running on dedicated hardware with disabled speculative execution mitigations
- Using HSM integration via custom `SecureRandomProvider`
- Implementing additional application-level protections

## Standards Compliance

This implementation follows:
- **FIPS 204**: Module-Lattice-Based Digital Signature Standard
- **FIPS 202**: SHA-3 Standard (Keccak/SHAKE)

## License

[Add your license here]

## Contributing

[Add contribution guidelines here]

## Acknowledgments

- NIST Post-Quantum Cryptography Standardization Project
- CRYSTALS-Dilithium reference implementation

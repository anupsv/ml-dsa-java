/**
 * Encoding and decoding utilities for ML-DSA keys and signatures.
 *
 * <h2>Overview</h2>
 * <p>This package handles serialization of ML-DSA keys and signatures to/from
 * byte arrays according to the formats specified in FIPS 204.</p>
 *
 * <h2>Key Classes</h2>
 * <ul>
 *   <li>{@link mldsa.encode.ByteCodec} - Key and signature encoding/decoding</li>
 *   <li>{@link mldsa.encode.BitPacker} - Bit-level packing/unpacking utilities</li>
 * </ul>
 *
 * <h2>Encoding Formats</h2>
 *
 * <h3>Public Key: pk = rho || t1_encoded</h3>
 * <ul>
 *   <li>rho: 32 bytes (seed for matrix A)</li>
 *   <li>t1_encoded: k * 320 bytes (t1 coefficients, 10 bits each)</li>
 * </ul>
 *
 * <h3>Private Key: sk = rho || K || tr || s1 || s2 || t0</h3>
 * <ul>
 *   <li>rho: 32 bytes (seed for matrix A)</li>
 *   <li>K: 32 bytes (signing key for hedged signatures)</li>
 *   <li>tr: 64 bytes (hash of public key)</li>
 *   <li>s1: l * 32*eta bytes (secret vector, eta bits per coefficient)</li>
 *   <li>s2: k * 32*eta bytes (secret vector)</li>
 *   <li>t0: k * 416 bytes (low bits of t, 13 bits per coefficient)</li>
 * </ul>
 *
 * <h3>Signature: sig = c_tilde || z || h</h3>
 * <ul>
 *   <li>c_tilde: lambda/4 bytes (challenge hash)</li>
 *   <li>z: l * gamma1_bits * 32 bytes (response vector)</li>
 *   <li>h: omega + k bytes (sparse hint encoding)</li>
 * </ul>
 *
 * <h2>Input Validation</h2>
 * <p>The decoding functions validate:</p>
 * <ul>
 *   <li>Correct overall size for the parameter set</li>
 *   <li>Coefficient values within valid ranges</li>
 *   <li>Canonical hint encoding (ascending indices, no duplicates)</li>
 * </ul>
 *
 * @since 1.0
 */
package mldsa.encode;

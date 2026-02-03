/**
 * SHAKE256 and Keccak hash functions (FIPS 202).
 *
 * <h2>Overview</h2>
 * <p>This package provides a pure Java implementation of the Keccak sponge construction
 * and SHAKE extendable-output functions (XOFs) as specified in FIPS 202.</p>
 *
 * <h2>Key Classes</h2>
 * <ul>
 *   <li>{@link mldsa.hash.Shake} - SHAKE256 and SHAKE128 convenience methods</li>
 *   <li>{@link mldsa.hash.Keccak} - Low-level Keccak sponge implementation</li>
 * </ul>
 *
 * <h2>Usage</h2>
 * <p>For simple hashing with fixed output:</p>
 * <pre>{@code
 * byte[] hash = Shake.shake256(message, 64);  // 64-byte output
 * }</pre>
 *
 * <p>For streaming/incremental use:</p>
 * <pre>{@code
 * Shake.ShakeDigest xof = Shake.newShake256();
 * xof.update(part1);
 * xof.update(part2);
 * byte[] output = new byte[100];
 * xof.digest(output, 0, output.length);
 * }</pre>
 *
 * <h2>SHAKE vs SHA-3</h2>
 * <p>ML-DSA uses SHAKE (extendable-output functions) rather than SHA-3 (fixed-output)
 * because it needs variable-length outputs for sampling operations.</p>
 *
 * <h2>Parameters</h2>
 * <ul>
 *   <li><b>SHAKE128</b>: 128-bit security, 168-byte rate (used for matrix expansion)</li>
 *   <li><b>SHAKE256</b>: 256-bit security, 136-byte rate (used for hashing and sampling)</li>
 * </ul>
 *
 * @since 1.0
 */
package mldsa.hash;

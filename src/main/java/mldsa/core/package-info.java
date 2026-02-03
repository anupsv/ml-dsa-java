/**
 * Core ML-DSA algorithms implementing FIPS 204.
 *
 * <h2>Overview</h2>
 * <p>This package contains the core cryptographic algorithms for ML-DSA:</p>
 * <ul>
 *   <li>{@link mldsa.core.KeyGen} - Key pair generation (FIPS 204 Algorithm 1)</li>
 *   <li>{@link mldsa.core.Sign} - Signature generation (FIPS 204 Algorithm 2)</li>
 *   <li>{@link mldsa.core.Verify} - Signature verification (FIPS 204 Algorithm 3)</li>
 * </ul>
 *
 * <h2>Internal Use</h2>
 * <p>These classes are intended for internal use by the {@link mldsa.api.MLDSA} facade.
 * Direct use is possible but not recommended, as the API layer provides additional
 * security features such as fault attack mitigations and input validation.</p>
 *
 * <h2>Algorithm Overview</h2>
 * <p>ML-DSA uses the Fiat-Shamir with Aborts paradigm:</p>
 * <ol>
 *   <li><b>Key Generation</b>: Expands a seed into matrix A and secret vectors s1, s2,
 *       then computes public key t = A*s1 + s2</li>
 *   <li><b>Signing</b>: Samples random masking vector y, computes commitment w = A*y,
 *       challenges the prover, and iteratively attempts to create a valid signature
 *       that doesn't leak information about the secret key</li>
 *   <li><b>Verification</b>: Recomputes the commitment from the signature and public key,
 *       then verifies the challenge hash matches</li>
 * </ol>
 *
 * <h2>Security Properties</h2>
 * <ul>
 *   <li>Based on Module Learning With Errors (MLWE) and Module Short Integer Solution (MSIS)</li>
 *   <li>Believed to be secure against quantum attacks</li>
 *   <li>Constant-time implementation to prevent timing side-channels</li>
 * </ul>
 *
 * @see mldsa.api.MLDSA
 * @since 1.0
 */
package mldsa.core;

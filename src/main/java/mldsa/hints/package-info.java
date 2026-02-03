/**
 * Hint and decomposition operations for ML-DSA.
 *
 * <h2>Overview</h2>
 * <p>ML-DSA signatures include "hints" that help verifiers recover high-order bits
 * without transmitting them directly. This reduces signature size while maintaining
 * security.</p>
 *
 * <h2>Key Classes</h2>
 * <ul>
 *   <li>{@link mldsa.hints.Decompose} - Decompose values into high and low bits</li>
 *   <li>{@link mldsa.hints.MakeHint} - Create hints during signing</li>
 *   <li>{@link mldsa.hints.UseHint} - Apply hints during verification</li>
 *   <li>{@link mldsa.hints.Power2Round} - Power-of-2 rounding for key generation</li>
 * </ul>
 *
 * <h2>Decomposition</h2>
 * <p>The Decompose operation splits a value r into high bits r1 and low bits r0
 * such that r = r1 * 2*gamma2 + r0, where |r0| <= gamma2. This is used to create
 * commitments that hide the exact value while preserving verifiability.</p>
 *
 * <h2>Hint Mechanism</h2>
 * <p>When the signer computes w - c*s2, the result may have different high bits
 * than w due to carry propagation. The hint h encodes which positions need
 * adjustment, allowing the verifier to recover the correct high bits of w.</p>
 *
 * <h2>Power2Round</h2>
 * <p>During key generation, the public value t is split into t1 (high bits) and
 * t0 (low bits) using power-of-2 rounding. Only t1 is included in the public key;
 * t0 is stored in the private key for efficient signing.</p>
 *
 * <h2>Security Notes</h2>
 * <p>The MakeHint operation uses constant-time branchless arithmetic to prevent
 * timing leaks based on secret values.</p>
 *
 * @since 1.0
 */
package mldsa.hints;

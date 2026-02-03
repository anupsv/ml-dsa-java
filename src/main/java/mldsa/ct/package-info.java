/**
 * Constant-time utilities for cryptographic operations.
 *
 * <h2>Overview</h2>
 * <p>This package provides constant-time implementations of common operations
 * to prevent timing side-channel attacks. All functions execute in the same
 * amount of time regardless of input values.</p>
 *
 * <h2>Why Constant-Time?</h2>
 * <p>In cryptographic code, execution time that depends on secret values can
 * leak information to attackers who can measure timing. For example:</p>
 * <ul>
 *   <li>Early-exit comparisons reveal where differences occur</li>
 *   <li>Conditional branches based on secrets leak the branch taken</li>
 *   <li>Variable-time arithmetic can reveal operand values</li>
 * </ul>
 *
 * <h2>Implementation Techniques</h2>
 * <p>The {@link mldsa.ct.ConstantTime} class uses branchless arithmetic:</p>
 * <ul>
 *   <li><b>Bit manipulation</b> - Uses shifts and masks instead of conditionals</li>
 *   <li><b>Arithmetic encoding</b> - Encodes boolean results as 0 or -1 (all bits set)</li>
 *   <li><b>Select operations</b> - Uses bitwise AND/OR instead of ternary operators</li>
 *   <li><b>Full traversal</b> - Always examines all elements, never exits early</li>
 * </ul>
 *
 * <h2>Key Functions</h2>
 * <ul>
 *   <li>{@link mldsa.ct.ConstantTime#equals(int, int)} - Constant-time equality</li>
 *   <li>{@link mldsa.ct.ConstantTime#lessThan(int, int)} - Constant-time comparison</li>
 *   <li>{@link mldsa.ct.ConstantTime#select(int, int, int)} - Constant-time conditional select</li>
 *   <li>{@link mldsa.ct.ConstantTime#arraysEqual(byte[], byte[])} - Constant-time array comparison</li>
 *   <li>{@link mldsa.ct.ConstantTime#zero(byte[])} - Secure memory zeroing</li>
 * </ul>
 *
 * <h2>Limitations</h2>
 * <p>While these functions are designed for constant-time execution:</p>
 * <ul>
 *   <li>JVM JIT compilation may affect timing guarantees</li>
 *   <li>CPU microarchitecture effects (caches, branch prediction) may still apply</li>
 *   <li>For critical applications, verify with tools like ctgrind or dudect</li>
 * </ul>
 *
 * @see mldsa.ct.ConstantTime
 * @since 1.0
 */
package mldsa.ct;

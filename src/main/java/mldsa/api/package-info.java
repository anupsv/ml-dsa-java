/**
 * Public API for ML-DSA (Module-Lattice-Based Digital Signature Algorithm).
 *
 * <h2>Overview</h2>
 * <p>This package provides the public interface for ML-DSA digital signatures as specified
 * in <a href="https://csrc.nist.gov/pubs/fips/204/final">FIPS 204</a>. ML-DSA is a
 * post-quantum signature scheme designed to be secure against both classical and
 * quantum computer attacks.</p>
 *
 * <h2>Main Entry Point</h2>
 * <p>The {@link mldsa.api.MLDSA} class is the main entry point for all operations:</p>
 * <ul>
 *   <li>{@link mldsa.api.MLDSA#generateKeyPair(MLDSAParameterSet)} - Generate a new key pair</li>
 *   <li>{@link mldsa.api.MLDSA#sign(MLDSAPrivateKey, byte[])} - Sign a message</li>
 *   <li>{@link mldsa.api.MLDSA#verify(MLDSAPublicKey, byte[], MLDSASignature)} - Verify a signature</li>
 * </ul>
 *
 * <h2>Quick Start</h2>
 * <pre>{@code
 * // Generate a key pair
 * MLDSAKeyPair keyPair = MLDSA.generateKeyPair(MLDSAParameterSet.ML_DSA_65);
 *
 * // Sign a message
 * byte[] message = "Hello, World!".getBytes();
 * MLDSASignature signature = MLDSA.sign(keyPair.privateKey(), message);
 *
 * // Verify the signature
 * boolean valid = MLDSA.verify(keyPair.publicKey(), message, signature);
 *
 * // Clean up
 * keyPair.destroyPrivateKey();
 * }</pre>
 *
 * <h2>Parameter Sets</h2>
 * <p>Three security levels are available via {@link mldsa.api.MLDSAParameterSet}:</p>
 * <table border="1">
 *   <tr><th>Parameter Set</th><th>Security Level</th><th>Use Case</th></tr>
 *   <tr><td>ML_DSA_44</td><td>Level 2 (SHA-256 equivalent)</td><td>General purpose</td></tr>
 *   <tr><td>ML_DSA_65</td><td>Level 3 (AES-192 equivalent)</td><td>High security</td></tr>
 *   <tr><td>ML_DSA_87</td><td>Level 5 (AES-256 equivalent)</td><td>Maximum security</td></tr>
 * </table>
 *
 * <h2>Security Features</h2>
 * <ul>
 *   <li><b>Constant-time operations</b> - All security-sensitive code uses branchless arithmetic</li>
 *   <li><b>Fault attack mitigations</b> - Signatures are self-verified before returning</li>
 *   <li><b>Secure memory handling</b> - Private keys implement {@link AutoCloseable} for cleanup</li>
 *   <li><b>Input validation</b> - All inputs are validated for correctness and canonical encoding</li>
 *   <li><b>Entropy health checks</b> - RNG output is validated before use</li>
 * </ul>
 *
 * <h2>Thread Safety</h2>
 * <p>All methods in {@link mldsa.api.MLDSA} are thread-safe. Key and signature objects are
 * immutable after construction (though private keys can be destroyed).</p>
 *
 * <h2>Exception Handling</h2>
 * <p>{@link mldsa.api.MLDSAException} is thrown for cryptographic errors such as:</p>
 * <ul>
 *   <li>Signing failures (e.g., if rejection sampling exceeds limits)</li>
 *   <li>Entropy health check failures</li>
 *   <li>Key consistency check failures (possible fault attack)</li>
 * </ul>
 * <p>{@link IllegalArgumentException} is thrown for invalid arguments (null, wrong size, etc.)</p>
 *
 * @see mldsa.api.MLDSA
 * @see mldsa.api.MLDSAParameterSet
 * @since 1.0
 */
package mldsa.api;

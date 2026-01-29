package mldsa.hash;

/**
 * SHAKE128 and SHAKE256 extendable-output functions (XOFs).
 *
 * <p>Uses our own Keccak sponge implementation because the JDK's MessageDigest
 * for SHAKE only produces 64 bytes (fixed output), which is insufficient for ML-DSA.
 * This wrapper delegates to {@link Keccak} for proper XOF support with arbitrary
 * output lengths.</p>
 *
 * <p>SHAKE is part of the SHA-3 family (FIPS 202) and produces variable-length output.</p>
 */
public final class Shake {

    private Shake() {
        // Utility class
    }

    /**
     * Computes SHAKE128 with the given input and output length.
     *
     * @param input the input bytes
     * @param outputLength the desired output length in bytes
     * @return the SHAKE128 output of the specified length
     */
    public static byte[] shake128(byte[] input, int outputLength) {
        return Keccak.shake128(input, outputLength);
    }

    /**
     * Computes SHAKE256 with the given input and output length.
     *
     * @param input the input bytes
     * @param outputLength the desired output length in bytes
     * @return the SHAKE256 output of the specified length
     */
    public static byte[] shake256(byte[] input, int outputLength) {
        return Keccak.shake256(input, outputLength);
    }

    /**
     * Computes SHAKE128 with multiple input parts concatenated.
     *
     * @param outputLength the desired output length in bytes
     * @param inputs the input byte arrays to concatenate
     * @return the SHAKE128 output of the specified length
     */
    public static byte[] shake128(int outputLength, byte[]... inputs) {
        return Keccak.shake128(outputLength, inputs);
    }

    /**
     * Computes SHAKE256 with multiple input parts concatenated.
     *
     * @param outputLength the desired output length in bytes
     * @param inputs the input byte arrays to concatenate
     * @return the SHAKE256 output of the specified length
     */
    public static byte[] shake256(int outputLength, byte[]... inputs) {
        return Keccak.shake256(outputLength, inputs);
    }

    /**
     * Creates a SHAKE128 instance for incremental hashing.
     *
     * @return a new ShakeDigest for SHAKE128
     */
    public static ShakeDigest newShake128() {
        return new ShakeDigest(Keccak.ShakeXof.shake128());
    }

    /**
     * Creates a SHAKE256 instance for incremental hashing.
     *
     * @return a new ShakeDigest for SHAKE256
     */
    public static ShakeDigest newShake256() {
        return new ShakeDigest(Keccak.ShakeXof.shake256());
    }

    /**
     * Wrapper for incremental SHAKE hashing.
     */
    public static final class ShakeDigest {
        private final Keccak.ShakeXof xof;

        ShakeDigest(Keccak.ShakeXof xof) {
            this.xof = xof;
        }

        /**
         * Updates the digest with more input.
         *
         * @param input the input bytes
         * @return this digest for chaining
         */
        public ShakeDigest update(byte[] input) {
            xof.absorb(input);
            return this;
        }

        /**
         * Updates the digest with a portion of the input array.
         *
         * @param input the input bytes
         * @param offset starting offset
         * @param length number of bytes to use
         * @return this digest for chaining
         */
        public ShakeDigest update(byte[] input, int offset, int length) {
            byte[] slice = new byte[length];
            System.arraycopy(input, offset, slice, 0, length);
            xof.absorb(slice);
            return this;
        }

        /**
         * Updates the digest with a single byte.
         *
         * @param b the byte
         * @return this digest for chaining
         */
        public ShakeDigest update(byte b) {
            xof.absorb(b);
            return this;
        }

        /**
         * Finalizes the digest and produces output of the specified length.
         *
         * @param outputLength the desired output length in bytes
         * @return the digest output
         */
        public byte[] digest(int outputLength) {
            return xof.squeeze(outputLength);
        }

        /**
         * Resets the digest to its initial state.
         */
        public void reset() {
            xof.reset();
        }
    }
}

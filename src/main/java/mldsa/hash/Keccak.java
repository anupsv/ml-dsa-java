package mldsa.hash;

/**
 * Keccak sponge construction implementation for SHAKE128/256.
 * This implements FIPS 202 with support for arbitrary-length output (XOF).
 *
 * <p>The standard JDK MessageDigest for SHAKE only produces 64 bytes,
 * which is insufficient for ML-DSA. This class implements the full
 * Keccak sponge to support the required output lengths.</p>
 */
public final class Keccak {

    private Keccak() {
        // Utility class
    }

    // Keccak-f[1600] constants
    private static final int KECCAK_ROUNDS = 24;
    private static final int STATE_SIZE = 25; // 5x5 lanes of 64 bits each

    // Round constants for iota step
    private static final long[] RC = {
        0x0000000000000001L, 0x0000000000008082L, 0x800000000000808aL,
        0x8000000080008000L, 0x000000000000808bL, 0x0000000080000001L,
        0x8000000080008081L, 0x8000000000008009L, 0x000000000000008aL,
        0x0000000000000088L, 0x0000000080008009L, 0x000000008000000aL,
        0x000000008000808bL, 0x800000000000008bL, 0x8000000000008089L,
        0x8000000000008003L, 0x8000000000008002L, 0x8000000000000080L,
        0x000000000000800aL, 0x800000008000000aL, 0x8000000080008081L,
        0x8000000000008080L, 0x0000000080000001L, 0x8000000080008008L
    };

    // Rotation offsets for rho step
    private static final int[] RHO_OFFSETS = {
         0,  1, 62, 28, 27,
        36, 44,  6, 55, 20,
         3, 10, 43, 25, 39,
        41, 45, 15, 21,  8,
        18,  2, 61, 56, 14
    };

    // Pi step permutation indices
    private static final int[] PI_INDICES = {
         0, 10, 20,  5, 15,
        16,  1, 11, 21,  6,
         7, 17,  2, 12, 22,
        23,  8, 18,  3, 13,
        14, 24,  9, 19,  4
    };

    /**
     * SHAKE128 XOF: rate = 168 bytes (1344 bits), capacity = 32 bytes (256 bits)
     */
    public static byte[] shake128(byte[] input, int outputLength) {
        return sponge(input, outputLength, 168, (byte) 0x1F);
    }

    /**
     * SHAKE256 XOF: rate = 136 bytes (1088 bits), capacity = 64 bytes (512 bits)
     */
    public static byte[] shake256(byte[] input, int outputLength) {
        return sponge(input, outputLength, 136, (byte) 0x1F);
    }

    /**
     * SHAKE128 with multiple input arrays concatenated.
     */
    public static byte[] shake128(int outputLength, byte[]... inputs) {
        int totalLen = 0;
        for (byte[] input : inputs) {
            totalLen += input.length;
        }
        byte[] combined = new byte[totalLen];
        int offset = 0;
        for (byte[] input : inputs) {
            System.arraycopy(input, 0, combined, offset, input.length);
            offset += input.length;
        }
        return shake128(combined, outputLength);
    }

    /**
     * SHAKE256 with multiple input arrays concatenated.
     */
    public static byte[] shake256(int outputLength, byte[]... inputs) {
        int totalLen = 0;
        for (byte[] input : inputs) {
            totalLen += input.length;
        }
        byte[] combined = new byte[totalLen];
        int offset = 0;
        for (byte[] input : inputs) {
            System.arraycopy(input, 0, combined, offset, input.length);
            offset += input.length;
        }
        return shake256(combined, outputLength);
    }

    /**
     * Core sponge construction.
     *
     * @param input the input bytes
     * @param outputLength desired output length
     * @param rate the rate in bytes (168 for SHAKE128, 136 for SHAKE256)
     * @param suffix the domain separator (0x1F for SHAKE)
     * @return the XOF output
     */
    private static byte[] sponge(byte[] input, int outputLength, int rate, byte suffix) {
        // Initialize state (25 x 64-bit lanes = 200 bytes)
        long[] state = new long[STATE_SIZE];

        // Absorb phase: XOR input into state, rate bytes at a time
        int inputOffset = 0;
        while (inputOffset + rate <= input.length) {
            xorBytesIntoState(state, input, inputOffset, rate);
            keccakF(state);
            inputOffset += rate;
        }

        // Pad and absorb remaining bytes
        int remaining = input.length - inputOffset;
        byte[] padded = new byte[rate];
        if (remaining > 0) {
            System.arraycopy(input, inputOffset, padded, 0, remaining);
        }
        // SHAKE padding: suffix || 10*1
        padded[remaining] = suffix;
        padded[rate - 1] |= 0x80;
        xorBytesIntoState(state, padded, 0, rate);
        keccakF(state);

        // Squeeze phase: extract output, rate bytes at a time
        byte[] output = new byte[outputLength];
        int outputOffset = 0;
        while (outputOffset < outputLength) {
            int blockSize = Math.min(rate, outputLength - outputOffset);
            extractBytesFromState(state, output, outputOffset, blockSize);
            outputOffset += blockSize;
            if (outputOffset < outputLength) {
                keccakF(state);
            }
        }

        return output;
    }

    /**
     * XOR bytes from a byte array into the state.
     */
    private static void xorBytesIntoState(long[] state, byte[] data, int offset, int length) {
        for (int i = 0; i < length; i++) {
            int laneIndex = i / 8;
            int byteIndex = i % 8;
            state[laneIndex] ^= ((long) (data[offset + i] & 0xFF)) << (8 * byteIndex);
        }
    }

    /**
     * Extract bytes from state into output array.
     */
    private static void extractBytesFromState(long[] state, byte[] output, int offset, int length) {
        for (int i = 0; i < length; i++) {
            int laneIndex = i / 8;
            int byteIndex = i % 8;
            output[offset + i] = (byte) (state[laneIndex] >>> (8 * byteIndex));
        }
    }

    /**
     * Keccak-f[1600] permutation.
     */
    private static void keccakF(long[] state) {
        long[] b = new long[STATE_SIZE];
        long[] c = new long[5];
        long[] d = new long[5];

        for (int round = 0; round < KECCAK_ROUNDS; round++) {
            // Theta step
            for (int x = 0; x < 5; x++) {
                c[x] = state[x] ^ state[x + 5] ^ state[x + 10] ^ state[x + 15] ^ state[x + 20];
            }
            for (int x = 0; x < 5; x++) {
                d[x] = c[(x + 4) % 5] ^ Long.rotateLeft(c[(x + 1) % 5], 1);
            }
            for (int i = 0; i < STATE_SIZE; i++) {
                state[i] ^= d[i % 5];
            }

            // Rho and Pi steps combined
            for (int i = 0; i < STATE_SIZE; i++) {
                b[PI_INDICES[i]] = Long.rotateLeft(state[i], RHO_OFFSETS[i]);
            }

            // Chi step
            for (int y = 0; y < 5; y++) {
                for (int x = 0; x < 5; x++) {
                    int i = y * 5 + x;
                    state[i] = b[i] ^ ((~b[y * 5 + (x + 1) % 5]) & b[y * 5 + (x + 2) % 5]);
                }
            }

            // Iota step
            state[0] ^= RC[round];
        }
    }

    /**
     * Incremental SHAKE hasher for absorb/squeeze pattern.
     */
    public static final class ShakeXof {
        private final long[] state = new long[STATE_SIZE];
        private final int rate;
        private final byte suffix;
        private final byte[] buffer;
        private int bufferOffset = 0;
        private boolean squeezing = false;
        private int squeezeOffset = 0;

        /**
         * Creates a SHAKE128 XOF instance.
         */
        public static ShakeXof shake128() {
            return new ShakeXof(168, (byte) 0x1F);
        }

        /**
         * Creates a SHAKE256 XOF instance.
         */
        public static ShakeXof shake256() {
            return new ShakeXof(136, (byte) 0x1F);
        }

        private ShakeXof(int rate, byte suffix) {
            this.rate = rate;
            this.suffix = suffix;
            this.buffer = new byte[rate];
        }

        /**
         * Absorbs input bytes.
         */
        public ShakeXof absorb(byte[] input) {
            if (squeezing) {
                throw new IllegalStateException("Cannot absorb after squeezing");
            }

            int inputOffset = 0;
            while (inputOffset < input.length) {
                int toCopy = Math.min(rate - bufferOffset, input.length - inputOffset);
                System.arraycopy(input, inputOffset, buffer, bufferOffset, toCopy);
                bufferOffset += toCopy;
                inputOffset += toCopy;

                if (bufferOffset == rate) {
                    xorBytesIntoState(state, buffer, 0, rate);
                    keccakF(state);
                    bufferOffset = 0;
                }
            }
            return this;
        }

        /**
         * Absorbs a single byte.
         */
        public ShakeXof absorb(byte b) {
            return absorb(new byte[]{b});
        }

        /**
         * Finalizes absorbing and prepares for squeezing.
         */
        private void finalizeAbsorb() {
            if (!squeezing) {
                // Apply padding
                buffer[bufferOffset] = suffix;
                for (int i = bufferOffset + 1; i < rate; i++) {
                    buffer[i] = 0;
                }
                buffer[rate - 1] |= 0x80;
                xorBytesIntoState(state, buffer, 0, rate);
                keccakF(state);
                squeezing = true;
                squeezeOffset = 0;
            }
        }

        /**
         * Squeezes output bytes.
         */
        public byte[] squeeze(int length) {
            finalizeAbsorb();
            byte[] output = new byte[length];
            squeeze(output, 0, length);
            return output;
        }

        /**
         * Squeezes output bytes into a caller-provided buffer.
         *
         * @param output destination buffer
         * @param offset starting offset in destination
         * @param length number of bytes to write
         */
        public void squeeze(byte[] output, int offset, int length) {
            finalizeAbsorb();
            int outputOffset = 0;

            while (outputOffset < length) {
                if (squeezeOffset == rate) {
                    keccakF(state);
                    squeezeOffset = 0;
                }
                int toCopy = Math.min(rate - squeezeOffset, length - outputOffset);
                extractBytesFromState(state, output, offset + outputOffset, toCopy);
                // Adjust for squeeze offset within block
                for (int i = 0; i < toCopy; i++) {
                    int laneIndex = (squeezeOffset + i) / 8;
                    int byteIndex = (squeezeOffset + i) % 8;
                    output[offset + outputOffset + i] = (byte) (state[laneIndex] >>> (8 * byteIndex));
                }
                squeezeOffset += toCopy;
                outputOffset += toCopy;
            }
        }

        /**
         * Resets the XOF to initial state.
         */
        public void reset() {
            for (int i = 0; i < STATE_SIZE; i++) {
                state[i] = 0;
            }
            bufferOffset = 0;
            squeezing = false;
            squeezeOffset = 0;
        }
    }
}

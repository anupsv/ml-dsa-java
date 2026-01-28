package io.salvador.mldsa.encode;

import io.salvador.mldsa.params.Parameters;
import io.salvador.mldsa.poly.Polynomial;
import io.salvador.mldsa.poly.PolynomialVector;

/**
 * Encoding and decoding utilities for ML-DSA keys and signatures.
 * Follows the encoding format specified in FIPS 204.
 */
public final class ByteCodec {

    private ByteCodec() {
        // Utility class
    }

    // ==================== Public Key Encoding ====================

    /**
     * Encodes a public key: pk = rho || t1_packed
     *
     * @param rho the 32-byte seed
     * @param t1 the t1 polynomial vector
     * @param params the parameter set
     * @return the encoded public key
     */
    public static byte[] encodePublicKey(byte[] rho, PolynomialVector t1, Parameters params) {
        int t1Bytes = params.k() * (Parameters.N * 10 / 8); // 10 bits per t1 coefficient
        byte[] result = new byte[32 + t1Bytes];

        // Copy rho
        System.arraycopy(rho, 0, result, 0, 32);

        // Pack t1
        byte[] t1Packed = BitPacker.packVector(t1, 10);
        System.arraycopy(t1Packed, 0, result, 32, t1Packed.length);

        return result;
    }

    /**
     * Decodes a public key.
     *
     * @param data the encoded public key bytes
     * @param params the parameter set
     * @return an array containing [rho, t1]
     */
    public static Object[] decodePublicKey(byte[] data, Parameters params) {
        byte[] rho = new byte[32];
        System.arraycopy(data, 0, rho, 0, 32);

        int t1Bytes = params.k() * (Parameters.N * 10 / 8);
        byte[] t1Data = new byte[t1Bytes];
        System.arraycopy(data, 32, t1Data, 0, t1Bytes);

        PolynomialVector t1 = BitPacker.unpackVector(t1Data, params.k(), 10);

        return new Object[] { rho, t1 };
    }

    // ==================== Private Key Encoding ====================

    /**
     * Encodes a private key: sk = rho || K || tr || s1 || s2 || t0
     *
     * @param rho the 32-byte seed for A
     * @param K the 32-byte signing key
     * @param tr the 64-byte hash of public key
     * @param s1 the secret vector s1
     * @param s2 the secret vector s2
     * @param t0 the low bits of t
     * @param params the parameter set
     * @return the encoded private key
     */
    public static byte[] encodePrivateKey(byte[] rho, byte[] K, byte[] tr,
                                          PolynomialVector s1, PolynomialVector s2,
                                          PolynomialVector t0, Parameters params) {
        int eta = params.eta();
        int etaBits = params.etaBits();
        int k = params.k();
        int l = params.l();

        int s1Bytes = l * (Parameters.N * etaBits / 8);
        int s2Bytes = k * (Parameters.N * etaBits / 8);
        int t0Bytes = k * (Parameters.N * 13 / 8); // 13 bits per t0 coefficient

        byte[] result = new byte[32 + 32 + 64 + s1Bytes + s2Bytes + t0Bytes];
        int offset = 0;

        // rho (32 bytes)
        System.arraycopy(rho, 0, result, offset, 32);
        offset += 32;

        // K (32 bytes)
        System.arraycopy(K, 0, result, offset, 32);
        offset += 32;

        // tr (64 bytes)
        System.arraycopy(tr, 0, result, offset, 64);
        offset += 64;

        // s1 - packed with etaBits per coefficient
        byte[] s1Packed = packEtaVector(s1, eta, etaBits);
        System.arraycopy(s1Packed, 0, result, offset, s1Packed.length);
        offset += s1Packed.length;

        // s2 - packed with etaBits per coefficient
        byte[] s2Packed = packEtaVector(s2, eta, etaBits);
        System.arraycopy(s2Packed, 0, result, offset, s2Packed.length);
        offset += s2Packed.length;

        // t0 - packed with 13 bits per coefficient
        byte[] t0Packed = packT0Vector(t0);
        System.arraycopy(t0Packed, 0, result, offset, t0Packed.length);

        return result;
    }

    /**
     * Decodes a private key.
     *
     * @param data the encoded private key bytes
     * @param params the parameter set
     * @return an array containing [rho, K, tr, s1, s2, t0]
     */
    public static Object[] decodePrivateKey(byte[] data, Parameters params) {
        int eta = params.eta();
        int etaBits = params.etaBits();
        int k = params.k();
        int l = params.l();

        int offset = 0;

        // rho (32 bytes)
        byte[] rho = new byte[32];
        System.arraycopy(data, offset, rho, 0, 32);
        offset += 32;

        // K (32 bytes)
        byte[] K = new byte[32];
        System.arraycopy(data, offset, K, 0, 32);
        offset += 32;

        // tr (64 bytes)
        byte[] tr = new byte[64];
        System.arraycopy(data, offset, tr, 0, 64);
        offset += 64;

        // s1
        int s1Bytes = l * (Parameters.N * etaBits / 8);
        byte[] s1Data = new byte[s1Bytes];
        System.arraycopy(data, offset, s1Data, 0, s1Bytes);
        PolynomialVector s1 = unpackEtaVector(s1Data, l, eta, etaBits);
        offset += s1Bytes;

        // s2
        int s2Bytes = k * (Parameters.N * etaBits / 8);
        byte[] s2Data = new byte[s2Bytes];
        System.arraycopy(data, offset, s2Data, 0, s2Bytes);
        PolynomialVector s2 = unpackEtaVector(s2Data, k, eta, etaBits);
        offset += s2Bytes;

        // t0
        int t0Bytes = k * (Parameters.N * 13 / 8);
        byte[] t0Data = new byte[t0Bytes];
        System.arraycopy(data, offset, t0Data, 0, t0Bytes);
        PolynomialVector t0 = unpackT0Vector(t0Data, k);

        return new Object[] { rho, K, tr, s1, s2, t0 };
    }

    // ==================== Signature Encoding ====================

    /**
     * Encodes a signature: sig = c_tilde || z || h
     *
     * @param cTilde the challenge hash (lambda/4 bytes)
     * @param z the response vector
     * @param h the hint polynomial vector
     * @param params the parameter set
     * @return the encoded signature
     */
    public static byte[] encodeSignature(byte[] cTilde, PolynomialVector z,
                                         PolynomialVector h, Parameters params) {
        int l = params.l();
        int k = params.k();
        int omega = params.omega();
        int gamma1Bits = params.gamma1Bits();
        int cTildeBytes = params.cTildeBytes();

        int zBytes = l * (Parameters.N * gamma1Bits / 8);
        int hBytes = omega + k; // Packed hint format

        byte[] result = new byte[cTildeBytes + zBytes + hBytes];
        int offset = 0;

        // c_tilde (lambda/4 bytes)
        System.arraycopy(cTilde, 0, result, offset, cTildeBytes);
        offset += cTildeBytes;

        // z
        byte[] zPacked = BitPacker.packZ(z, params);
        System.arraycopy(zPacked, 0, result, offset, zPacked.length);
        offset += zPacked.length;

        // h (hints) - special encoding
        byte[] hPacked = packHints(h, omega, k);
        System.arraycopy(hPacked, 0, result, offset, hPacked.length);

        return result;
    }

    /**
     * Decodes a signature.
     *
     * @param data the encoded signature bytes
     * @param params the parameter set
     * @return an array containing [cTilde, z, h] or null if invalid
     */
    public static Object[] decodeSignature(byte[] data, Parameters params) {
        int l = params.l();
        int k = params.k();
        int omega = params.omega();
        int gamma1Bits = params.gamma1Bits();
        int cTildeBytes = params.cTildeBytes();

        int offset = 0;

        // c_tilde (lambda/4 bytes)
        byte[] cTilde = new byte[cTildeBytes];
        System.arraycopy(data, offset, cTilde, 0, cTildeBytes);
        offset += cTildeBytes;

        // z
        int zBytes = l * (Parameters.N * gamma1Bits / 8);
        byte[] zData = new byte[zBytes];
        System.arraycopy(data, offset, zData, 0, zBytes);
        PolynomialVector z = BitPacker.unpackZ(zData, params);
        offset += zBytes;

        // h (hints)
        int hBytes = omega + k;
        byte[] hData = new byte[hBytes];
        System.arraycopy(data, offset, hData, 0, hBytes);
        PolynomialVector h = unpackHints(hData, omega, k);

        if (h == null) {
            return null; // Invalid hint encoding
        }

        return new Object[] { cTilde, z, h };
    }

    // ==================== Helper Methods ====================

    /**
     * Packs a vector with eta-bounded coefficients.
     * Coefficients are in [-eta, eta], stored as [0, 2*eta].
     */
    private static byte[] packEtaVector(PolynomialVector vec, int eta, int bits) {
        int polyBytes = (Parameters.N * bits + 7) / 8;
        byte[] result = new byte[vec.dimension() * polyBytes];

        int offset = 0;
        for (int i = 0; i < vec.dimension(); i++) {
            byte[] packed = packEtaPoly(vec.get(i), eta, bits);
            System.arraycopy(packed, 0, result, offset, packed.length);
            offset += polyBytes;
        }

        return result;
    }

    private static byte[] packEtaPoly(Polynomial poly, int eta, int bits) {
        int[] coeffs = poly.coefficients();
        int totalBits = Parameters.N * bits;
        int totalBytes = (totalBits + 7) / 8;
        byte[] result = new byte[totalBytes];

        int bitIndex = 0;
        for (int coeff : coeffs) {
            // Map from [0, q) with possible negative (stored as q-|val|) to [0, 2*eta]
            int centered = coeff > Parameters.Q / 2 ? coeff - Parameters.Q : coeff;
            int shifted = eta - centered; // Map [-eta, eta] to [0, 2*eta]

            for (int b = 0; b < bits; b++) {
                int bit = (shifted >> b) & 1;
                int byteIndex = bitIndex / 8;
                int bitOffset = bitIndex % 8;
                result[byteIndex] |= (byte) (bit << bitOffset);
                bitIndex++;
            }
        }

        return result;
    }

    private static PolynomialVector unpackEtaVector(byte[] data, int dimension, int eta, int bits) {
        int polyBytes = (Parameters.N * bits + 7) / 8;
        Polynomial[] polys = new Polynomial[dimension];

        for (int i = 0; i < dimension; i++) {
            byte[] slice = new byte[polyBytes];
            System.arraycopy(data, i * polyBytes, slice, 0, polyBytes);
            polys[i] = unpackEtaPoly(slice, eta, bits);
        }

        return new PolynomialVector(polys);
    }

    private static Polynomial unpackEtaPoly(byte[] data, int eta, int bits) {
        int[] coeffs = new int[Parameters.N];

        int bitIndex = 0;
        for (int i = 0; i < Parameters.N; i++) {
            int value = 0;
            for (int b = 0; b < bits; b++) {
                int byteIndex = bitIndex / 8;
                int bitOffset = bitIndex % 8;
                int bit = (data[byteIndex] >> bitOffset) & 1;
                value |= bit << b;
                bitIndex++;
            }
            // Map [0, 2*eta] back to [-eta, eta], then to [0, q)
            int centered = eta - value;
            coeffs[i] = centered < 0 ? centered + Parameters.Q : centered;
        }

        return new Polynomial(coeffs);
    }

    /**
     * Packs t0 vector (13 bits per coefficient).
     */
    private static byte[] packT0Vector(PolynomialVector vec) {
        int polyBytes = (Parameters.N * 13 + 7) / 8;
        byte[] result = new byte[vec.dimension() * polyBytes];

        int offset = 0;
        for (int i = 0; i < vec.dimension(); i++) {
            byte[] packed = packT0Poly(vec.get(i));
            System.arraycopy(packed, 0, result, offset, packed.length);
            offset += polyBytes;
        }

        return result;
    }

    private static byte[] packT0Poly(Polynomial poly) {
        // t0 is in range [-(2^{d-1}-1), 2^{d-1}] where d=13
        // So range is [-(2^12-1), 2^12] = [-4095, 4096]
        // Store as 2^{d-1} - t0 which is in [0, 2^d-1]
        int halfD = 1 << 12; // 4096

        int[] coeffs = poly.coefficients();
        int totalBits = Parameters.N * 13;
        int totalBytes = (totalBits + 7) / 8;
        byte[] result = new byte[totalBytes];

        int bitIndex = 0;
        for (int coeff : coeffs) {
            // Convert from [0, q) to centered
            int centered = coeff > Parameters.Q / 2 ? coeff - Parameters.Q : coeff;
            // Map to [0, 2^13-1]
            int shifted = halfD - centered;

            for (int b = 0; b < 13; b++) {
                int bit = (shifted >> b) & 1;
                int byteIndex = bitIndex / 8;
                int bitOffset = bitIndex % 8;
                result[byteIndex] |= (byte) (bit << bitOffset);
                bitIndex++;
            }
        }

        return result;
    }

    private static PolynomialVector unpackT0Vector(byte[] data, int dimension) {
        int polyBytes = (Parameters.N * 13 + 7) / 8;
        Polynomial[] polys = new Polynomial[dimension];

        for (int i = 0; i < dimension; i++) {
            byte[] slice = new byte[polyBytes];
            System.arraycopy(data, i * polyBytes, slice, 0, polyBytes);
            polys[i] = unpackT0Poly(slice);
        }

        return new PolynomialVector(polys);
    }

    private static Polynomial unpackT0Poly(byte[] data) {
        int halfD = 1 << 12;
        int[] coeffs = new int[Parameters.N];

        int bitIndex = 0;
        for (int i = 0; i < Parameters.N; i++) {
            int value = 0;
            for (int b = 0; b < 13; b++) {
                int byteIndex = bitIndex / 8;
                int bitOffset = bitIndex % 8;
                int bit = (data[byteIndex] >> bitOffset) & 1;
                value |= bit << b;
                bitIndex++;
            }
            // Map back from [0, 2^13-1] to [-(2^12-1), 2^12]
            int centered = halfD - value;
            coeffs[i] = centered < 0 ? centered + Parameters.Q : centered;
        }

        return new Polynomial(coeffs);
    }

    /**
     * Packs hints vector using the sparse encoding from FIPS 204.
     * Format: For each polynomial, list the indices of 1s, followed by the count.
     */
    private static byte[] packHints(PolynomialVector h, int omega, int k) {
        byte[] result = new byte[omega + k];

        int totalOnes = 0;
        int offset = 0;

        for (int i = 0; i < k; i++) {
            int[] coeffs = h.get(i).coefficients();
            for (int j = 0; j < Parameters.N; j++) {
                if (coeffs[j] != 0) {
                    if (totalOnes < omega) {
                        result[totalOnes] = (byte) j;
                    }
                    totalOnes++;
                }
            }
            result[omega + i] = (byte) totalOnes;
        }

        return result;
    }

    /**
     * Unpacks hints from the sparse encoding.
     * Returns null if the encoding is invalid.
     */
    private static PolynomialVector unpackHints(byte[] data, int omega, int k) {
        Polynomial[] polys = new Polynomial[k];
        for (int i = 0; i < k; i++) {
            polys[i] = new Polynomial();
        }

        int prevCount = 0;
        for (int i = 0; i < k; i++) {
            int count = data[omega + i] & 0xFF;
            if (count < prevCount || count > omega) {
                return null; // Invalid encoding
            }

            int[] coeffs = polys[i].coefficients();
            for (int j = prevCount; j < count; j++) {
                int idx = data[j] & 0xFF;
                if (idx >= Parameters.N) {
                    return null; // Invalid index
                }
                if (coeffs[idx] != 0) {
                    return null; // Duplicate index
                }
                coeffs[idx] = 1;
            }

            prevCount = count;
        }

        return new PolynomialVector(polys);
    }
}

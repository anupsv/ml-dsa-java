package mldsa.encode;

import mldsa.params.Parameters;
import mldsa.poly.Polynomial;
import mldsa.poly.PolynomialVector;

/**
 * Bit packing utilities for encoding polynomials to bytes and vice versa.
 * Supports variable bit widths for different coefficient ranges.
 */
public final class BitPacker {

    private BitPacker() {
        // Utility class
    }

    /**
     * Packs a polynomial's coefficients into bytes using the specified bit width.
     *
     * @param poly the polynomial to pack
     * @param bits the number of bits per coefficient
     * @return the packed byte array
     */
    public static byte[] pack(Polynomial poly, int bits) {
        int[] coeffs = poly.coefficients();
        int totalBits = Parameters.N * bits;
        int totalBytes = (totalBits + 7) / 8;
        byte[] result = new byte[totalBytes];

        int bitIndex = 0;
        for (int coeff : coeffs) {
            // Pack 'bits' bits from coeff
            for (int b = 0; b < bits; b++) {
                int bit = (coeff >> b) & 1;
                int byteIndex = bitIndex / 8;
                int bitOffset = bitIndex % 8;
                result[byteIndex] |= (byte) (bit << bitOffset);
                bitIndex++;
            }
        }

        return result;
    }

    /**
     * Unpacks bytes into a polynomial using the specified bit width.
     *
     * @param data the packed bytes
     * @param bits the number of bits per coefficient
     * @return the unpacked polynomial
     */
    public static Polynomial unpack(byte[] data, int bits) {
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
            coeffs[i] = value;
        }

        return new Polynomial(coeffs);
    }

    /**
     * Packs a polynomial vector into bytes.
     *
     * @param vec the vector to pack
     * @param bits the number of bits per coefficient
     * @return the packed byte array
     */
    public static byte[] packVector(PolynomialVector vec, int bits) {
        int polyBytes = (Parameters.N * bits + 7) / 8;
        byte[] result = new byte[vec.dimension() * polyBytes];

        int offset = 0;
        for (int i = 0; i < vec.dimension(); i++) {
            byte[] packed = pack(vec.get(i), bits);
            System.arraycopy(packed, 0, result, offset, packed.length);
            offset += polyBytes;
        }

        return result;
    }

    /**
     * Unpacks bytes into a polynomial vector.
     *
     * @param data the packed bytes
     * @param dimension the vector dimension
     * @param bits the number of bits per coefficient
     * @return the unpacked polynomial vector
     */
    public static PolynomialVector unpackVector(byte[] data, int dimension, int bits) {
        int polyBytes = (Parameters.N * bits + 7) / 8;
        Polynomial[] polys = new Polynomial[dimension];

        for (int i = 0; i < dimension; i++) {
            byte[] slice = new byte[polyBytes];
            System.arraycopy(data, i * polyBytes, slice, 0, polyBytes);
            polys[i] = unpack(slice, bits);
        }

        return new PolynomialVector(polys);
    }

    /**
     * Packs coefficients that are in a centered range [-bound, bound].
     * First maps to [0, 2*bound] by adding bound.
     *
     * @param poly the polynomial with centered coefficients
     * @param bound the coefficient bound
     * @param bits the number of bits per coefficient
     * @return the packed bytes
     */
    public static byte[] packCentered(Polynomial poly, int bound, int bits) {
        int[] coeffs = poly.coefficients();
        int totalBits = Parameters.N * bits;
        int totalBytes = (totalBits + 7) / 8;
        byte[] result = new byte[totalBytes];

        int bitIndex = 0;
        for (int coeff : coeffs) {
            // Convert from [0, q) to centered, then shift to [0, 2*bound]
            int centered = coeff > Parameters.Q / 2 ? coeff - Parameters.Q : coeff;
            int shifted = bound - centered;

            // Pack 'bits' bits
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

    /**
     * Unpacks bytes into a polynomial with centered coefficients.
     * Assumes values were packed as [0, 2*bound], maps back to [-bound, bound].
     *
     * @param data the packed bytes
     * @param bound the coefficient bound
     * @param bits the number of bits per coefficient
     * @return the unpacked polynomial with coefficients in [0, q)
     */
    public static Polynomial unpackCentered(byte[] data, int bound, int bits) {
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
            // Map from [0, 2*bound] back to [-bound, bound]
            int centered = bound - value;
            // Convert to [0, q)
            coeffs[i] = centered < 0 ? centered + Parameters.Q : centered;
        }

        return new Polynomial(coeffs);
    }

    /**
     * Packs w1 coefficients for the signature.
     * w1 coefficients are in a specific range based on gamma2.
     *
     * @param poly the w1 polynomial
     * @param params the parameter set
     * @return the packed bytes
     */
    public static byte[] packW1(Polynomial poly, Parameters params) {
        int gamma2 = params.gamma2();
        int bits;

        // w1 range depends on gamma2
        if (gamma2 == (Parameters.Q - 1) / 88) {
            // ML-DSA-44: w1 in [0, 43]
            bits = 6;
        } else {
            // ML-DSA-65/87: w1 in [0, 15]
            bits = 4;
        }

        return pack(poly, bits);
    }

    /**
     * Packs z vector (signature component) with gamma1-bounded coefficients.
     *
     * @param vec the z vector
     * @param params the parameter set
     * @return the packed bytes
     */
    public static byte[] packZ(PolynomialVector vec, Parameters params) {
        int gamma1 = params.gamma1();
        int bits = params.gamma1Bits();

        int polyBytes = (Parameters.N * bits + 7) / 8;
        byte[] result = new byte[vec.dimension() * polyBytes];

        int offset = 0;
        for (int i = 0; i < vec.dimension(); i++) {
            byte[] packed = packCentered(vec.get(i), gamma1, bits);
            System.arraycopy(packed, 0, result, offset, packed.length);
            offset += polyBytes;
        }

        return result;
    }

    /**
     * Unpacks z vector from signature bytes.
     *
     * @param data the packed bytes
     * @param params the parameter set
     * @return the unpacked z vector
     */
    public static PolynomialVector unpackZ(byte[] data, Parameters params) {
        int gamma1 = params.gamma1();
        int bits = params.gamma1Bits();
        int l = params.l();

        int polyBytes = (Parameters.N * bits + 7) / 8;
        Polynomial[] polys = new Polynomial[l];

        for (int i = 0; i < l; i++) {
            byte[] slice = new byte[polyBytes];
            System.arraycopy(data, i * polyBytes, slice, 0, polyBytes);
            polys[i] = unpackCentered(slice, gamma1, bits);
        }

        return new PolynomialVector(polys);
    }
}

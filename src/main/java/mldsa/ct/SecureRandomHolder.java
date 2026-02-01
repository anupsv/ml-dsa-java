package mldsa.ct;

import java.security.SecureRandom;

/**
 * Thread-safe holder for a shared SecureRandom instance.
 *
 * <p>Creating new SecureRandom instances is expensive and can deplete
 * entropy pools. This class provides a shared instance that is properly
 * initialized and thread-safe.</p>
 *
 * <p>SecureRandom is thread-safe by contract (per Java documentation),
 * so a single shared instance can be used across threads without
 * synchronization.</p>
 */
public final class SecureRandomHolder {

    private SecureRandomHolder() {
        // Utility class
    }

    /**
     * Shared SecureRandom instance.
     * Initialized lazily on first access using the holder pattern.
     */
    private static final class Holder {
        static final SecureRandom INSTANCE = new SecureRandom();
    }

    /**
     * Returns the shared SecureRandom instance.
     *
     * @return the shared SecureRandom
     */
    public static SecureRandom get() {
        return Holder.INSTANCE;
    }

    /**
     * Fills the given array with random bytes using the shared instance.
     *
     * @param bytes the array to fill
     */
    public static void nextBytes(byte[] bytes) {
        Holder.INSTANCE.nextBytes(bytes);
    }
}

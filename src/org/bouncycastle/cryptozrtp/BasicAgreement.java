package org.bouncycastle.cryptozrtp;

import gnu.java.bigintcrypto.BigIntegerCrypto;

/**
 * The basic interface that basic Diffie-Hellman implementations
 * conforms to.
 */
public interface BasicAgreement {
    /**
     * initialise the agreement engine.
     */
    void init(CipherParameters param);

    /**
     * given a public key from a given party calculate the next
     * message in the agreement sequence.
     */
    BigIntegerCrypto calculateAgreement(CipherParameters pubKey);

    /**
     * Clear agreement data including private key data.
     * <p>
     * Clears all known agreement data and resets the agreement. To use the
     * agreement againt the application must initialize it again.
     */

    void clear();
}
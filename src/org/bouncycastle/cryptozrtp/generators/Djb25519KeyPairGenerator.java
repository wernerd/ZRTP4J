package org.bouncycastle.cryptozrtp.generators;

import djb.Curve25519;
import gnu.java.bigintcrypto.BigIntegerCrypto;
import org.bouncycastle.crypto.prng.RandomGenerator;
import org.bouncycastle.cryptozrtp.AsymmetricCipherKeyPair;
import org.bouncycastle.cryptozrtp.AsymmetricCipherKeyPairGenerator;
import org.bouncycastle.cryptozrtp.KeyGenerationParameters;
import org.bouncycastle.cryptozrtp.params.*;
import org.bouncycastle.mathzrtp.ec.ECConstants;
import org.bouncycastle.mathzrtp.ec.ECPoint;

public class Djb25519KeyPairGenerator implements AsymmetricCipherKeyPairGenerator, ECConstants
{
    RandomGenerator     random;

    public void init(KeyGenerationParameters param) {
        Djb25519KeyGenerationParameters ecP = (Djb25519KeyGenerationParameters)param;

        this.random = ecP.getRandom();
    }

    /**
     * Given the domain parameters this routine generates an EC key
     * pair in accordance with X9.62 section 5.2.1 pages 26, 27.
     */
    public AsymmetricCipherKeyPair generateKeyPair()
    {
        int        nBitLength = Curve25519.KEY_SIZE * 8;
        BigIntegerCrypto d;

        // Generate 32 bytes random data
        byte[] k = new byte[Curve25519.KEY_SIZE];
        random.nextBytes(k);

        byte[] P = new byte[Curve25519.KEY_SIZE];
        Curve25519.keygen(P, null, k);
        return new AsymmetricCipherKeyPair(
            new Djb25519PublicKeyParameters(P),
            new Djb25519PrivateKeyParameters(k));
    }
}

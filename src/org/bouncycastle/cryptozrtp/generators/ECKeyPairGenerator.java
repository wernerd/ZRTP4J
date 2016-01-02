package org.bouncycastle.cryptozrtp.generators;

import gnu.java.bigintcrypto.BigIntegerCrypto;

import org.bouncycastle.crypto.prng.RandomGenerator;
import org.bouncycastle.cryptozrtp.AsymmetricCipherKeyPair;
import org.bouncycastle.cryptozrtp.AsymmetricCipherKeyPairGenerator;
import org.bouncycastle.cryptozrtp.KeyGenerationParameters;
import org.bouncycastle.cryptozrtp.params.ECDomainParameters;
import org.bouncycastle.cryptozrtp.params.ECKeyGenerationParameters;
import org.bouncycastle.cryptozrtp.params.ECPrivateKeyParameters;
import org.bouncycastle.cryptozrtp.params.ECPublicKeyParameters;
import org.bouncycastle.mathzrtp.ec.ECConstants;
import org.bouncycastle.mathzrtp.ec.ECPoint;

public class ECKeyPairGenerator
    implements AsymmetricCipherKeyPairGenerator, ECConstants
{
    ECDomainParameters  params;
    RandomGenerator     random;

    public void init(KeyGenerationParameters param) {
        ECKeyGenerationParameters  ecP = (ECKeyGenerationParameters)param;

        this.random = ecP.getRandom();
        this.params = ecP.getDomainParameters();
    }

    /**
     * Given the domain parameters this routine generates an EC key
     * pair in accordance with X9.62 section 5.2.1 pages 26, 27.
     */
    public AsymmetricCipherKeyPair generateKeyPair()
    {
        BigIntegerCrypto n = params.getN();
        int        nBitLength = n.bitLength();
        BigIntegerCrypto d;

        do
        {
            d = new BigIntegerCrypto(nBitLength, random);
        }
        while (d.equals(ZERO)  || (d.compareTo(n) >= 0));

        ECPoint Q = params.getG().multiply(d);

        return new AsymmetricCipherKeyPair(
            new ECPublicKeyParameters(Q, params),
            new ECPrivateKeyParameters(d, params));
    }
}

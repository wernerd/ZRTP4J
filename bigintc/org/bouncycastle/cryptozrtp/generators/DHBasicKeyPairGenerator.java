package org.bouncycastle.cryptozrtp.generators;

import org.bouncycastle.cryptozrtp.AsymmetricCipherKeyPair;
import org.bouncycastle.cryptozrtp.AsymmetricCipherKeyPairGenerator;
import org.bouncycastle.cryptozrtp.KeyGenerationParameters;
import org.bouncycastle.cryptozrtp.params.DHKeyGenerationParameters;
import org.bouncycastle.cryptozrtp.params.DHParameters;
import org.bouncycastle.cryptozrtp.params.DHPrivateKeyParameters;
import org.bouncycastle.cryptozrtp.params.DHPublicKeyParameters;

import gnu.java.bigintcrypto.BigIntegerCrypto;

/**
 * a basic Diffie-Helman key pair generator.
 *
 * This generates keys consistent for use with the basic algorithm for
 * Diffie-Helman.
 */
public class DHBasicKeyPairGenerator
    implements AsymmetricCipherKeyPairGenerator
{
    private DHKeyGeneratorHelper helper = DHKeyGeneratorHelper.INSTANCE;
    private DHKeyGenerationParameters param;

    public void init(
        KeyGenerationParameters param)
    {
        this.param = (DHKeyGenerationParameters)param;
    }

    public AsymmetricCipherKeyPair generateKeyPair()
    {
        BigIntegerCrypto      p, x, y;
        DHParameters    dhParams = param.getParameters();

        p = dhParams.getP();
        x = helper.calculatePrivate(p, param.getRandom(), dhParams.getL()); 
        y = helper.calculatePublic(p, dhParams.getG(), x);

        return new AsymmetricCipherKeyPair(
                new DHPublicKeyParameters(y, dhParams),
                new DHPrivateKeyParameters(x, dhParams));
    }
}

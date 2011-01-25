package org.bouncycastle.cryptozrtp.agreement;

import gnu.java.bigintcrypto.BigIntegerCrypto;

import org.bouncycastle.cryptozrtp.BasicAgreement;
import org.bouncycastle.cryptozrtp.CipherParameters;
import org.bouncycastle.cryptozrtp.params.DHParameters;
import org.bouncycastle.cryptozrtp.params.DHPublicKeyParameters;
import org.bouncycastle.cryptozrtp.params.DHPrivateKeyParameters;
import org.bouncycastle.cryptozrtp.params.AsymmetricKeyParameter;
import org.bouncycastle.cryptozrtp.params.ParametersWithRandom;

/**
 * a Diffie-Hellman key agreement class.
 * <p>
 * note: This is only the basic algorithm, it doesn't take advantage of
 * long term public keys if they are available. See the DHAgreement class
 * for a "better" implementation.
 */
public class DHBasicAgreement
    implements BasicAgreement
{
    private DHPrivateKeyParameters  key;
    private DHParameters            dhParams;

    public void init(
        CipherParameters    param)
    {
        AsymmetricKeyParameter  kParam;

        if (param instanceof ParametersWithRandom)
        {
            ParametersWithRandom rParam = (ParametersWithRandom)param;
            kParam = (AsymmetricKeyParameter)rParam.getParameters();
        }
        else
        {
            kParam = (AsymmetricKeyParameter)param;
        }

        if (!(kParam instanceof DHPrivateKeyParameters))
        {
            throw new IllegalArgumentException("DHEngine expects DHPrivateKeyParameters");
        }

        this.key = (DHPrivateKeyParameters)kParam;
        this.dhParams = key.getParameters();
    }

    /**
     * given a short term public key from a given party calculate the next
     * message in the agreement sequence. 
     */
    public BigIntegerCrypto calculateAgreement(
        CipherParameters   pubKey)
    {
        DHPublicKeyParameters   pub = (DHPublicKeyParameters)pubKey;

        if (!pub.getParameters().equals(dhParams))
        {
            throw new IllegalArgumentException("Diffie-Hellman public key has wrong parameters.");
        }

        return pub.getY().modPow(key.getX(), dhParams.getP());
    }
    
    /**
     * Clear agreement data including private key data.
     * 
     * Clears all known agreement data and resets the agreement. To use the
     * agreement againt the application must initialize it again.
     */
    
    public void clear() {
        key.getX().zeroize();   // clear private key data
        key = null;
        dhParams = null;
    }
}

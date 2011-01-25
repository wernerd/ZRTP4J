package org.bouncycastle.cryptozrtp.agreement;

import gnu.java.bigintcrypto.BigIntegerCrypto;

import org.bouncycastle.mathzrtp.ec.ECPoint;

import org.bouncycastle.cryptozrtp.BasicAgreement;
import org.bouncycastle.cryptozrtp.CipherParameters;
import org.bouncycastle.cryptozrtp.params.ECPublicKeyParameters;
import org.bouncycastle.cryptozrtp.params.ECPrivateKeyParameters;


/**
 * P1363 7.2.1 ECSVDP-DH
 *
 * ECSVDP-DH is Elliptic Curve Secret Value Derivation Primitive,
 * Diffie-Hellman version. It is based on the work of [DH76], [Mil86],
 * and [Kob87]. This primitive derives a shared secret value from one
 * party's private key and another party's public key, where both have
 * the same set of EC domain parameters. If two parties correctly
 * execute this primitive, they will produce the same output. This
 * primitive can be invoked by a scheme to derive a shared secret key;
 * specifically, it may be used with the schemes ECKAS-DH1 and
 * DL/ECKAS-DH2. It assumes that the input keys are valid (see also
 * Section 7.2.2).
 */
public class ECDHBasicAgreement
    implements BasicAgreement
{
    private ECPrivateKeyParameters key;

    public void init(
        CipherParameters key)
    {
        this.key = (ECPrivateKeyParameters)key;
    }

    public BigIntegerCrypto calculateAgreement(
        CipherParameters pubKey)
    {
        ECPublicKeyParameters pub = (ECPublicKeyParameters)pubKey;
        ECPoint P = pub.getQ().multiply(key.getD());

        // if (p.isInfinity()) throw new RuntimeException("d*Q == infinity");

        return P.getX().toBigInteger();
    }
    /**
     * Clear agreement data including private key data.
     * 
     * Clears all known agreement data and resets the agreement. To use the
     * agreement againt the application must initialize it again.
     */
    
    public void clear() {
        key.getD().zeroize();   // clear private key data
        key = null;
    }
}

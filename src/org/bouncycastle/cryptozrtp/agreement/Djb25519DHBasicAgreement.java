package org.bouncycastle.cryptozrtp.agreement;

import djb.Curve25519;
import gnu.java.bigintcrypto.BigIntegerCrypto;
import org.bouncycastle.cryptozrtp.BasicAgreement;
import org.bouncycastle.cryptozrtp.CipherParameters;
import org.bouncycastle.cryptozrtp.params.Djb25519PrivateKeyParameters;
import org.bouncycastle.cryptozrtp.params.Djb25519PublicKeyParameters;
import org.bouncycastle.cryptozrtp.params.ECPrivateKeyParameters;
import org.bouncycastle.cryptozrtp.params.ECPublicKeyParameters;
import org.bouncycastle.mathzrtp.ec.ECPoint;

import java.util.Arrays;


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
public class Djb25519DHBasicAgreement implements BasicAgreement
{
    private Djb25519PrivateKeyParameters key;

    public void init(CipherParameters key) {
        this.key = (Djb25519PrivateKeyParameters)key;
    }

    public BigIntegerCrypto calculateAgreement(CipherParameters pubKey) {
        Djb25519PublicKeyParameters pub = (Djb25519PublicKeyParameters)pubKey;
        byte[] P = pub.getP();

        /* Key agreement
         *   Z  [out] shared secret (needs hashing before use)
         *   k  [in]  your private key for key agreement
         *   P  [in]  peer's public key
         */
        byte[] Z = new byte[Curve25519.KEY_SIZE];
        Curve25519.curve(Z, key.getK(), P);

        // Return a BigInteger, use only as a byte array transport and to keep the API
        return new BigIntegerCrypto(1, Z);
    }
    /**
     * Clear agreement data including private key data.
     * 
     * Clears all known agreement data and resets the agreement. To use the
     * agreement againt the application must initialize it again.
     */
    
    public void clear() {
        Arrays.fill(key.getK(), (byte)0);
        key = null;
    }
}

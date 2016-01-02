package org.bouncycastle.cryptozrtp.params;

// Curve25519 uses 32 byte random data as a private key, not a BigInteger
public class Djb25519PrivateKeyParameters extends ECKeyParameters {
    byte[] k;

    public Djb25519PrivateKeyParameters(byte[] k) {
        super(true, null);
        this.k = k;
    }

    public byte[] getK()
    {
        return k;
    }
}

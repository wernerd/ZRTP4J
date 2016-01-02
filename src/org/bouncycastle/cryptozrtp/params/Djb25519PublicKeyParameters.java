package org.bouncycastle.cryptozrtp.params;

// Curve25519 derives 32 byte data as a public key from the private key data.
public class Djb25519PublicKeyParameters extends ECKeyParameters {
    byte[] P;

    public Djb25519PublicKeyParameters(byte[] P) {
        super(false, null);
        this.P = P;
    }

    public byte[] getP()
    {
        return P;
    }
}

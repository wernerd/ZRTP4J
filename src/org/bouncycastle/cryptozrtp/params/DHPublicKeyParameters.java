package org.bouncycastle.cryptozrtp.params;

import gnu.java.bigintcrypto.BigIntegerCrypto;

public class DHPublicKeyParameters
    extends DHKeyParameters
{
    private BigIntegerCrypto      y;

    public DHPublicKeyParameters(
        BigIntegerCrypto      y,
        DHParameters    params)
    {
        super(false, params);

        this.y = y;
    }   

    public BigIntegerCrypto getY()
    {
        return y;
    }

    public int hashCode()
    {
        return y.hashCode() ^ super.hashCode();
    }

    public boolean equals(
        Object  obj)
    {
        if (!(obj instanceof DHPublicKeyParameters))
        {
            return false;
        }

        DHPublicKeyParameters   other = (DHPublicKeyParameters)obj;

        return other.getY().equals(y) && super.equals(obj);
    }
}

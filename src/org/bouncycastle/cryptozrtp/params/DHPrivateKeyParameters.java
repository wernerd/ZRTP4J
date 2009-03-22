package org.bouncycastle.cryptozrtp.params;

import gnu.java.bigintcrypto.BigIntegerCrypto;

public class DHPrivateKeyParameters
    extends DHKeyParameters
{
    private BigIntegerCrypto      x;

    public DHPrivateKeyParameters(
        BigIntegerCrypto      x,
        DHParameters    params)
    {
        super(true, params);

        this.x = x;
    }   

    public BigIntegerCrypto getX()
    {
        return x;
    }

    public int hashCode()
    {
        return x.hashCode() ^ super.hashCode();
    }
    
    public boolean equals(
        Object  obj)
    {
        if (!(obj instanceof DHPrivateKeyParameters))
        {
            return false;
        }

        DHPrivateKeyParameters  other = (DHPrivateKeyParameters)obj;

        return other.getX().equals(this.x) && super.equals(obj);
    }
    
    /**
     * Clear private key data.
     * 
     * Clears the private key data and overwrites it. To use the
     * agreement againt the application must initialize it again.
     */
    
    public void clear() {
        if (x != null)
            x.clear();          // overwrites BigIntere data with zero
        x = null;
    }

}

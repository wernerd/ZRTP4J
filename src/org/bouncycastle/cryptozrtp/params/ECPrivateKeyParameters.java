package org.bouncycastle.cryptozrtp.params;

import gnu.java.bigintcrypto.BigIntegerCrypto;

public class ECPrivateKeyParameters
    extends ECKeyParameters
{
    BigIntegerCrypto d;

    public ECPrivateKeyParameters(
        BigIntegerCrypto          d,
        ECDomainParameters  params)
    {
        super(true, params);
        this.d = d;
    }

    public BigIntegerCrypto getD()
    {
        return d;
    }
}

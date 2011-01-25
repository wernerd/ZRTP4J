package org.bouncycastle.mathzrtp.ec;

import gnu.java.bigintcrypto.BigIntegerCrypto;

/**
 * Class implementing the NAF (Non-Adjacent Form) multiplication algorithm.
 */
class FpNafMultiplier implements ECMultiplier
{
    /**
     * D.3.2 pg 101
     * @see org.bouncycastle.math.ec.ECMultiplier#multiply(org.bouncycastle.math.ec.ECPoint, java.math.BigInteger)
     */
    public ECPoint multiply(ECPoint p, BigIntegerCrypto k, PreCompInfo preCompInfo)
    {
        // TODO Probably should try to add this
        // BigInteger e = k.mod(n); // n == order of p
        BigIntegerCrypto e = k;
        BigIntegerCrypto h = e.multiply(BigIntegerCrypto.valueOf(3));

        ECPoint neg = p.negate();
        ECPoint R = p;

        for (int i = h.bitLength() - 2; i > 0; --i)
        {             
            R = R.twice();

            boolean hBit = h.testBit(i);
            boolean eBit = e.testBit(i);

            if (hBit != eBit)
            {
                R = R.add(hBit ? p : neg);
            }
        }

        return R;
    }
}

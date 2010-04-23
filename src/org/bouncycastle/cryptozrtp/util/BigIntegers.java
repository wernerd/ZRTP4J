package org.bouncycastle.cryptozrtp.util;

import gnu.java.bigintcrypto.BigIntegerCrypto;
import org.bouncycastle.crypto.prng.RandomGenerator;

/**
 * BigInteger utilities.
 */
public final class BigIntegers
{
    /**
     * Return the passed in value as an unsigned byte array.
     * 
     * @param value value to be converted.
     * @return a byte array without a leading zero byte if present in the signed encoding.
     */
    public static byte[] asUnsignedByteArray(
        BigIntegerCrypto value)
    {
        byte[] bytes = value.toByteArray();
        
        if (bytes[0] == 0)
        {
            byte[] tmp = new byte[bytes.length - 1];
            
            System.arraycopy(bytes, 1, tmp, 0, tmp.length);
            
            return tmp;
        }
        
        return bytes;
    }

    /**
     * Return a random BigInteger not less than 'min' and not greater than 'max'
     * 
     * @param min the least value that may be generated
     * @param max the greatest value that may be generated
     * @param random the source of randomness
     * @return a random BigInteger value in the range [min,max]
     */
    public static BigIntegerCrypto createRandomInRange(
            BigIntegerCrypto      min,
            BigIntegerCrypto      max,
            RandomGenerator    random)
    {
        BigIntegerCrypto x;
        do
        {
            x = new BigIntegerCrypto(max.bitLength(), random);
        }
        while (x.compareTo(min) < 0 || x.compareTo(max) > 0);
        return x;
    }
}

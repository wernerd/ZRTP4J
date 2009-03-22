package org.bouncycastle.cryptozrtp.generators;

import gnu.java.bigintcrypto.BigIntegerCrypto;
import java.security.SecureRandom;

class DHKeyGeneratorHelper
{
    private static final int MAX_ITERATIONS = 1000;

    static final DHKeyGeneratorHelper INSTANCE = new DHKeyGeneratorHelper();
    
    private static final BigIntegerCrypto ZERO = BigIntegerCrypto.valueOf(0);
    private static final BigIntegerCrypto TWO = BigIntegerCrypto.valueOf(2);
    
    private DHKeyGeneratorHelper()
    {
    }
    
    BigIntegerCrypto calculatePrivate(BigIntegerCrypto p, SecureRandom random, int limit)
    {
        //
        // calculate the private key
        //
        BigIntegerCrypto pSub2 = p.subtract(TWO);
        BigIntegerCrypto x;
        
        if (limit == 0)
        {
            x = createInRange(pSub2, random);
        }
        else
        {
            do
            {
                x = new BigIntegerCrypto(limit, 0, random);
            }
            while (x.equals(ZERO));
        }
        
        return x;
    }

    private BigIntegerCrypto createInRange(BigIntegerCrypto max, SecureRandom random)
    {
        BigIntegerCrypto x;
        int maxLength = max.bitLength();
        int count = 0;
        
        do
        {
            x = new BigIntegerCrypto(maxLength, random);
            count++;
        }
        while ((x.equals(ZERO) || x.compareTo(max) > 0) && count != MAX_ITERATIONS);
        
        if (count == MAX_ITERATIONS)  // fall back to a faster (restricted) method
        {
            return new BigIntegerCrypto(maxLength - 1, random).setBit(0);
        }
        
        return x;
    }
    
    BigIntegerCrypto calculatePublic(BigIntegerCrypto p, BigIntegerCrypto g, BigIntegerCrypto x)
    {
        return g.modPow(x, p);
    }
}

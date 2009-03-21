package org.bouncycastle.cryptozrtp.generators;

import gnu.java.bigintcrypto.BigIntegerCrypto;
import java.security.SecureRandom;

import org.bouncycastle.cryptozrtp.util.BigIntegers;

class DHParametersHelper
{
    private static final BigIntegerCrypto ONE = BigIntegerCrypto.valueOf(1);
    private static final BigIntegerCrypto TWO = BigIntegerCrypto.valueOf(2);

    // Finds a pair of prime BigIntegerCrypto's {p, q: p = 2q + 1}
    static BigIntegerCrypto[] generateSafePrimes(
        int             size,
        int             certainty,
        SecureRandom    random)
    {
        BigIntegerCrypto p, q;
        int qLength = size - 1;

        for (;;)
        {
            q = new BigIntegerCrypto(qLength, 2, random);

            // p <- 2q + 1
            p = q.shiftLeft(1).add(ONE);

            if (p.isProbablePrime(certainty)
                && (certainty <= 2 || q.isProbablePrime(certainty)))
            {
                    break;
            }
        }

        return new BigIntegerCrypto[] { p, q };
    }

    // Select a high order element of the multiplicative group Zp*
    // p and q must be s.t. p = 2*q + 1, where p and q are prime
    static BigIntegerCrypto selectGenerator(
        BigIntegerCrypto      p,
        BigIntegerCrypto      q,
        SecureRandom    random)
    {
        BigIntegerCrypto pMinusTwo = p.subtract(TWO);
        BigIntegerCrypto g;

        // Handbook of Applied Cryptography 4.86
        do
        {
            g = BigIntegers.createRandomInRange(TWO, pMinusTwo, random);
        }
        while (g.modPow(TWO, p).equals(ONE)
            || g.modPow(q, p).equals(ONE));

/*
        // RFC 2631 2.1.1 (and see Handbook of Applied Cryptography 4.81)
        do
        {
            BigInteger h = createInRange(TWO, pMinusTwo, random);

            g = h.modPow(TWO, p);
        }
        while (g.equals(ONE));
*/

        return g;
    }
}

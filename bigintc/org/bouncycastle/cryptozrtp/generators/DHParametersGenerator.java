package org.bouncycastle.cryptozrtp.generators;

import org.bouncycastle.cryptozrtp.params.DHParameters;

import gnu.java.bigintcrypto.BigIntegerCrypto;
import java.security.SecureRandom;

public class DHParametersGenerator
{
    private int             size;
    private int             certainty;
    private SecureRandom    random;

    private static final BigIntegerCrypto TWO = BigIntegerCrypto.valueOf(2);

    /**
     * Initialise the parameters generator.
     * 
     * @param size bit length for the prime p
     * @param certainty level of certainty for the prime number tests
     * @param random  a source of randomness
     */
    public void init(
        int             size,
        int             certainty,
        SecureRandom    random)
    {
        this.size = size;
        this.certainty = certainty;
        this.random = random;
    }

    /**
     * which generates the p and g values from the given parameters,
     * returning the DHParameters object.
     * <p>
     * Note: can take a while...
     */
    public DHParameters generateParameters()
    {
        //
        // find a safe prime p where p = 2*q + 1, where p and q are prime.
        //
        BigIntegerCrypto[] safePrimes = DHParametersHelper.generateSafePrimes(size, certainty, random);

        BigIntegerCrypto p = safePrimes[0];
        BigIntegerCrypto q = safePrimes[1];
        BigIntegerCrypto g = DHParametersHelper.selectGenerator(p, q, random);

        return new DHParameters(p, g, q, TWO, null);
    }
}

package org.bouncycastle.cryptozrtp.params;

import org.bouncycastle.crypto.prng.RandomGenerator;

import org.bouncycastle.cryptozrtp.KeyGenerationParameters;

public class DHKeyGenerationParameters
    extends KeyGenerationParameters
{
    private DHParameters    params;

    public DHKeyGenerationParameters(
    	RandomGenerator    random,
        DHParameters    params)
    {
        super(random, params.getP().bitLength());

        this.params = params;
    }

    public DHParameters getParameters()
    {
        return params;
    }
}

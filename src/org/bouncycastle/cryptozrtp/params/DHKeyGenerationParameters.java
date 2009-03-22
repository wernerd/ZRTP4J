package org.bouncycastle.cryptozrtp.params;

import java.security.SecureRandom;

import org.bouncycastle.cryptozrtp.KeyGenerationParameters;

public class DHKeyGenerationParameters
    extends KeyGenerationParameters
{
    private DHParameters    params;

    public DHKeyGenerationParameters(
        SecureRandom    random,
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

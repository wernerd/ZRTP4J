package org.bouncycastle.cryptozrtp.params;

import djb.Curve25519;
import org.bouncycastle.crypto.prng.RandomGenerator;
import org.bouncycastle.cryptozrtp.KeyGenerationParameters;

public class Djb25519KeyGenerationParameters extends KeyGenerationParameters {

    public Djb25519KeyGenerationParameters(RandomGenerator random) {
        super(random, Curve25519.KEY_SIZE * 8);
    }
}

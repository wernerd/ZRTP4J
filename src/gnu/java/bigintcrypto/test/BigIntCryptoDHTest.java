package gnu.java.bigintcrypto.test;

import gnu.java.bigintcrypto.BigIntegerCrypto;

import java.security.SecureRandom;

/**
 * Class to test and check required crypto algorithms.
 * 
 * This class instantiates a security provider and all necessary crypto
 * classes and algorithms. Then it preforms a quick check if the algorithms
 * are available and work. If something is wrong an exception is thrown.
 * 
 *  Most often it is just a missing "unlimited strength" policy file. The
 *  standard policy file limits the key length of some alorithms.
 */
public class BigIntCryptoDHTest {

    // The DH prime for DH3k (3072 bit) as defined in RFC 3526
    public static final BigIntegerCrypto P3072 = new BigIntegerCrypto(
//                        1                   2        
//    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3           24 bytes per line
    "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1" +        // 0
    "29024E088A67CC74020BBEA63B139B22514A08798E3404DD" +        // 1
    "EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245" +        // 2
    "E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED" +        // 3
    "EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3D" +        // 4
    "C2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F" +        // 5
    "83655D23DCA3AD961C62F356208552BB9ED529077096966D" +        // 6
    "670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B" +        // 7
    "E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9" +        // 8
    "DE2BCBF6955817183995497CEA956AE515D2261898FA0510" +        // 9
    "15728E5A8AAAC42DAD33170D04507A33A85521ABDF1CBA64" +        // 10
    "ECFB850458DBEF0A8AEA71575D060C7DB3970F85A6E1E4C7" +        // 11
    "ABF5AE8CDB0933D71E8C94E04A25619DCEE3D2261AD2EE6B" +        // 12
    "F12FFA06D98A0864D87602733EC86A64521F2B18177B200C" +        // 13
    "BBE117577A615D6C770988C0BAD946E208E24FA074E5AB31" +        // 14
    "43DB5BFCE0FD108E4B82D120A93AD2CAFFFFFFFFFFFFFFFF", 16);    // 15, total = 24 * 16 = 384

    // DH generator 2
    public static final BigIntegerCrypto two = BigIntegerCrypto.valueOf(2);

    private SecureRandom secRand = new SecureRandom();
    
        
    public void testManyPub() {
        BigIntegerCrypto x;

        for (int i = 0; i < 20; i++) {

            do {
                x = new BigIntegerCrypto(256, 0, secRand);
            } while (x.equals(BigIntegerCrypto.ZERO));

            two.modPow(x, P3072);
            System.out.print(i + " ");
        }
    }

    public static void main(String[] args) {

        BigIntCryptoDHTest ct = new BigIntCryptoDHTest();
        ct.testManyPub();
        
        System.out.println("Test done");
        System.exit(0);
    }

}

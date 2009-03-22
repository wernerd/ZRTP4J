package gnu.java.bigintcrypto.test;

import gnu.java.zrtp.ZrtpConstants;

import gnu.java.bigintcrypto.BigIntegerCrypto;

import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.Random;
import java.util.Arrays;

import org.bouncycastle.cryptozrtp.generators.DHBasicKeyPairGenerator;
import org.bouncycastle.cryptozrtp.params.DHKeyGenerationParameters;
import org.bouncycastle.cryptozrtp.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.DataLengthException;
//import org.bouncycastle.cryptozrtp.InvalidCipherTextException;
import org.bouncycastle.cryptozrtp.agreement.DHBasicAgreement;
import org.bouncycastle.cryptozrtp.params.DHPrivateKeyParameters;
import org.bouncycastle.cryptozrtp.params.DHPublicKeyParameters;
import org.bouncycastle.cryptozrtp.params.DHParameters;

import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.macs.HMac;
import org.bouncycastle.crypto.params.KeyParameter;

import org.bouncycastle.crypto.BufferedBlockCipher;
import org.bouncycastle.crypto.modes.CFBBlockCipher;
import org.bouncycastle.crypto.engines.AESFastEngine;
import org.bouncycastle.crypto.params.ParametersWithIV;


import gnu.java.zrtp.utils.ZrtpUtils;


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
public class CryptoTestPureLW {

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

    public static final DHParameters specDh3k = new DHParameters(P3072, two, null, 256);

    private SecureRandom secRand = new SecureRandom();
    
    private DHBasicKeyPairGenerator dhKeyPairGenLw;
    private AsymmetricCipherKeyPair myKeyPairLwA;
    private AsymmetricCipherKeyPair myKeyPairLwB;
    private DHBasicAgreement dhContextLwA;
    private DHBasicAgreement dhContextLwB;

    byte[] masterKey = 
        { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
          0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 
          0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
          0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f };     // 32 bytes == 256 bits
    private byte[] randomIV = new byte[16];

    String dataAsText = new String("This data is highly confidential and shall never exposed to anybody else except me");
    byte[] dataToSecure = dataAsText.getBytes();
    
    boolean testProvider() {
    
        /*
         * Test and check DH key agreement
         */
        // do it the lightWeight way
        dhKeyPairGenLw = new DHBasicKeyPairGenerator();
        
        // set the p and g parameters and the required bit length for the private key
        DHKeyGenerationParameters dhParamsLw = new DHKeyGenerationParameters(secRand, specDh3k);
        dhKeyPairGenLw.init(dhParamsLw);
        myKeyPairLwA = dhKeyPairGenLw.generateKeyPair(); // this is our A party key pair
        
        myKeyPairLwB = dhKeyPairGenLw.generateKeyPair(); // this is our B party key pair

                
        // Now the key agreement
        
        // do it stepwise to simulate situation inside ZRTP - we get a BigInt and need to
        // construct the DH parameters manually.
        
        // get B party's public key 
        DHPublicKeyParameters tmp = (DHPublicKeyParameters) myKeyPairLwB.getPublic();
        BigIntegerCrypto y = tmp.getY();                            // and the big int value of it

        // System.out.println("B public length: " + y.toByteArray().length);
        
        // create a lightWeight DH agreement for A party
        // initialize with A party's private key and its parameters
        // calculate the secret value of A party, using B party's value
        dhContextLwA = new DHBasicAgreement();
        dhContextLwA.init(myKeyPairLwA.getPrivate());        
        BigIntegerCrypto resultLwA = dhContextLwA.calculateAgreement(new DHPublicKeyParameters(y, specDh3k));

        
        // get A party's public key 
        tmp = (DHPublicKeyParameters) myKeyPairLwA.getPublic();
        y = tmp.getY();                            // and the big int value of it
        
        // System.out.println("A public length: " + y.toByteArray().length);
        
        // create a lightWeight DH agreement for B party
        // and initialize with A party's private key and its parameters
        // then calculate the secret value of A party, using B party's value
        dhContextLwB = new DHBasicAgreement();       
        dhContextLwB.init(myKeyPairLwB.getPrivate());
        BigIntegerCrypto resultLwB = dhContextLwB.calculateAgreement(new DHPublicKeyParameters(y, specDh3k));

        byte[] lwByteA = adjustKey(resultLwA);
        byte[] lwByteB = adjustKey(resultLwB);
                
        // System.out.println("DH Length A, B: " + lwByteA.length + ", " + lwByteB.length);
        
        if (Arrays.equals(lwByteA, lwByteB)) {
            System.out.println("DH results are equal");
        } else {
            System.out.println("DH results differ");
            ZrtpUtils.hexdump("lwByteA", lwByteA, lwByteA.length);
            ZrtpUtils.hexdump("lwByteB", lwByteB, lwByteB.length);

        }

        // SHA256 LW
        HMac hmacSha256lw = new HMac(new SHA256Digest());
        hmacSha256lw.init(new KeyParameter(masterKey));
        hmacSha256lw.update(dataToSecure, 0, dataToSecure.length);
        byte[] hmac256lw = new byte[hmacSha256lw.getMacSize()];
        hmacSha256lw.doFinal(hmac256lw, 0);        
        
        // Test the AES cipher
        Random ran = new Random();
        ran.nextBytes(randomIV);        // IV used in encryption
        
        // test the cipher - LW
        
        AESFastEngine aesEnc = new AESFastEngine();
        CFBBlockCipher cfbAesEnc = new CFBBlockCipher(aesEnc, aesEnc.getBlockSize() * 8);
        BufferedBlockCipher bufCfbAesEnc = new BufferedBlockCipher(cfbAesEnc);
        bufCfbAesEnc.init(true, new ParametersWithIV(new KeyParameter(masterKey), randomIV));
        
        byte[] aesOutLwEnc = new byte[dataToSecure.length];
        int done = bufCfbAesEnc.processBytes(dataToSecure, 0, dataToSecure.length, aesOutLwEnc, 0);
        try {
            bufCfbAesEnc.doFinal(aesOutLwEnc, done);
        } catch (DataLengthException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        } catch (IllegalStateException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        }
        
        AESFastEngine aesDec = new AESFastEngine();
        CFBBlockCipher cfbAesDec = new CFBBlockCipher(aesDec, aesDec.getBlockSize() * 8);
        BufferedBlockCipher bufCfbAesDec = new BufferedBlockCipher(cfbAesDec);
        bufCfbAesDec.init(false, new ParametersWithIV(new KeyParameter(masterKey), randomIV));
        
        byte[] aesOutLwDec = new byte[dataToSecure.length];
        done = bufCfbAesDec.processBytes(aesOutLwEnc, 0, aesOutLwEnc.length, aesOutLwDec, 0);
        try {
            bufCfbAesDec.doFinal(aesOutLwDec, done);
        } catch (DataLengthException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        } catch (IllegalStateException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        }
        if (Arrays.equals(dataToSecure, aesOutLwDec)) {
            System.out.println("AES-CFB results are equal");
        } else {
            System.out.println("AES-CFB results differ");
            ZrtpUtils.hexdump("Clear", dataToSecure, dataToSecure.length);
            ZrtpUtils.hexdump("Dec", aesOutLwDec, aesOutLwDec.length);

        }
        return true;
    }
        
    public void testManyPub() {
        BigIntegerCrypto x;

        for (int i = 0; i < 10; i++) {

            do {
                x = new BigIntegerCrypto(256, 0, secRand);
            } while (x.equals(BigIntegerCrypto.ZERO));

            two.modPow(x, P3072);
            System.out.print(i + " ");
        }
    }

    byte[] adjustKey(BigIntegerCrypto in)  {
        byte[] inBytes = in.toByteArray();
        // check for leading zero byte if public key resulted in negtive
        // value. BigIntegerCrypto adds a leading zero to drop the negatice sign bit
        if (inBytes[0] == 0) {
            byte[] tmp = new byte[inBytes.length - 1];
            System.arraycopy(inBytes, 1, tmp, 0, tmp.length);
            return tmp;

            // ZrtpUtils.hexdump("Public key timmed", pubKeyBytes, pubKeyBytes.length);
        }
        return inBytes;
    }
    public static void main(String[] args) {

        CryptoTestPureLW ct = new CryptoTestPureLW();
        ct.testProvider();
        ct.testManyPub();
        
        System.out.println("Test done");
        System.exit(0);
    }

}

package demo;

import gnu.java.zrtp.ZrtpConstants;

import gnu.java.bigintcrypto.BigIntegerCrypto;

import java.util.Random;
import java.util.Arrays;

import org.bouncycastle.cryptozrtp.generators.DHBasicKeyPairGenerator;
import org.bouncycastle.cryptozrtp.params.DHKeyGenerationParameters;
import org.bouncycastle.cryptozrtp.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.DataLengthException;
import org.bouncycastle.crypto.InvalidCipherTextException;
//import org.bouncycastle.cryptozrtp.InvalidCipherTextException;
import org.bouncycastle.cryptozrtp.agreement.DHBasicAgreement;
import org.bouncycastle.cryptozrtp.params.DHPublicKeyParameters;

import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.macs.HMac;
import org.bouncycastle.crypto.params.KeyParameter;

import org.bouncycastle.crypto.BufferedBlockCipher;
import org.bouncycastle.crypto.modes.CFBBlockCipher;
import org.bouncycastle.crypto.engines.AESFastEngine;
import org.bouncycastle.crypto.params.ParametersWithIV;
import org.bouncycastle.crypto.prng.RandomGenerator;
import org.jitsi.bccontrib.prng.FortunaGenerator;

import gnu.java.zrtp.utils.ZrtpUtils;


/**
 * Class to test and check required crypto algorithms.
 * 
 * This class instantiates a security provider and all necessary crypto
 * classes and algorithms. Then it performs a quick check if the algorithms
 * are available and work. If something is wrong an exception is thrown.
 * 
 *  Most often it is just a missing "unlimited strength" policy file. The
 *  standard policy file limits the key length of some algorithms.
 */
public class CryptoTestPureLW {

//    public static final DHParameterSpec specDh3kjce = new DHParameterSpec(ZrtpConstants.P3072, ZrtpConstants.two, 256);

    
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
    	byte[] rnd = new byte[256];
    	new Random().nextBytes(rnd);
    	RandomGenerator secRand = new FortunaGenerator(rnd);
        /*
         * Test and check DH key agreement
         */
        // do it the lightWeight way
        dhKeyPairGenLw = new DHBasicKeyPairGenerator();
        
        // set the p and g parameters and the required bit length for the private key
        DHKeyGenerationParameters dhParamsLw = new DHKeyGenerationParameters(secRand, ZrtpConstants.specDh3k);
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
        BigIntegerCrypto resultLwA = dhContextLwA.calculateAgreement(new DHPublicKeyParameters(y, ZrtpConstants.specDh3k));

        
        // get A party's public key 
        tmp = (DHPublicKeyParameters) myKeyPairLwA.getPublic();
        y = tmp.getY();                            // and the big int value of it
        
        // System.out.println("A public length: " + y.toByteArray().length);
        
        // create a lightWeight DH agreement for B party
        // and initialize with A party's private key and its parameters
        // then calculate the secret value of A party, using B party's value
        dhContextLwB = new DHBasicAgreement();       
        dhContextLwB.init(myKeyPairLwB.getPrivate());
        BigIntegerCrypto resultLwB = dhContextLwB.calculateAgreement(new DHPublicKeyParameters(y, ZrtpConstants.specDh3k));

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
        secRand.nextBytes(randomIV);        // IV used in encryption
        
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
        } catch (InvalidCipherTextException e) {
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
        } catch (InvalidCipherTextException e) {
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
    
    byte[] adjustKey(BigIntegerCrypto in)  {
        byte[] inBytes = in.toByteArray();
        // check for leading zero byte if public key resulted in negative
        // value. BigIntegerCrypto adds a leading zero to drop the negative sign bit
        if (inBytes[0] == 0) {
            byte[] tmp = new byte[inBytes.length - 1];
            System.arraycopy(inBytes, 1, tmp, 0, tmp.length);
            return tmp;

            // ZrtpUtils.hexdump("Public key trimmed", pubKeyBytes, pubKeyBytes.length);
        }
        return inBytes;
    }
    public static void main(String[] args) {

        CryptoTestPureLW ct = new CryptoTestPureLW();
        ct.testProvider();

        System.out.println("Test done");
        System.exit(0);
    }

}

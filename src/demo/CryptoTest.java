package demo;

import gnu.java.zrtp.ZrtpConstants;

import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.Provider;
import java.util.Random;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyAgreement;
import javax.crypto.Mac;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.ShortBufferException;
import javax.crypto.spec.DHParameterSpec;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

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
public class CryptoTest {
    public static final DHParameterSpec specDh3kjce = new DHParameterSpec(ZrtpConstants.P3072, ZrtpConstants.two, 256);

    private Provider cryptoProvider = null;
    
    private KeyAgreement dhContext;
    private KeyPairGenerator dhKeyPairGen;
    private KeyPair myKeyPair = null;
    private KeyFactory DHKeyFactory = null;

    private MessageDigest sha256;       // used for various SHA256 computations 
    private Mac hmacSha256;             // used for various HMAC computations

    private Cipher AEScipher = null;

    byte[] masterKey = 
        { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
          0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 
          0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
          0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f };     // 32 bytes == 256 bits
    private byte[] randomIV = new byte[16];

    String dataAsText = new String("This data is highly confidential and shall never exposed to anybody except me");
    byte[] dataToSecure = dataAsText.getBytes();
    
    boolean testProvider(String name) {
    
        System.out.println("Testing for: " + name);
        try {
            Class<?> c = Class.forName(name);
            cryptoProvider = (Provider) c.newInstance();
        } catch (ClassNotFoundException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        } catch (InstantiationException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        } catch (IllegalAccessException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        }

        /*
         * Get all required crypto algorithms here, used everywhere :-)
         */
        try {
            sha256 = MessageDigest.getInstance("SHA256", cryptoProvider);
            hmacSha256 = Mac.getInstance("HMACSHA256", cryptoProvider);
            dhContext = KeyAgreement.getInstance("DH", cryptoProvider);
            dhKeyPairGen = KeyPairGenerator.getInstance("DH", cryptoProvider);
            DHKeyFactory = KeyFactory.getInstance("DH", cryptoProvider);
            AEScipher = Cipher.getInstance("AES/CFB128/NOPADDING", cryptoProvider);
        } catch (NoSuchAlgorithmException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        } catch (NoSuchPaddingException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        }

        // test DH key pair 
        try {
            dhKeyPairGen.initialize(specDh3kjce);
        } catch (InvalidAlgorithmParameterException e1) {
            // TODO Auto-generated catch block
            e1.printStackTrace();
        }
        myKeyPair = dhKeyPairGen.generateKeyPair();

        // test HMAC 256
        SecretKey key = new SecretKeySpec(masterKey, "HMAC");
        try {
            hmacSha256.init(key);
        } catch (InvalidKeyException e1) {
            // TODO Auto-generated catch block
            e1.printStackTrace();
        }
        hmacSha256.update(dataToSecure, 0, dataToSecure.length);

        // test SHA256
        sha256.digest(dataToSecure);

        // Test the AES cipher
        Random ran = new Random();
        ran.nextBytes(randomIV);        // IV used in encryption

        SecretKey encryptionKey = new SecretKeySpec(masterKey, 0, masterKey.length, "AES");
        IvParameterSpec ivp = new IvParameterSpec(randomIV);
        
        try {
            AEScipher.init(Cipher.ENCRYPT_MODE, encryptionKey, ivp);
            AEScipher.doFinal(dataToSecure, 0, dataToSecure.length, dataToSecure);
        } catch (InvalidKeyException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        } catch (InvalidAlgorithmParameterException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        } catch (ShortBufferException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        } catch (IllegalBlockSizeException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        } catch (BadPaddingException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        }
        
        return true;
    }
    
    public static void main(String[] args) {

        CryptoTest ct = new CryptoTest();
        if (args.length == 0) 
            ct.testProvider("org.bouncycastle.jce.provider.BouncyCastleProvider");
        else
            ct.testProvider(args[0]);

        System.out.println("Test done");
        System.exit(0);
    }

}

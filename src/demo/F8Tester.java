package demo;

import java.util.Arrays;

import org.bouncycastle.crypto.BlockCipher;
import org.bouncycastle.crypto.params.KeyParameter;

import org.bouncycastle.crypto.engines.AESFastEngine;

import gnu.java.zrtp.jmf.transform.srtp.SRTPCipherF8;
import gnu.java.zrtp.utils.ZrtpUtils;

public class F8Tester {
    /*
     * The F8 test vectors according to RFC3711
     */
    public static final byte[] salt = {(byte)0x32, (byte)0xf2, (byte)0x87, (byte)0x0d};

    public static final byte[] iv = {(byte)0x00, (byte)0x6e, (byte)0x5c, (byte)0xba, (byte)0x50, (byte)0x68, (byte)0x1d, (byte)0xe5,
        (byte)0x5c, (byte)0x62, (byte)0x15, (byte)0x99, (byte)0xd4, (byte)0x62, (byte)0x56, (byte)0x4a};

    public static final byte[] key= {  (byte)0x23, (byte)0x48, (byte)0x29, (byte)0x00, (byte)0x84, (byte)0x67, (byte)0xbe, (byte)0x18,
        (byte)0x6c, (byte)0x3d, (byte)0xe1, (byte)0x4a, (byte)0xae, (byte)0x72, (byte)0xd6, (byte)0x2c};

    public static final byte[] payload = {
        (byte)0x70, (byte)0x73, (byte)0x65, (byte)0x75, (byte)0x64, (byte)0x6f, (byte)0x72, (byte)0x61,
        (byte)0x6e, (byte)0x64, (byte)0x6f, (byte)0x6d, (byte)0x6e, (byte)0x65, (byte)0x73, (byte)0x73,
        (byte)0x20, (byte)0x69, (byte)0x73, (byte)0x20, (byte)0x74, (byte)0x68, (byte)0x65, (byte)0x20,
        (byte)0x6e, (byte)0x65, (byte)0x78, (byte)0x74, (byte)0x20, (byte)0x62, (byte)0x65, (byte)0x73,
        (byte)0x74, (byte)0x20, (byte)0x74, (byte)0x68, (byte)0x69, (byte)0x6e, (byte)0x67};  // 39 bytes

    public static final byte[] cipherText = {
        (byte)0x01, (byte)0x9c, (byte)0xe7, (byte)0xa2, (byte)0x6e, (byte)0x78, (byte)0x54, (byte)0x01,
        (byte)0x4a, (byte)0x63, (byte)0x66, (byte)0xaa, (byte)0x95, (byte)0xd4, (byte)0xee, (byte)0xfd,
        (byte)0x1a, (byte)0xd4, (byte)0x17, (byte)0x2a, (byte)0x14, (byte)0xf9, (byte)0xfa, (byte)0xf4,
        (byte)0x55, (byte)0xb7, (byte)0xf1, (byte)0xd4, (byte)0xb6, (byte)0x2b, (byte)0xd0, (byte)0x8f,
        (byte)0x56, (byte)0x2c, (byte)0x0e, (byte)0xef, (byte)0x7c, (byte)0x48, (byte)0x02}; // 39 bytes

    // public static final byte[] rtpPacketHeader[] = {
//                             0x80, 0x6e, 0x5c, 0xba, 0x50, 0x68, 0x1d, 0xe5,
//                             0x5c, 0x62, 0x15, 0x99};

    public static final byte[] rtpPacket = {
        (byte)0x80, (byte)0x6e, (byte)0x5c, (byte)0xba, (byte)0x50, (byte)0x68, (byte)0x1d, (byte)0xe5,
        (byte)0x5c, (byte)0x62, (byte)0x15, (byte)0x99,                        // header
        (byte)0x70, (byte)0x73, (byte)0x65, (byte)0x75, (byte)0x64, (byte)0x6f, (byte)0x72, (byte)0x61, // payload, 39 bytes
        (byte)0x6e, (byte)0x64, (byte)0x6f, (byte)0x6d, (byte)0x6e, (byte)0x65, (byte)0x73, (byte)0x73,
        (byte)0x20, (byte)0x69, (byte)0x73, (byte)0x20, (byte)0x74, (byte)0x68, (byte)0x65, (byte)0x20,
        (byte)0x6e, (byte)0x65, (byte)0x78, (byte)0x74, (byte)0x20, (byte)0x62, (byte)0x65, (byte)0x73,
        (byte)0x74, (byte)0x20, (byte)0x74, (byte)0x68, (byte)0x69, (byte)0x6e, (byte)0x67};

    static final int ROC = 0xd462564a;

    // The symmetric cipher engines we need here
    private BlockCipher cipher = null;
    private BlockCipher cipherF8 = null; // used inside F8 mode only
    private final byte[] ivStore = new byte[16];
    private final byte[] tmpBuf = new byte[payload.length];

    int testF8()
    {
        cipher = new AESFastEngine();
        cipherF8 = new AESFastEngine();

        KeyParameter encryptionKey = new KeyParameter(key);
        cipher.init(true, encryptionKey);

        //aesCipher->setNewKey(key, sizeof(key));

        /* Create the F8 IV (refer to chapter 4.1.2.2 in RFC 3711):
         *
         * IV = 0x00 || M || PT || SEQ  ||      TS    ||    SSRC   ||    ROC
         *      8Bit  1bit  7bit  16bit       32bit        32bit        32bit
         * ------------\     /--------------------------------------------------
         *       XX       XX      XX XX   XX XX XX XX   XX XX XX XX  XX XX XX XX
         */

        System.arraycopy(rtpPacket, 0, ivStore, 0, 12);
        ivStore[0] = 0;
        // set the ROC in network order into IV
        ivStore[12] = (byte) (ROC >> 24);
        ivStore[13] = (byte) (ROC >> 16);
        ivStore[14] = (byte) (ROC >> 8);
        ivStore[15] = (byte) ROC;

        if (!Arrays.equals(iv, ivStore)) {
            System.err.print("Wrong IV constructed");
            ZrtpUtils.hexdump("derivedIv", ivStore, 16);
            ZrtpUtils.hexdump("test vector Iv", iv, 16);
            return -1;
        }

        SRTPCipherF8.deriveForIV(cipherF8, key, salt);

        // now encrypt the RTP payload data
        SRTPCipherF8.process(cipher, rtpPacket, 12, 39, ivStore, cipherF8);

        System.arraycopy(rtpPacket, 12, tmpBuf, 0, tmpBuf.length);

        // compare with test vector cipher data
        if (!Arrays.equals(tmpBuf, cipherText)) {
            System.err.print("cipher data mismatch");
            ZrtpUtils.hexdump("computed cipher data", tmpBuf, tmpBuf.length);
            ZrtpUtils.hexdump("Test vcetor cipher data", cipherText, cipherText.length);
            return -1;
        }

        // Now decrypt the data to get the payload data again
        SRTPCipherF8.process(cipher, rtpPacket, 12, 39, ivStore, cipherF8);

        System.arraycopy(rtpPacket, 12, tmpBuf, 0, tmpBuf.length);
        // compare decrypted data with test vector payload data
        if (!Arrays.equals(tmpBuf, payload)) {
            System.err.print("payload data mismatch");
            ZrtpUtils.hexdump("computed payload data", tmpBuf, tmpBuf.length);
            ZrtpUtils.hexdump("Test vector payload data", payload, payload.length);
            return -1;
        }
        return 0;
    }

    public static void main(String[] args) {

        F8Tester f8 = new F8Tester();
        System.out.println("Result: " + f8.testF8());
        
        System.exit(0);
    }
}

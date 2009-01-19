/**
 * Copyright (C) 2006-2008 Werner Dittmann
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 * Authors: Werner Dittmann <Werner.Dittmann@t-online.de>
 */

package gnu.java.zrtp;

import java.math.BigInteger;
import javax.crypto.spec.DHParameterSpec;
/**
 * @author Werner Dittmann <Werner.Dittmann@t-online.de>
 *
 */
public class ZrtpConstants {
    
    // Number of bytes of a SHA256 hash
    public static final int SHA256_DIGEST_LENGTH = 32;

    //                                               1
    //                                     0123456789012345
    public static final String clientId = "GNU ZRTP4J 1.4.2"  ;
 
//  "1.00"
    public static final byte[] zrtpVersion = {
        (byte)0x31, (byte)0x2e, (byte)0x31, (byte)0x30};

   /**
    * The message names as defined in ZRTP specification.
    */
//  "Hello   "
    public static final byte[] HelloMsg = {
        (byte)0x48, (byte)0x65, (byte)0x6c, (byte)0x6c, (byte)0x6f, (byte)0x20, (byte)0x20, (byte)0x20};

//  "HelloACK"
    public static final byte[] HelloAckMsg = {
        (byte)0x48, (byte)0x65, (byte)0x6c, (byte)0x6c, (byte)0x6f, (byte)0x41, (byte)0x43, (byte)0x4b};

//  "Commit  "
    public static final byte[] CommitMsg = {
        (byte)0x43, (byte)0x6f, (byte)0x6d, (byte)0x6d, (byte)0x69, (byte)0x74, (byte)0x20, (byte)0x20};

//  "DHPart1 "
    public static final byte[] DHPart1Msg = {
        (byte)0x44, (byte)0x48, (byte)0x50, (byte)0x61, (byte)0x72, (byte)0x74, (byte)0x31, (byte)0x20};

//  "DHPart2 "
    public static final byte[] DHPart2Msg = {
        (byte)0x44, (byte)0x48, (byte)0x50, (byte)0x61, (byte)0x72, (byte)0x74, (byte)0x32, (byte)0x20};

//  "Confirm1"
    public static final byte[] Confirm1Msg = {
        (byte)0x43, (byte)0x6f, (byte)0x6e, (byte)0x66, (byte)0x69, (byte)0x72, (byte)0x6d, (byte)0x31};

//  "Confirm2"
    public static final byte[] Confirm2Msg = {
        (byte)0x43, (byte)0x6f, (byte)0x6e, (byte)0x66, (byte)0x69, (byte)0x72, (byte)0x6d, (byte)0x32};

//  "Conf2ACK"
    public static final byte[] Conf2AckMsg = {
        (byte)0x43, (byte)0x6f, (byte)0x6e, (byte)0x66, (byte)0x32, (byte)0x41, (byte)0x43, (byte)0x4b};

//  "Error   "
    public static final byte[] ErrorMsg = {
        (byte)0x45, (byte)0x72, (byte)0x72, (byte)0x6f, (byte)0x72, (byte)0x20, (byte)0x20, (byte)0x20};

//  "ErrorACK"
    public static final byte[] ErrorAckMsg = {
        (byte)0x45, (byte)0x72, (byte)0x72, (byte)0x6f, (byte)0x72, (byte)0x41, (byte)0x43, (byte)0x4b};

//  "GoClear "
    public static final byte[] GoClearMsg = {
        (byte)0x47, (byte)0x6f, (byte)0x43, (byte)0x6c, (byte)0x65, (byte)0x61, (byte)0x72, (byte)0x20};

//  "ClearACK"
    public static final byte[] ClearAckMsg = {
        (byte)0x43, (byte)0x6c, (byte)0x65, (byte)0x61, (byte)0x72, (byte)0x41, (byte)0x43, (byte)0x4b};

    /**
     * Various strings used to build the keys, hashes and HMACs
     */
//  "Responder"
    public static final byte[] responder = {
        (byte)0x52, (byte)0x65, (byte)0x73, (byte)0x70, (byte)0x6f, (byte)0x6e, (byte)0x64, (byte)0x65,
        (byte)0x72};
    
//  "Initiator"
    public static final byte[] initiator = {
        (byte)0x49, (byte)0x6e, (byte)0x69, (byte)0x74, (byte)0x69, (byte)0x61, (byte)0x74, (byte)0x6f,
        (byte)0x72};

//  "Initiator SRTP master key"
    public static final byte[] iniMasterKey = {
        (byte)0x49, (byte)0x6e, (byte)0x69, (byte)0x74, (byte)0x69, (byte)0x61, (byte)0x74, (byte)0x6f,
        (byte)0x72, (byte)0x20, (byte)0x53, (byte)0x52, (byte)0x54, (byte)0x50, (byte)0x20, (byte)0x6d,
        (byte)0x61, (byte)0x73, (byte)0x74, (byte)0x65, (byte)0x72, (byte)0x20, (byte)0x6b, (byte)0x65,
        (byte)0x79, (byte)0x0};

//  "Initiator SRTP master salt"
    public static final byte[] iniMasterSalt = {
        (byte)0x49, (byte)0x6e, (byte)0x69, (byte)0x74, (byte)0x69, (byte)0x61, (byte)0x74, (byte)0x6f,
        (byte)0x72, (byte)0x20, (byte)0x53, (byte)0x52, (byte)0x54, (byte)0x50, (byte)0x20, (byte)0x6d,
        (byte)0x61, (byte)0x73, (byte)0x74, (byte)0x65, (byte)0x72, (byte)0x20, (byte)0x73, (byte)0x61,
        (byte)0x6c, (byte)0x74, (byte)0x0};

//  "Responder SRTP master key"
    public static final byte[] respMasterKey = {
        (byte)0x52, (byte)0x65, (byte)0x73, (byte)0x70, (byte)0x6f, (byte)0x6e, (byte)0x64, (byte)0x65,
        (byte)0x72, (byte)0x20, (byte)0x53, (byte)0x52, (byte)0x54, (byte)0x50, (byte)0x20, (byte)0x6d,
        (byte)0x61, (byte)0x73, (byte)0x74, (byte)0x65, (byte)0x72, (byte)0x20, (byte)0x6b, (byte)0x65,
        (byte)0x79, (byte)0x0};

//  "Responder SRTP master salt"
    public static final byte[] respMasterSalt = {
        (byte)0x52, (byte)0x65, (byte)0x73, (byte)0x70, (byte)0x6f, (byte)0x6e, (byte)0x64, (byte)0x65,
        (byte)0x72, (byte)0x20, (byte)0x53, (byte)0x52, (byte)0x54, (byte)0x50, (byte)0x20, (byte)0x6d,
        (byte)0x61, (byte)0x73, (byte)0x74, (byte)0x65, (byte)0x72, (byte)0x20, (byte)0x73, (byte)0x61,
        (byte)0x6c, (byte)0x74, (byte)0x0};

//  "Initiator HMAC key"
    public static final byte[] iniHmacKey = {
        (byte)0x49, (byte)0x6e, (byte)0x69, (byte)0x74, (byte)0x69, (byte)0x61, (byte)0x74, (byte)0x6f,
        (byte)0x72, (byte)0x20, (byte)0x48, (byte)0x4d, (byte)0x41, (byte)0x43, (byte)0x20, (byte)0x6b,
        (byte)0x65, (byte)0x79, (byte)0x0};

//  "Responder HMAC key"
    public static final byte[] respHmacKey = {
        (byte)0x52, (byte)0x65, (byte)0x73, (byte)0x70, (byte)0x6f, (byte)0x6e, (byte)0x64, (byte)0x65,
        (byte)0x72, (byte)0x20, (byte)0x48, (byte)0x4d, (byte)0x41, (byte)0x43, (byte)0x20, (byte)0x6b,
        (byte)0x65, (byte)0x79, (byte)0x0};

//  "retained secret"
    public static final byte[] retainedSec = {
        (byte)0x72, (byte)0x65, (byte)0x74, (byte)0x61, (byte)0x69, (byte)0x6e, (byte)0x65, (byte)0x64,
        (byte)0x20, (byte)0x73, (byte)0x65, (byte)0x63, (byte)0x72, (byte)0x65, (byte)0x74, (byte)0x0};

//  "Initiator ZRTP key"
    public static final byte[] iniZrtpKey = {
        (byte)0x49, (byte)0x6e, (byte)0x69, (byte)0x74, (byte)0x69, (byte)0x61, (byte)0x74, (byte)0x6f,
        (byte)0x72, (byte)0x20, (byte)0x5a, (byte)0x52, (byte)0x54, (byte)0x50, (byte)0x20, (byte)0x6b,
        (byte)0x65, (byte)0x79, (byte)0x0};
    
//  "Responder ZRTP key"
    public static final byte[] respZrtpKey = {
        (byte)0x52, (byte)0x65, (byte)0x73, (byte)0x70, (byte)0x6f, (byte)0x6e, (byte)0x64, (byte)0x65,
        (byte)0x72, (byte)0x20, (byte)0x5a, (byte)0x52, (byte)0x54, (byte)0x50, (byte)0x20, (byte)0x6b,
        (byte)0x65, (byte)0x79, (byte)0x0};

//  "SAS"
    public static final byte[] sasString = {
        (byte)0x53, (byte)0x41, (byte)0x53, (byte)0x0};

//  "ZRTP-HMAC-KDF"
    public static final byte[] KDFString = {
        (byte)0x5a, (byte)0x52, (byte)0x54, (byte)0x50, (byte)0x2d, (byte)0x48, (byte)0x4d, (byte)0x41,
        (byte)0x43, (byte)0x2d, (byte)0x4b, (byte)0x44, (byte)0x46};

//  "ZRTP Session Key"
    public static final byte[] zrtpSessionKey = {
        (byte)0x5a, (byte)0x52, (byte)0x54, (byte)0x50, (byte)0x20, (byte)0x53, (byte)0x65, (byte)0x73,
        (byte)0x73, (byte)0x69, (byte)0x6f, (byte)0x6e, (byte)0x20, (byte)0x4b, (byte)0x65, (byte)0x79,
        (byte)0x0};

//  "ZRTP MSK"
    public static final byte[] zrtpMsk = {
        (byte)0x5a, (byte)0x52, (byte)0x54, (byte)0x50, (byte)0x20, (byte)0x4d, (byte)0x53, (byte)0x4b,
        (byte)0x0};

    /**
     * The names of the algorithms as defined in ZRTP specification
     * 
     * The arrays are sorted: the most secure / best algorithm is first in the
     * array. If we add an algorithm here then we need to adjust the corresponding
     * value in ZrtpTextData.h as well.
     */

    public static final byte[] s256 = {
        (byte)0x53, (byte)0x32, (byte)0x35, (byte)0x36};        // "S256"
    public static final byte[] aes3 = {
        (byte)0x41, (byte)0x45, (byte)0x53, (byte)0x33};        // "AES3"
    public static final byte[] aes1 = {
        (byte)0x41, (byte)0x45, (byte)0x53, (byte)0x31};        // "AES1"
    public static final byte[] dh4k = {
        (byte)0x44, (byte)0x48, (byte)0x34, (byte)0x6b};        // "DH4k"
    public static final byte[] dh3k = {
        (byte)0x44, (byte)0x48, (byte)0x33, (byte)0x6b};        // "DH3k"
    public static final byte[] dh2k = {
        (byte)0x44, (byte)0x48, (byte)0x32, (byte)0x6b};        // "DH2k"
    public static final byte[] mult = {
        (byte)0x4D, (byte)0x75, (byte)0x6c, (byte)0x74};        // "Mult"
    public static final byte[] b32 = {
        (byte)0x42, (byte)0x33, (byte)0x32, (byte)0x20};        // "B32 "
    public static final byte[] hs32 = {
        (byte)0x48, (byte)0x53, (byte)0x33, (byte)0x32};        // "HS32"
    public static final byte[] hs80 = {
        (byte)0x48, (byte)0x53, (byte)0x38, (byte)0x30};        // "HS80"

    // Keep the Hash identifers in supportedHashes in the same order than the
    // following enum, starting with zero.
   public static enum  SupportedHashes {
        S256(0, s256),
        END(0, null);
        // NumSupportedHashes(1, null);
        
        public int value;
        public byte[] name;
        private SupportedHashes(int val, byte[] nm) {
            value = val;
            name = nm;
        }
    }
    // Keep the Cipher identifers in supportedCipher in the same order than the
    // following enum, starting with zero.
    public static enum SupportedSymCiphers {
        AES3(0, aes3),
        AES1(1, aes1),
        END(0, null);
        // NumSupportedSymCiphers(2, null);
        
        public int value;
        public byte[] name;
        private SupportedSymCiphers(int val, byte[] nm) {
            value = val;
            name = nm;
        }
    }

    // Keep the PubKey identifers in supportedPubKey in the same order than the
    // following enum, starting with zero.
    public static enum SupportedPubKeys {
        DH3K(0, dh3k),
        MULT(1, mult),
        // DH2K(2, dh2k)
        END(0, null);
        // NumSupportedPubKeys(1);
        
        public int value;
        public byte[] name;
        private SupportedPubKeys(int val, byte[] nm) {
            value = val;
            name = nm;
        }
    }

    // Keep the SAS identifers in supportedSASType in the same order than the
    // following enum, starting with zero.
    public static enum SupportedSASTypes {
        B32(0, b32),
        END(0, null);
        // NumSupportedSASTypes(1);
        
        public int value;
        public byte[] name;
        private SupportedSASTypes(int val, byte[] nm) {
            value = val;
            name = nm;
        }
    }

    // Keep the auth len identifers in supportedAuthLen in the same order than the
    // following enum, starting with zero.
    public static enum SupportedAuthLengths {
        HS32(0, hs32),
        HS80(1, hs80),
        END(0, null);
        // NumSupportedAuthLengths(2);
        
        public int value;
        public byte[] name;
        private SupportedAuthLengths(int val, byte[] nm) {
            value = val;
            name = nm;
        }
    }

    
    // The Diffie-Helman constants as defined in the ZRTP specification
    // The DH prime for DH2k (2048 bit) as defined in RFC 3526
    public static final BigInteger P2048 = new BigInteger(
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
    "15728E5A8AACAA68FFFFFFFFFFFFFFFF", 16);                    // Total = 16 + 24 * 10 = 256
    
   
    // The DH prime for DH3k (3072 bit) as defined in RFC 3526
    public static final BigInteger P3072 = new BigInteger(
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

    // The DH prime for DH4k (4096 bit) as defined in RFC 3526
    public static final BigInteger P4096 = new BigInteger(
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
    "43DB5BFCE0FD108E4B82D120A92108011A723C12A787E6D7" +        // 15
    "88719A10BDBA5B2699C327186AF4E23C1A946834B6150BDA" +        // 16
    "2583E9CA2AD44CE8DBBBC2DB04DE8EF92E8EFC141FBECAA6" +        // 17
    "287C59474E6BC05D99B2964FA090C3A2233BA186515BE7ED" +        // 18
    "1F612970CEE2D7AFB81BDD762170481CD0069127D5B05AA9" +        // 19
    "93B4EA988D8FDDC186FFB7DC90A6C08F4DF435C934063199" +        // 20
    "FFFFFFFFFFFFFFFF", 16);                                    // Total = 8 + 24 * 21 = 512 

    // DH generator 2
    public static final BigInteger two = new BigInteger("2");
    
    public static final BigInteger P2048MinusOne = P2048.subtract(BigInteger.ONE);
    public static final BigInteger P3072MinusOne = P3072.subtract(BigInteger.ONE);
    public static final BigInteger P4096MinusOne = P4096.subtract(BigInteger.ONE);
    

    public static final DHParameterSpec specDh2k = new DHParameterSpec(ZrtpConstants.P2048, ZrtpConstants.two, 128);
    public static final DHParameterSpec specDh3k = new DHParameterSpec(ZrtpConstants.P3072, ZrtpConstants.two, 256);
    public static final DHParameterSpec specDh4k = new DHParameterSpec(ZrtpConstants.P4096, ZrtpConstants.two, 512);


    
    public static void main(String argv[]) {
        System.err.println("SHA enum: " + SupportedHashes.valueOf("S256"));
        System.err.println("SHA enum: " + SupportedHashes.valueOf("S256").value);
    }
}

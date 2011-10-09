package demo;

import java.util.Arrays;

import gnu.java.zrtp.jmf.transform.RawPacket;
import gnu.java.zrtp.jmf.transform.srtp.SRTCPCryptoContext;
import gnu.java.zrtp.jmf.transform.srtp.SRTPPolicy;
import gnu.java.zrtp.utils.ZrtpUtils;

public class SrtcpTest {

/*
 * Use input and output data from libsrtp test program to check 
 * this SRTCP implementation. 
 * 
 * Call test program:  srtp_driver -v -d driver
 * 
testing srtp_protect_rtcp and srtp_unprotect_rtcp
# SSRC:          any outbound
# rtp cipher:    aes integer counter mode
# rtp auth:      hmac sha-1 authentication function
# rtp services:  confidentiality and authentication
# rtcp cipher:   aes integer counter mode
# rtcp auth:     hmac sha-1 authentication function
# rtcp services: confidentiality and authentication

driver: before protection:
    (s)rtp packet: {
       version:     2
       p:           0
       x:           0
       cc:          0
       m:           0
       pt:          f
       seq:         3412
       ts:          adfbcade
       ssrc:        adfbcade
       data:        abababababababababababababababab
    } (28 octets in total)

driver: reference packet before protection:
800f1234decafbaddecafbadabababababababababababababababab
driver: after protection:
    (s)rtp packet: {
       version:     2
       p:           0
       x:           0
       cc:          0
       m:           0
       pt:          f
       seq:         3412
       ts:          adfbcade
       ssrc:        6c0d7ec
       data:        a6112bc8ed4a89ebed926c377bebf88180000001572f590a467b63731576
    } (42 octets in total)

driver: after protection:
800f1234decafbadecd7c006a6112bc8ed4a89ebed926c377bebf88180000001572f590a467b63731576
*/

    // Master key and master salt copied from SRTCP test program, also the policy settings.
    public static byte[] masterKey = {
        (byte)0xe1, (byte)0xf9, (byte)0x7a, (byte)0x0d, (byte)0x3e, (byte)0x01, (byte)0x8b, (byte)0xe0,
        (byte)0xd6, (byte)0x4f, (byte)0xa3, (byte)0x2c, (byte)0x06, (byte)0xde, (byte)0x41, (byte)0x39 };

    public static byte[] masterSalt = {
        (byte)0x0e, (byte)0xc6, (byte)0x75, (byte)0xad, (byte)0x49, (byte)0x8a, (byte)0xfe, (byte)0xeb,
        (byte)0xb6, (byte)0x96, (byte)0x0b, (byte)0x3a, (byte)0xab, (byte)0xe6 };

    public static byte[] srtp_plaintext_ref = {
        (byte)0x80, (byte)0x0f, (byte)0x12, (byte)0x34, (byte)0xde, (byte)0xca, (byte)0xfb, (byte)0xad,
        (byte)0xde, (byte)0xca, (byte)0xfb, (byte)0xad, (byte)0xab, (byte)0xab, (byte)0xab, (byte)0xab,
        (byte)0xab, (byte)0xab, (byte)0xab, (byte)0xab, (byte)0xab, (byte)0xab, (byte)0xab, (byte)0xab,
        (byte)0xab, (byte)0xab, (byte)0xab, (byte)0xab };

    public static byte[] srtp_ciphertext_ref = {
        (byte)0x80, (byte)0x0f, (byte)0x12, (byte)0x34, (byte)0xde, (byte)0xca, (byte)0xfb, (byte)0xad, 
        (byte)0xec, (byte)0xd7, (byte)0xc0, (byte)0x06, (byte)0xa6, (byte)0x11, (byte)0x2b, (byte)0xc8,
        (byte)0xed, (byte)0x4a, (byte)0x89, (byte)0xeb, (byte)0xed, (byte)0x92, (byte)0x6c, (byte)0x37,
        (byte)0x7b, (byte)0xeb, (byte)0xf8, (byte)0x81, (byte)0x80, (byte)0x00, (byte)0x00, (byte)0x01, 
        (byte)0x57, (byte)0x2f, (byte)0x59, (byte)0x0a, (byte)0x46, (byte)0x7b, (byte)0x63, (byte)0x73,
        (byte)0x15, (byte)0x76 };
    
    
    public static void main(String[] args) {

        SRTPPolicy srtcpPolicy = new SRTPPolicy(SRTPPolicy.AESCM_ENCRYPTION, 
                16,                     // keylength
                SRTPPolicy.HMACSHA1_AUTHENTICATION, 
                16,                     // auth tag key length 
                10,                     // auth tag length to send in packet
                14);                    // salt length

        byte[] buffer = new byte[srtp_plaintext_ref.length];

        SRTCPCryptoContext ctx = new SRTCPCryptoContext(0, masterKey, masterSalt, srtcpPolicy);
        ctx.deriveSrtcpKeys();

        // This first encryption (transform) is performed to bumb the squence
        // counter to 1. libsrtp increments the sequence counter _before it 
        // uses it. This is not according to RFC 3711, chap 3.4, description 
        // of SRTCP index.
        System.arraycopy(srtp_plaintext_ref, 0, buffer, 0, buffer.length);
        RawPacket pkt = new RawPacket(buffer, 0, buffer.length);
        ctx.transformPacket(pkt);
        
        System.arraycopy(srtp_plaintext_ref, 0, buffer, 0, buffer.length);
        pkt = new RawPacket(buffer, 0, buffer.length);
                
        ctx.transformPacket(pkt);

        if (srtp_ciphertext_ref.length != pkt.getLength() ||
                ZrtpUtils.byteArrayCompare(srtp_ciphertext_ref, pkt.getBuffer(), srtp_ciphertext_ref.length) != 0) {
            System.out.println("Error during SRTCP protect: length: " + pkt.getLength());
            ZrtpUtils.hexdump("cipher text expected", srtp_ciphertext_ref, srtp_ciphertext_ref.length);
            ZrtpUtils.hexdump("cipher text computed", pkt.getBuffer(), pkt.getLength());
        }

        ctx.reverseTransformPacket(pkt);
        
        
        if (srtp_plaintext_ref.length != pkt.getLength() ||
                ZrtpUtils.byteArrayCompare(srtp_plaintext_ref, pkt.getBuffer(), srtp_plaintext_ref.length) != 0) {
            System.out.println("Error during SRTCP unprotect: length: " + pkt.getLength());
            ZrtpUtils.hexdump("plaintext expected", srtp_plaintext_ref, srtp_plaintext_ref.length);
            ZrtpUtils.hexdump("plaintext computed", pkt.getBuffer(), pkt.getLength());
        }
        System.out.println("SRTCP test done");
        System.exit(0);
    }

}

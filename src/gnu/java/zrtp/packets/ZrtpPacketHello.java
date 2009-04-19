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

package gnu.java.zrtp.packets;

import gnu.java.zrtp.ZrtpConstants;
import gnu.java.zrtp.utils.ZrtpUtils;

import java.io.UnsupportedEncodingException;
import java.util.Arrays;

/**
 * Implement the Hello packet.
 *
 * The ZRTP message Hello. The implementation sends this
 * to start the ZRTP negotiation sequence. The Hello message
 * offers crypto methods and parameters to the other party. The
 * other party selects methods and parameters it can support
 * and uses the Commit message to commit these.

 * @author Werner Dittmann <Werner.Dittmann@t-online.de>
 *
 */

public class ZrtpPacketHello extends ZrtpPacketBase {
    
    // private boolean passive;
    // number of the algorithms
    private final int nHash, nCipher, nPubkey, nSas, nAuth;
    
    // offsets in bytes into hello packet where algo names are stored
    private final int oHash, oCipher, oPubkey, oSas, oAuth, oHmac;

    /*
     * The length of the Hello specific ZRTP packet part in words
     */
    private static final int ZRTP_HELLO_FIX_LENGTH = 17;
    
    /*
     * Now the Hello packet specific offsets into the packet buffer. They
     * all start after ZRTP_HEADER_LENGTH and a given in bytes, not ZRTP
     * words.
     */
    private static final int VERSION_OFFSET = ZRTP_HEADER_LENGTH * ZRTP_WORD_SIZE;   // [ZRTP_WORD_SIZE]
    private static final int CLIENT_ID_OFFSET = VERSION_OFFSET + ZRTP_WORD_SIZE;     // [4*ZRTP_WORD_SIZE]
    private static final int HASH_H3_OFFSET = CLIENT_ID_OFFSET + 4*ZRTP_WORD_SIZE;   // [8*ZRTP_WORD_SIZE]
    private static final int ZID_OFFSET = HASH_H3_OFFSET + 8*ZRTP_WORD_SIZE;         // [3*ZRTP_WORD_SIZE]
    private static final int FLAG_LENGTH_OFFSET = ZID_OFFSET + 3*ZRTP_WORD_SIZE;     // [ZRTP_WORD_SIZE]
    private static final int VARIABLE_OFFSET = FLAG_LENGTH_OFFSET + ZRTP_WORD_SIZE;

    /*
     * The length of the Hello packet in bytes. The length is variable.
     */
    private int helloLength = 
            (ZRTP_HEADER_LENGTH + ZRTP_HELLO_FIX_LENGTH) * ZRTP_WORD_SIZE + CRC_SIZE;

    public ZrtpPacketHello() {
        super(null);                        // will set packet buffer explicitly

        nHash = ZrtpConstants.SupportedHashes.values().length - 1;
        nCipher = ZrtpConstants.SupportedSymCiphers.values().length - 1;
        nPubkey = ZrtpConstants.SupportedPubKeys.values().length - 1;
        nSas = ZrtpConstants.SupportedSASTypes.values().length - 1;
        nAuth = ZrtpConstants.SupportedAuthLengths.values().length - 1;

        // length is fixed length plus HMAC size (2*ZRTP_WORD_SIZE)
        helloLength += (2 * ZRTP_WORD_SIZE);
        helloLength += nHash * ZRTP_WORD_SIZE;
        helloLength += nCipher * ZRTP_WORD_SIZE;
        helloLength += nPubkey * ZRTP_WORD_SIZE;
        helloLength += nSas * ZRTP_WORD_SIZE;
        helloLength += nAuth * ZRTP_WORD_SIZE;
        
        packetBuffer = new byte[helloLength];
        Arrays.fill(packetBuffer, (byte)0);

        oHash = VARIABLE_OFFSET;
        oCipher = oHash + (nHash * ZRTP_WORD_SIZE);
        oAuth = oCipher + (nCipher * ZRTP_WORD_SIZE);
        oPubkey = oAuth + (nAuth * ZRTP_WORD_SIZE);
        oSas = oPubkey + (nPubkey * ZRTP_WORD_SIZE);
        oHmac = oSas + (nSas * ZRTP_WORD_SIZE);         // offset to HMAC

        setZrtpId();

        // minus 1: CRC size does not count in packet length field 
        setLength((helloLength / ZRTP_WORD_SIZE) - 1);
        setMessageType(ZrtpConstants.HelloMsg);

        setVersion(ZrtpConstants.zrtpVersion);

        packetBuffer[FLAG_LENGTH_OFFSET] = (byte)0;  // Passive flag if required
        
        packetBuffer[FLAG_LENGTH_OFFSET+1] = (byte)(nHash);
        for (ZrtpConstants.SupportedHashes sh: ZrtpConstants.SupportedHashes.values()) {
            if (sh == ZrtpConstants.SupportedHashes.END) {
                break;
            }
            setHashType(sh.value, sh.name);
        }

        packetBuffer[FLAG_LENGTH_OFFSET+2] = (byte)(nCipher << 4);
        for (ZrtpConstants.SupportedSymCiphers sh: ZrtpConstants.SupportedSymCiphers.values()) {
            if (sh == ZrtpConstants.SupportedSymCiphers.END) {
                break;
            }
            setCipherType(sh.value, sh.name);
        }

        packetBuffer[FLAG_LENGTH_OFFSET+2] |= (byte)(nAuth);
        for (ZrtpConstants.SupportedAuthLengths sh: ZrtpConstants.SupportedAuthLengths.values()) {
            if (sh == ZrtpConstants.SupportedAuthLengths.END) {
                break;
            }
            setAuthLen(sh.value, sh.name);
        }

        packetBuffer[FLAG_LENGTH_OFFSET+3] = (byte)(nPubkey << 4);
        for (ZrtpConstants.SupportedPubKeys sh: ZrtpConstants.SupportedPubKeys.values()) {
            if (sh == ZrtpConstants.SupportedPubKeys.END) {
                break;
            }
            setPubKeyType(sh.value, sh.name);
        }

        packetBuffer[FLAG_LENGTH_OFFSET+3] |= (byte)(nSas);
        for (ZrtpConstants.SupportedSASTypes sh: ZrtpConstants.SupportedSASTypes.values()) {
            if (sh == ZrtpConstants.SupportedSASTypes.END) {
                break;
            }
            setSasType(sh.value, sh.name);
        }
    }

    public ZrtpPacketHello(final byte[] data) {
        super(data);
        
        int temp = packetBuffer[FLAG_LENGTH_OFFSET];    // check for passive flag (0x10)

        temp = packetBuffer[FLAG_LENGTH_OFFSET+1];      // contains hash counter on low 4 bits
        nHash = temp & 0xf;
        
        temp = packetBuffer[FLAG_LENGTH_OFFSET+2];      // contains cipher cnt on high 4 bits, auth cnt on low        
        nCipher = (temp & 0xf0) >> 4;
        nAuth = temp & 0xf;
        temp = packetBuffer[FLAG_LENGTH_OFFSET+3];      // contains key agreement cnt on high 4 bits, sas cnt on low        
        nPubkey = (temp & 0xf0) >> 4;
        nSas = temp & 0xf;

        oHash = VARIABLE_OFFSET;
        oCipher = oHash + (nHash * ZRTP_WORD_SIZE);
        oAuth = oCipher + (nCipher * ZRTP_WORD_SIZE);
        oPubkey = oAuth + (nAuth * ZRTP_WORD_SIZE);
        oSas = oPubkey + (nPubkey * ZRTP_WORD_SIZE);
        oHmac = oSas + (nSas * ZRTP_WORD_SIZE);         // offset to HMAC
    }

    public final void setClientId(final String text) {
        byte[] data = null;
        try {
            data = text.getBytes("UTF-8");
        } catch (UnsupportedEncodingException e) {
            data = ZrtpConstants.clientId.getBytes();
        }
        int length = (data.length > 4*ZRTP_WORD_SIZE)? (4*ZRTP_WORD_SIZE) : data.length;
        System.arraycopy(data, 0, packetBuffer, CLIENT_ID_OFFSET, length);
    }
    
    public final void setH3(final byte[] data)          { 
        System.arraycopy(data, 0, packetBuffer, HASH_H3_OFFSET, 8*ZRTP_WORD_SIZE);
    }
    
    public final byte[] getH3() {
        return ZrtpUtils.readRegion(packetBuffer, HASH_H3_OFFSET, 8*ZRTP_WORD_SIZE);
    }

    public final void setZid(final byte[] data)         { 
        System.arraycopy(data, 0, packetBuffer, ZID_OFFSET, 3*ZRTP_WORD_SIZE);
    }

    public final byte[] getZid() {
        return ZrtpUtils.readRegion(packetBuffer, ZID_OFFSET, 3*ZRTP_WORD_SIZE);
    }

    public final void setVersion(final byte[] data) {
        System.arraycopy(data, 0, packetBuffer, VERSION_OFFSET, ZRTP_WORD_SIZE);
    }

    public final void setHashType(final int n, final byte[] data) {
        System.arraycopy(data, 0, packetBuffer, oHash+(n*ZRTP_WORD_SIZE), ZRTP_WORD_SIZE);
    }
    
    public final void setCipherType(final int n, final byte[] data) {
        System.arraycopy(data, 0, packetBuffer, oCipher+(n*ZRTP_WORD_SIZE), ZRTP_WORD_SIZE);
    }

    public final void setAuthLen(final int n, final byte[] data) {
        System.arraycopy(data, 0, packetBuffer, oAuth+(n*ZRTP_WORD_SIZE), ZRTP_WORD_SIZE);
    }

    public final void setPubKeyType(final int n, final byte[] data) {
        System.arraycopy(data, 0, packetBuffer, oPubkey+(n*ZRTP_WORD_SIZE), ZRTP_WORD_SIZE);
    }
    
    public final void setSasType(final int n, final byte[] data) {
        System.arraycopy(data, 0, packetBuffer, oSas+(n*ZRTP_WORD_SIZE), ZRTP_WORD_SIZE);
    }
    
    public final void setHMAC(final byte[] data) {
        System.arraycopy(data, 0, packetBuffer, oHmac, 2*ZRTP_WORD_SIZE);
    }
    
    /**
     * Check if version data matches.
     * 
     * @param data The data to compare against.
     * @return true if data matches the packet version data, false other wise.
     */
    public final boolean isSameVersion(final byte[] data) {
        for (int i = 0; i < ZRTP_WORD_SIZE; i++) {
            if (packetBuffer[VERSION_OFFSET+i] != data[i]) {
                return false;
            }
        }
        return true;
    }
    
    /**
     * Find matching algorithms in Hello packet.
     * 
     * The next functions look up and return a prefered algorithm. These
     * functions work as follows:
     * - If the Hello packet does not contain an algorithm (number of algorithms is
     *   zero) then return our prefered algorithm. This prefered algorithm must be
     *   one of the mandatory algorithms specified in chapter 6.1.x.
     * - If the functions find a match return the found algorithm.
     * - If the functions do not find a match return a prefered, mandatory
     *   algorithm.
     * This guarantees that we always return a supported alogrithm.
     *
     * The mandatory algorithms are: (internal enums are our prefered algoritms)
     * Hash:                S256 (SHA 256)             (internal enum Sha256)
     * Symmetric Cipher:    AES1 (AES 128)             (internal enum Aes128)
     * SRTP Authentication: HS32 and HS80 (32/80 bits) (internal enum AuthLen32)
     * Key Agreement:       DH3k (3072 Diffie-Helman)  (internal enum Dh3072)
     *
     * Find macthing Hash type.
     * 
     * @return found matching hash or default SHA 256.
     */
    public final ZrtpConstants.SupportedHashes findBestHash() {
        if (nHash == 0)
            return ZrtpConstants.SupportedHashes.S256;
        
        for (ZrtpConstants.SupportedHashes sh: ZrtpConstants.SupportedHashes.values()) {
            if (sh == ZrtpConstants.SupportedHashes.END) {
                break;
            }
            byte[] s = sh.name;
            for (int ii = 0; ii < nHash; ii++) {
                int o = oHash + (ii*ZRTP_WORD_SIZE);
                if (s[0] == packetBuffer[o] && s[1] == packetBuffer[o+1] &&
                        s[2] == packetBuffer[o+2] && s[3] == packetBuffer[o+3]) {
                    return sh;
                }
            }
        }
        return ZrtpConstants.SupportedHashes.S256;
    }

    public final ZrtpConstants.SupportedSymCiphers findBestCipher() {
        if (nCipher == 0)
            return ZrtpConstants.SupportedSymCiphers.AES1;
        
        for (ZrtpConstants.SupportedSymCiphers sh: ZrtpConstants.SupportedSymCiphers.values()) {
            if (sh == ZrtpConstants.SupportedSymCiphers.END) {
                break;
            }
           byte[] s = sh.name;
            for (int ii = 0; ii < nCipher; ii++) {
                int o = oCipher + (ii*ZRTP_WORD_SIZE);
                if (s[0] == packetBuffer[o] && s[1] == packetBuffer[o+1] &&
                        s[2] == packetBuffer[o+2] && s[3] == packetBuffer[o+3]) {
                    return sh;
                }
            }
        }
        return ZrtpConstants.SupportedSymCiphers.AES1;
    }
    
    public final ZrtpConstants.SupportedPubKeys findBestPubkey() {
        if (nPubkey == 0)
            return ZrtpConstants.SupportedPubKeys.DH3K;
        
        for (ZrtpConstants.SupportedPubKeys sh: ZrtpConstants.SupportedPubKeys.values()) {
            if (sh == ZrtpConstants.SupportedPubKeys.END) {
                break;
            }
            byte[] s = sh.name;
            for (int ii = 0; ii < nPubkey; ii++) {
                int o = oPubkey + (ii*ZRTP_WORD_SIZE);
                if (s[0] == packetBuffer[o] && s[1] == packetBuffer[o+1] &&
                        s[2] == packetBuffer[o+2] && s[3] == packetBuffer[o+3]) {
                    return sh;
                }
            }
        }
        return ZrtpConstants.SupportedPubKeys.DH3K;
    }

    public final ZrtpConstants.SupportedSASTypes findBestSASType() {
        if (nSas == 0)
            return ZrtpConstants.SupportedSASTypes.B32;
        
        for (ZrtpConstants.SupportedSASTypes sh: ZrtpConstants.SupportedSASTypes.values()) {
            if (sh == ZrtpConstants.SupportedSASTypes.END) {
                break;
            }
            byte[] s = sh.name;
            for (int ii = 0; ii < nSas; ii++) {
                int o = oSas + (ii*ZRTP_WORD_SIZE);
                if (s[0] == packetBuffer[o] && s[1] == packetBuffer[o+1] &&
                        s[2] == packetBuffer[o+2] && s[3] == packetBuffer[o+3]) {
                    return sh;
                }
            }
        }
        return ZrtpConstants.SupportedSASTypes.B32;
    }

    public final ZrtpConstants.SupportedAuthLengths findBestAuthLen() {
        if (nAuth == 0)
            return ZrtpConstants.SupportedAuthLengths.HS32;
        
        for (ZrtpConstants.SupportedAuthLengths sh: ZrtpConstants.SupportedAuthLengths.values()) {
            if (sh == ZrtpConstants.SupportedAuthLengths.END) {
                break;
            }
            byte[] s = sh.name;
            for (int ii = 0; ii < nAuth; ii++) {
                int o = oAuth + (ii*ZRTP_WORD_SIZE);
                if (s[0] == packetBuffer[o] && s[1] == packetBuffer[o+1] &&
                        s[2] == packetBuffer[o+2] && s[3] == packetBuffer[o+3]) {
                    return sh;
                }
            }
        }
        return ZrtpConstants.SupportedAuthLengths.HS32;
    }

    public final boolean checkMultiStream() {
        // Multi Stream mode is mandatory, thus if nothing is offered then it is
        // supported :-)
        if (nPubkey == 0)
            return true;

        byte[] s = ZrtpConstants.SupportedPubKeys.MULT.name;
        // Loop over offer pub key data
        for (int ii = 0; ii < nPubkey; ii++) {
            int o = oPubkey + (ii * ZRTP_WORD_SIZE);
            if (s[0] == packetBuffer[o] && s[1] == packetBuffer[o + 1]
                    && s[2] == packetBuffer[o + 2]
                    && s[3] == packetBuffer[o + 3]) {
                return true;
            }
        }
        return false;
    }
    
    public final int getNAuth() {
        return nAuth;
    }

    public final int getNCipher() {
        return nCipher;
    }

    public final int getNHash() {
        return nHash;
    }

    public final int getNPubkey() {
        return nPubkey;
    }

    public final int getNSas() {
        return nSas;
    }

    /* ***
    public static void main(String[] args) {
        ZrtpPacketHello pkt = new ZrtpPacketHello();
        System.err.println("Hello length: " + pkt.getLength());
        
        System.err.println("packetBuffer length in bytes: " + pkt.getHeaderBase().length);

        byte[] data= {1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,27,28,29,30,31,32};
        pkt.setZid(data);

        ZrtpUtils.hexdump("Hello packet", pkt.getHeaderBase(), pkt.getHeaderBase().length);
        System.err.println("best pubkey: " + pkt.findBestPubkey());
    }
    **** */
}

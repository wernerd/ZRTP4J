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

/**
 * Implement the Commit packet.
 *
 * The ZRTP message Commit. The ZRTP implementation sends or receives
 * this message to commit the crypto parameters offered during a Hello
 * message.
 *

 * @author Werner Dittmann <Werner.Dittmann@t-online.de>
 *
 */
public class ZrtpPacketCommit extends ZrtpPacketBase {
    
    /*
     * The number of the commit specific ZRTP part in words
     */
    private static final int ZRTP_COMMIT_LENGTH = 26;

    /*
     * Now the commit packet specific offsets into the packet buffer. They
     * all start after ZRTP_HEADER_LENGTH and a given in bytes, not ZRTP
     * words.
     */
    private static final int HASH_H2_OFFSET = ZRTP_HEADER_LENGTH * ZRTP_WORD_SIZE; // [8*ZRTP_WORD_SIZE];
    private static final int ZID_OFFSET = HASH_H2_OFFSET + 8*ZRTP_WORD_SIZE;       // [3*ZRTP_WORD_SIZE];
    private static final int HASH_OFFSET = ZID_OFFSET + 3*ZRTP_WORD_SIZE;          // [ZRTP_WORD_SIZE];
    private static final int CIPHER_OFFSET = HASH_OFFSET + ZRTP_WORD_SIZE;         // [ZRTP_WORD_SIZE];
    private static final int AUTHLENGTHS_OFFSET = CIPHER_OFFSET + ZRTP_WORD_SIZE;  // [ZRTP_WORD_SIZE];
    private static final int PUBKEY_OFFSET = AUTHLENGTHS_OFFSET + ZRTP_WORD_SIZE;  // [ZRTP_WORD_SIZE];
    private static final int SAS_OFFSET = PUBKEY_OFFSET + ZRTP_WORD_SIZE;          // [ZRTP_WORD_SIZE];
    private static final int HVI_OFFSET = SAS_OFFSET + ZRTP_WORD_SIZE;             // [8*ZRTP_WORD_SIZE];
    private static final int HMAC_OFFSET = HVI_OFFSET + 8*ZRTP_WORD_SIZE;          // [2*ZRTP_WORD_SIZE];

    /*
     * A complete Commit packet has a total length in bytes of:
     */
    private static final int COMMIT_LENGTH = 
        (ZRTP_HEADER_LENGTH + ZRTP_COMMIT_LENGTH) * ZRTP_WORD_SIZE + CRC_SIZE;
    
    
    public ZrtpPacketCommit() {
        super(new byte[COMMIT_LENGTH]);
        setZrtpId();
        
        // The length field of a ZRTP packet does not include the CRC field.
        // the length is given in number of ZRTP words.
        setLength(ZRTP_HEADER_LENGTH + ZRTP_COMMIT_LENGTH);
        setMessageType(ZrtpConstants.CommitMsg);
    }
    
    public ZrtpPacketCommit(byte[] data) {
        super(data);
    }
 
    public byte[] getHashType() {
        byte[] arr = ZrtpUtils.readRegion(packetBuffer, HASH_OFFSET, ZRTP_WORD_SIZE);
        return arr;
    }
    
    public ZrtpConstants.SupportedHashes getHash() {

        for (ZrtpConstants.SupportedHashes sh : ZrtpConstants.SupportedHashes
                .values()) {
            byte[] s = sh.name;
            int o = HASH_OFFSET;
            if (s[0] == packetBuffer[o] && s[1] == packetBuffer[o + 1]
                    && s[2] == packetBuffer[o + 2]
                    && s[3] == packetBuffer[o + 3]) {
                return sh;
            }
        }
        return ZrtpConstants.SupportedHashes.END;
    }

    public byte[] getCipherType()  { 
        byte[] arr = ZrtpUtils.readRegion(packetBuffer, CIPHER_OFFSET, ZRTP_WORD_SIZE);
        return arr;
    }

    public ZrtpConstants.SupportedSymCiphers getCipher() {

        for (ZrtpConstants.SupportedSymCiphers sh : ZrtpConstants.SupportedSymCiphers
                .values()) {
            if (sh == ZrtpConstants.SupportedSymCiphers.END)
                break;
            byte[] s = sh.name;
            int o = CIPHER_OFFSET;
            if (s[0] == packetBuffer[o] 
                    && s[1] == packetBuffer[o + 1]
                    && s[2] == packetBuffer[o + 2]
                    && s[3] == packetBuffer[o + 3]) {
                return sh;
            }
        }
        return ZrtpConstants.SupportedSymCiphers.END;
    }
        
    public byte[] getAuthLenType()     { 
        byte[] arr = ZrtpUtils.readRegion(packetBuffer, AUTHLENGTHS_OFFSET, ZRTP_WORD_SIZE);
        return arr;
    }

    public ZrtpConstants.SupportedAuthLengths getAuthlen() {

        for (ZrtpConstants.SupportedAuthLengths sh : ZrtpConstants.SupportedAuthLengths
                .values()) {
            byte[] s = sh.name;
            int o = AUTHLENGTHS_OFFSET;
            if (s[0] == packetBuffer[o] && s[1] == packetBuffer[o + 1]
                    && s[2] == packetBuffer[o + 2]
                    && s[3] == packetBuffer[o + 3]) {
                return sh;
            }
        }
        return ZrtpConstants.SupportedAuthLengths.END;
    }

    public byte[] getPubKeysType() { 
        byte[] arr = ZrtpUtils.readRegion(packetBuffer, PUBKEY_OFFSET, ZRTP_WORD_SIZE);
        return arr;
    }
       
    public ZrtpConstants.SupportedPubKeys getPubKey() {

        for (ZrtpConstants.SupportedPubKeys sh : ZrtpConstants.SupportedPubKeys
                .values()) {
            byte[] s = sh.name;
            int o = PUBKEY_OFFSET;
            if (s[0] == packetBuffer[o] && s[1] == packetBuffer[o + 1]
                    && s[2] == packetBuffer[o + 2]
                    && s[3] == packetBuffer[o + 3]) {
                return sh;
            }
                    }
        return ZrtpConstants.SupportedPubKeys.END;
    }
        
    public byte[] getSasType() {
        byte[] arr = ZrtpUtils.readRegion(packetBuffer, SAS_OFFSET, ZRTP_WORD_SIZE);
        return arr;
    }
        
    public ZrtpConstants.SupportedSASTypes getSas() {

        for (ZrtpConstants.SupportedSASTypes sh : ZrtpConstants.SupportedSASTypes
                .values()) {
            byte[] s = sh.name;
            int o = SAS_OFFSET;
            if (s[0] == packetBuffer[o] && s[1] == packetBuffer[o + 1]
                    && s[2] == packetBuffer[o + 2]
                    && s[3] == packetBuffer[o + 3]) {
                return sh;
            }
        }
        return ZrtpConstants.SupportedSASTypes.END;
    }

    public byte[] getZid() {
        byte[] arr = ZrtpUtils.readRegion(packetBuffer, ZID_OFFSET, 3*ZRTP_WORD_SIZE);
        return arr;
    }
       
    public byte[] getHvi() {
        byte[] arr = ZrtpUtils.readRegion(packetBuffer, HVI_OFFSET, 8*ZRTP_WORD_SIZE);
        return arr;
    }
        
    public byte[] getH2() {
        byte[] arr = ZrtpUtils.readRegion(packetBuffer, HASH_H2_OFFSET, 8*ZRTP_WORD_SIZE);
        return arr;
    }
       
    public byte[] getHMAC() {
        byte[] arr = ZrtpUtils.readRegion(packetBuffer, HMAC_OFFSET, 2*ZRTP_WORD_SIZE);
        return arr;
    }
        
    public void setHashType(byte[] data) {
        System.arraycopy(data, 0, packetBuffer, HASH_OFFSET, ZRTP_WORD_SIZE);
    }

    public void setCipherType(byte[] data) { 
        System.arraycopy(data, 0, packetBuffer, CIPHER_OFFSET, ZRTP_WORD_SIZE);
    }
    
    public void setAuthLen(byte[] data) { 
        System.arraycopy(data, 0, packetBuffer, AUTHLENGTHS_OFFSET, ZRTP_WORD_SIZE);
    }
    
    public void setPubKeyType(byte[] data) { 
        System.arraycopy(data, 0, packetBuffer, PUBKEY_OFFSET, ZRTP_WORD_SIZE);
    }
    
    public void setSasType(byte[] data) { 
        System.arraycopy(data, 0, packetBuffer, SAS_OFFSET, ZRTP_WORD_SIZE);
    }
    
    public void setZid(byte[] data) { 
        System.arraycopy(data, 0, packetBuffer, ZID_OFFSET, 3*ZRTP_WORD_SIZE);
    }
    
    public void setHvi(byte[] data) { 
        System.arraycopy(data, 0, packetBuffer, HVI_OFFSET, 8*ZRTP_WORD_SIZE);
    }
    
    public void setH2(byte[] data) { 
        System.arraycopy(data, 0, packetBuffer, HASH_H2_OFFSET, 8*ZRTP_WORD_SIZE);
    }
    
    public void setHMAC(byte[] data) { 
        System.arraycopy(data, 0, packetBuffer, HMAC_OFFSET, 2*ZRTP_WORD_SIZE);
    }
    
    public static void main(String[] args) {
        ZrtpPacketCommit commit = new ZrtpPacketCommit();
        System.err.println("Commit length: " + commit.getLength());
        System.err.println("packetBuffer length in bytes: " + commit.getHeaderBase().length);

        commit.setHashType(ZrtpConstants.SupportedHashes.S256.name);
        commit.setCipherType(ZrtpConstants.SupportedSymCiphers.AES1.name);
        commit.setAuthLen(ZrtpConstants.SupportedAuthLengths.HS32.name);
        commit.setPubKeyType(ZrtpConstants.SupportedPubKeys.DH3K.name);
        commit.setSasType(ZrtpConstants.SupportedSASTypes.B32.name);

        byte[] data= {1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,27,28,29,30,31,32};
        commit.setHMAC(data);
        data[0] += 1;
        commit.setHvi(data);
        data[0] += 1;
        commit.setZid(data);
        data[0] += 1;
        commit.setH2(data);
        ZrtpUtils.hexdump("Commit packet", commit.getHeaderBase(), commit.getHeaderBase().length);
        
    }
}
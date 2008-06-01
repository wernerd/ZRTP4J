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
 * @author Werner Dittmann <Werner.Dittmann@t-online.de>
 *
 */
public class ZrtpPacketDHPart extends ZrtpPacketBase {
    
    private int dhLength;   // length of DH data (3k or 4k)
    
    /*
     * Now the DHPart packet specific offsets into the packet buffer. They
     * all start after ZRTP_HEADER_LENGTH and a given in bytes, not ZRTP
     * words.
     */
    private static final int HASH_H1_OFFSET = ZRTP_HEADER_LENGTH * ZRTP_WORD_SIZE;       // [8*ZRTP_WORD_SIZE];
    private static final int RS1ID_OFFSET = HASH_H1_OFFSET + 8*ZRTP_WORD_SIZE;           // [2*ZRTP_WORD_SIZE];
    private static final int RS2ID_OFFSET = RS1ID_OFFSET + 2*ZRTP_WORD_SIZE;             // [2*ZRTP_WORD_SIZE];
//    private static final int SIGS_ID_OFFSET = RS2ID_OFFSET + 2*ZRTP_WORD_SIZE;           // [2*ZRTP_WORD_SIZE];
    private static final int S3_ID_OFFSET = RS2ID_OFFSET + 2*ZRTP_WORD_SIZE;          // [2*ZRTP_WORD_SIZE];
    private static final int PBX_SECRET_ID_OFFSET = S3_ID_OFFSET + 2*ZRTP_WORD_SIZE;// [2*ZRTP_WORD_SIZE];
    private static final int PUBLIC_KEY_OFFSET = PBX_SECRET_ID_OFFSET + 2*ZRTP_WORD_SIZE;
    
    /*
     * The number of the fixed DHPacket specific ZRTP fields in words
     */
    private static final int ZRTP_DHPART_FIXED_LENGTH = 16;

    // required bytes to hold the header, the fix part and the CRC
    private static final int DHPART_FIXED_LENGTH = 
        (ZRTP_HEADER_LENGTH + ZRTP_DHPART_FIXED_LENGTH) * ZRTP_WORD_SIZE + CRC_SIZE;

    /**
     * Constructor for a new DHPart message
     * 
     */
    
    public ZrtpPacketDHPart() {
        super(null);
    }

    /**
     * Constructor for a new DHPart message with DH part type.
     * 
     * @param pkt type of DH key agreement to use
     */
    public ZrtpPacketDHPart(ZrtpConstants.SupportedPubKeys pkt) {    // TODO use enum when ready
        super(null);
        setPubKeyType(pkt);
    }

    /**
     * Constructor for DHPart message initialized with received data.
     * 
     * @param data received from the network.
     */
    public ZrtpPacketDHPart(byte[] data) {
        super(data);

        short len = getLength();
        if (len == 117) {
            dhLength = 384;
        }
        else {
            dhLength = 0;
            System.err.println("Wrong DHPart length: " + len);  // TODO throw an exception?
            return;
        }
    }

    public void setPubKeyType(ZrtpConstants.SupportedPubKeys pkt) {
        dhLength = (pkt == ZrtpConstants.SupportedPubKeys.DH3K) ? 384 : 512;
        
        // compute total length of ZRTP message including space for CRC
        int length = DHPART_FIXED_LENGTH + dhLength + (2 * ZRTP_WORD_SIZE);  // HMAC field is 2*ZRTP_WORD_SIZE
        
        // allocate buffer
        packetBuffer = new byte[length];
        
        // Message length does not include CRC
        setLength((length-CRC_SIZE) / ZRTP_WORD_SIZE);
        setZrtpId();
    }

    public byte[] getPv() { 
        return ZrtpUtils.readRegion(packetBuffer, PUBLIC_KEY_OFFSET, dhLength);
    }

    public byte[] getRs1Id() {
        return ZrtpUtils.readRegion(packetBuffer, RS1ID_OFFSET, 2*ZRTP_WORD_SIZE);
    }
        
    public byte[] getRs2Id() { 
        return ZrtpUtils.readRegion(packetBuffer, RS2ID_OFFSET, 2*ZRTP_WORD_SIZE);
    }
        
    public byte[] getS3Id() {
        return ZrtpUtils.readRegion(packetBuffer, S3_ID_OFFSET, 2*ZRTP_WORD_SIZE);
    }

    public byte[] getPbxSecretId() {
        return ZrtpUtils.readRegion(packetBuffer, PBX_SECRET_ID_OFFSET, 2*ZRTP_WORD_SIZE);
    }
        
    public byte[] getH1() { 
        return ZrtpUtils.readRegion(packetBuffer, HASH_H1_OFFSET, 8*ZRTP_WORD_SIZE);
    }

    public byte[] getHMAC() {
        return ZrtpUtils.readRegion(packetBuffer, PUBLIC_KEY_OFFSET+dhLength, 2*ZRTP_WORD_SIZE);
    }

    /**
     * Setter methods.
     *
     */
    
    public void setPv(byte[] data) {
        System.arraycopy(data, 0, packetBuffer, PUBLIC_KEY_OFFSET, dhLength);
    }

    public void setRs1Id(byte[] data) {
        System.arraycopy(data, 0, packetBuffer, RS1ID_OFFSET, 2*ZRTP_WORD_SIZE);
    }
        
    public void setRs2Id(byte[] data) { 
        System.arraycopy(data, 0, packetBuffer, RS2ID_OFFSET, 2*ZRTP_WORD_SIZE);
    }
        
    public void setS3Id(byte[] data) {
        System.arraycopy(data, 0, packetBuffer, S3_ID_OFFSET, 2*ZRTP_WORD_SIZE);
    }

    public void setPbxSecretId(byte[] data) {
        System.arraycopy(data, 0, packetBuffer, PBX_SECRET_ID_OFFSET, 2*ZRTP_WORD_SIZE);
    }
        
    public void setH1(byte[] data) { 
        System.arraycopy(data, 0, packetBuffer, HASH_H1_OFFSET, 8*ZRTP_WORD_SIZE);
    }

    public void setHMAC(byte[] data) {
        System.arraycopy(data, 0, packetBuffer, PUBLIC_KEY_OFFSET+dhLength, 2*ZRTP_WORD_SIZE);
    }

    public static void main(String[] args) {
        ZrtpPacketDHPart pkt = new ZrtpPacketDHPart(ZrtpConstants.SupportedPubKeys.DH3K);
        System.err.println("DHPart length: " + pkt.getLength());
        pkt.setMessageType(ZrtpConstants.DHPart1Msg);

        System.err.println("packetBuffer length in bytes: " + pkt.getHeaderBase().length);
        ZrtpUtils.hexdump("DHPart packet", pkt.getHeaderBase(), pkt.getHeaderBase().length);
    }
}

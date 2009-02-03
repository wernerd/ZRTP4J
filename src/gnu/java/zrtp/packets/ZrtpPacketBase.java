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

import gnu.java.zrtp.utils.ZrtpUtils;

/**
 * This is the base class for all ZRTP packets
 *
 * All other ZRTP packet classes inherit from this class. It does not have
 * an implementation of its own.
 *
 * @author Werner Dittmann <Werner.Dittmann@t-online.de>
 */


public class ZrtpPacketBase {
    /*
     * This is the unique ZRTP ID in network order (PZ)
     */
    private static byte[] zrtpId;

    /**
     * A word in ZRTP is 4 bytes long.
     */
    public static final int ZRTP_WORD_SIZE = 4;
    
    /**
     * The size of the ZRTP specific CRC field.
     */
    public static final int CRC_SIZE = 4;

    /**
     * The length of the standard ZRTP packet header
     */
    protected static final int ZRTP_HEADER_LENGTH = 3;
    
    /*
     * Offsets of the header fields (byte offsets) in packet buffer
     */
    private static final int ID_OFFSET = 0;
    private static final int LENGTH_OFFSET = 2;
    private static final int TYPE_OFFSET = 4;
    private static final int TYPE_LENGTH = 8;   // length of type data in bytes
    
    protected byte[] packetBuffer = null;

    
    static {
        zrtpId = new byte[2];
        zrtpId[0] = 0x50;
        zrtpId[1] = 0x5a;
    }
    
    protected ZrtpPacketBase(byte[] pb) {
        packetBuffer = pb;
    }
    
    public final byte[] getHeaderBase() { 
        return (packetBuffer);
    }

    /**
     * Check if packet buffer contains the generic ZRTP id field.
     * 
     * @return true if packet buffer contains ZRTP id, false otherwise.
     */
    public final boolean isZrtpPacket() {
        if (packetBuffer[0] == zrtpId[0] && packetBuffer[1] == zrtpId[1]) {
            return (true);
        }
        return false;
    }
    
    public final short getLength() { 
        return ZrtpUtils.readShort(packetBuffer, LENGTH_OFFSET);
    }
    
    public final String getMessageType() { 
        return new String(packetBuffer, TYPE_OFFSET, TYPE_LENGTH); 
    }


    /**
     * Copy the unique ZRTP id into the ZRTP packer header
     *
     */
    protected final void setZrtpId() {    
        System.arraycopy(zrtpId, 0, packetBuffer, ID_OFFSET, zrtpId.length);
    }
    
    /**
     * Set the length of the packet (in ZRTP words) into the packet header.
     * 
     * The method first converts the integer into network order.
     *  
     * @param length The length of the packet in ZRTP words
     */
    protected final void setLength(int length) {
        ZrtpUtils.short16ToArrayInPlace(length, packetBuffer, LENGTH_OFFSET);
    }
    
    /**
     * Copy the message type to the ZRTP packet header.
     *  
     * @param messageType The message type name.
     */
    public final void setMessageType(byte[] messageType) {
        System.arraycopy(messageType, 0, packetBuffer, TYPE_OFFSET, 2*ZRTP_WORD_SIZE);
    }
}

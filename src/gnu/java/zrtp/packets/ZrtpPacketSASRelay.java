/**
 * Copyright (C) 2006-2011 Werner Dittmann
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
public class ZrtpPacketSASRelay extends ZrtpPacketBase {
    
    /*
     * The number of the Confirm specific ZRTP part in words
     */
    private static final int ZRTP_SAS_RELAY_FIXED_LENGTH = 16;
    
    
    private static final int HMAC_OFFSET = ZRTP_HEADER_LENGTH * ZRTP_WORD_SIZE;         // [2*ZRTP_WORD_SIZE];
    private static final int IV_OFFSET = HMAC_OFFSET + 2*ZRTP_WORD_SIZE;                // [4*ZRTP_WORD_SIZE];
    private static final int FILLER_OFFSET = IV_OFFSET + 4*ZRTP_WORD_SIZE;
    private static final int SIG_LENGTH_OFFSET = FILLER_OFFSET + 2;
    private static final int FLAGS_OFFSET = SIG_LENGTH_OFFSET + 1;
    private static final int RENDER_OFFSET = FLAGS_OFFSET + 1;
    private static final int TRUSTED_SAS_OFFSET = RENDER_OFFSET + 2;
    private static final int SIG_DATA_OFFSET = TRUSTED_SAS_OFFSET + 8*ZRTP_WORD_SIZE;

    // required bytes to hold the header, the fix part and the CRC
    private static final int CONFIRM_FIXED_LENGTH = 
        (ZRTP_HEADER_LENGTH + ZRTP_SAS_RELAY_FIXED_LENGTH) * ZRTP_WORD_SIZE + CRC_SIZE;
    
    private int signatureLength;

    public ZrtpPacketSASRelay() {
        super(null);
        setSignatureLength(0);
        setMessageType(ZrtpConstants.SASRelayMsg);
    }

    public ZrtpPacketSASRelay(final int sl) {
        super(null);
        setSignatureLength(sl);
        setMessageType(ZrtpConstants.SASRelayMsg);
    }

    public final void setSignatureLength(final int sl) {
        if (sl > 512) {
            return;                     // TODO throw exception here ?
        }
        signatureLength = sl;
        // compute total length inlcuding space for signature and CRC
        int length =  CONFIRM_FIXED_LENGTH + (sl * ZRTP_WORD_SIZE);
        
        if (packetBuffer == null) {
            packetBuffer = new byte[length];
        }
        else {
            // allocate new buffer, maybe shorter
            byte[] tmp = new byte[length];
            // copy header data to new place
            System.arraycopy(packetBuffer, 0, tmp, 0, (ZRTP_HEADER_LENGTH + ZRTP_SAS_RELAY_FIXED_LENGTH) * ZRTP_WORD_SIZE);
            packetBuffer = tmp;
        }
        packetBuffer[SIG_LENGTH_OFFSET] = (byte)sl;
        if (sl > 255) {
            packetBuffer[FILLER_OFFSET+1] = 1;  // set 9th bit if necessary
        }
        setLength((length-CRC_SIZE) / 4);
        setZrtpId();
    }

    public ZrtpPacketSASRelay(final byte[] data) {
        super(data);
        signatureLength = packetBuffer[SIG_LENGTH_OFFSET] & 0xff;
        if (packetBuffer[FILLER_OFFSET+1] == 1) {  // if we have a 9th bit - set it
            signatureLength |= 0x100;
        }
    }

    
    public final boolean isSASFlag() {
        return ((packetBuffer[FLAGS_OFFSET] & 0x4) == 0x4); 
    }
    
    public final byte[] getIv() {
        return ZrtpUtils.readRegion(packetBuffer, IV_OFFSET, 4*ZRTP_WORD_SIZE);
    }
        
    public final byte[] getHmac() {
        return ZrtpUtils.readRegion(packetBuffer, HMAC_OFFSET, 2*ZRTP_WORD_SIZE);
    }
        
    public final byte[] getRender() {
        return ZrtpUtils.readRegion(packetBuffer, RENDER_OFFSET, ZRTP_WORD_SIZE);
    }

    public final byte[] getDataToSecure() {
        // 9 is ZRTP_HEADER plus non secure confirm data       
        int length = (getLength() - 9) * ZRTP_WORD_SIZE;
        return ZrtpUtils.readRegion(packetBuffer, FILLER_OFFSET, length);
    }
    
    public final byte[] getSignatureData() {
        return ZrtpUtils.readRegion(packetBuffer, SIG_DATA_OFFSET, signatureLength);
    }
    
    public final int getSignatureLength() {
        return signatureLength;
    }
    /*
     * Setter methods
     */
    public final void setSASFlag() {
        packetBuffer[FLAGS_OFFSET] |= 0x4; 
    }

    public final void setHmac(final byte[] data) {
        System.arraycopy(data, 0, packetBuffer, HMAC_OFFSET, 2*ZRTP_WORD_SIZE);
    }

    public final void setIv(final byte[] data) {
        System.arraycopy(data, 0, packetBuffer, IV_OFFSET, 4*ZRTP_WORD_SIZE);
    }
        
    public final void setRender(final byte[] data)  { 
        System.arraycopy(data, 0, packetBuffer, RENDER_OFFSET, ZRTP_WORD_SIZE);
    }
    
    public final void setDataToSecure(final byte[] data) {
        // 9 is ZRTP_HEADER plus non secure confirm data       
        int length = (getLength() - 9) * ZRTP_WORD_SIZE;
        System.arraycopy(data, 0, packetBuffer, FILLER_OFFSET, length);
    }

    public final void setSignatureData(final byte[] data) {
        if (data.length > signatureLength) {
            return;                                 // TODO throw exception here?
        }
        System.arraycopy(data, 0, packetBuffer, SIG_DATA_OFFSET, data.length);       
    }
    
//    /* ***
    public static void main(String[] args) {
        ZrtpPacketSASRelay pkt = new ZrtpPacketSASRelay(0);
        System.err.println("SAS relay length: " + pkt.getLength());
        pkt.setSASFlag();
        
        System.err.println("packetBuffer length in bytes: " + pkt.getHeaderBase().length);
        ZrtpUtils.hexdump("SAS relay packet", pkt.getHeaderBase(), pkt.getHeaderBase().length);

        pkt = new ZrtpPacketSASRelay();
        pkt.setSignatureLength(150);
        System.err.println("SAS Relay length: " + pkt.getLength());
        pkt.setSASFlag();
        
        System.err.println("packetBuffer length in bytes: " + pkt.getHeaderBase().length);
        System.err.println("Signature length in words: " + pkt.getSignatureLength());
        ZrtpUtils.hexdump("SAS relay packet", pkt.getHeaderBase(), pkt.getHeaderBase().length);
    }
//    *** */
}

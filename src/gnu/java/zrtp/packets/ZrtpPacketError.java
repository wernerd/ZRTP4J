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
public class ZrtpPacketError extends ZrtpPacketBase {

    /*
     * The number of the Error specific ZRTP part in words
     */
    private static final int ZRTP_ERROR_LENGTH = 1;

    /*
     * Now the Erro packet specific offsets into the packet buffer. They
     * all start after ZRTP_HEADER_LENGTH and a given in bytes, not ZRTP
     * words.
     */
    private static final int CODE_OFFSET = ZRTP_HEADER_LENGTH * ZRTP_WORD_SIZE; // [ZRTP_WORD_SIZE];

    /*
     * Hello ack does not have any additional fields, just the header.
     */
    private static final int ERROR_LENGTH = 
        (ZRTP_HEADER_LENGTH + ZRTP_ERROR_LENGTH) * ZRTP_WORD_SIZE + CRC_SIZE;

    /**
     * Constructor for a new Error message.
     * 
     * ErrorAck does not have any specific fields, it is only
     * a simple message.
     *
     */
    public ZrtpPacketError() {
        super(new byte[ERROR_LENGTH]);
        setZrtpId();

        // The length field of a ZRTP packet does not include the CRC field.
        // the length is given in number of ZRTP words.
        setLength(ZRTP_HEADER_LENGTH + ZRTP_ERROR_LENGTH);
        setMessageType(ZrtpConstants.ErrorMsg);
    }

    /**
     * Constructor for Error message initialized with received data.
     * 
     * @param data received from the network.
     */
    public ZrtpPacketError(final byte[] data) {
        super(data);
    }
 
    /**
     * Get the error code from the Error packet.
     * 
     * Refer to the ZRTP specification about the error code semantics.
     * 
     * @return the error code.
     */
    public final int getErrorCode() { 
        return ZrtpUtils.readInt(packetBuffer, CODE_OFFSET); 
    }

    /**
     * Set the error code in the Error packet.
     * 
     * Refer to the ZRTP specification about the error code semantics.
     * 
     * @param code the error code.
     */
    public final void setErrorCode(final int code) {
        ZrtpUtils.int32ToArrayInPlace(code, packetBuffer, CODE_OFFSET);
    }

    /* ***
    public static void main(String[] args) {
        ZrtpPacketError pkt = new ZrtpPacketError();
        System.err.println("error length: " + pkt.getLength());
        System.err.println("packetBuffer length in bytes: " + pkt.getHeaderBase().length);
        pkt.setErrorCode(0x0102);
        ZrtpUtils.hexdump("error packet", pkt.getHeaderBase(), pkt.getHeaderBase().length);
    }
    *** */
}

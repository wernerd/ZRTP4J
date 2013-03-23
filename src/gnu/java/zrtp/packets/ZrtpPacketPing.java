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
public class ZrtpPacketPing extends ZrtpPacketBase {

    /*
     * The number of the Ping specific ZRTP part in words
     */
    private static final int ZRTP_PING_LENGTH = 3;

    /*
     * Now the Ping packet specific offsets into the packet buffer. They
     * all start after ZRTP_HEADER_LENGTH and a given in bytes, not ZRTP
     * words.
     */
    private static final int VERSION_OFFSET = ZRTP_HEADER_LENGTH * ZRTP_WORD_SIZE;   // [ZRTP_WORD_SIZE]
    private static final int EP_OFFSET = VERSION_OFFSET + ZRTP_WORD_SIZE;

    private static final int PING_LENGTH = 
        (ZRTP_HEADER_LENGTH + ZRTP_PING_LENGTH) * ZRTP_WORD_SIZE + CRC_SIZE;

    /**
     * Constructor for a new Ping message - currently not used for normal clients.
     * 
     *
     */
    protected ZrtpPacketPing() {
        super(new byte[PING_LENGTH]);
        setZrtpId();
        setVersion(ZrtpConstants.zrtpVersion_11);
        
        // The length field of a ZRTP packet does not include the CRC field.
        // the length is given in number of ZRTP words.
        setLength(ZRTP_HEADER_LENGTH + ZRTP_PING_LENGTH);
        setMessageType(ZrtpConstants.PingMsg);
    }

    /**
     * Constructor for Ping message initialized with received data.
     * 
     * @param data received from the network.
     */
    public ZrtpPacketPing(final byte[] data) {
        super(data);
    }
 
    /**
     * Get the endpoint hash from Ping packet.
     * 
     * @return the endpoint hash.
     */
    public final byte[] getEpHash() { 
        return ZrtpUtils.readRegion(packetBuffer, EP_OFFSET, 2*ZRTP_WORD_SIZE);
    }

    /**
     * Set the endpoint hash.
     * 
     * @return the endpoint hash.
     */
    protected final void setEpHash(final byte[] data) {
        System.arraycopy(data, 0, packetBuffer, EP_OFFSET, 2*ZRTP_WORD_SIZE);
    }
    
    private final void setVersion(final byte[] data) {
        System.arraycopy(data, 0, packetBuffer, VERSION_OFFSET, ZRTP_WORD_SIZE);
    }
}

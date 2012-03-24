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

package gnu.java.zrtp.jmf.transform.zrtp;

import gnu.java.zrtp.jmf.transform.PacketTransformer;
import gnu.java.zrtp.jmf.transform.RawPacket;
import gnu.java.zrtp.utils.ZrtpUtils;

/**
 * @author Werner Dittmann <Werner.Dittmann@t-online.de>
 *
 */
public class ZRTCPTransformer implements PacketTransformer {
    
    /**
     * We support different SRTCP contexts for input and output traffic:
     * 
     * Transform() uses the srtcpOut to perform encryption
     * reverseTransform() uses srtcpIn to perform decryption
     */
    private PacketTransformer srtcpIn = null;
    
    private PacketTransformer srtcpOut = null;
    /**
     * ZRTCPTransformer implements PacketTransformer.
     * It encapsulate the encryption / decryption logic for SRTCP packets
     * 
     * This class is currently not used.
     * 
     * @author Bing SU (nova.su@gmail.com)
     */
    //private ZRTPTransformEngine engine;

    /**
     * Constructs a SRTCPTransformer object
     *
     * @param engine The associated ZRTPTransformEngine object
     */
    public ZRTCPTransformer(ZRTPTransformEngine engine) {
        //this.engine = engine;
    }

    /**
     * Close the transformer engine.
     * 
     * The close functions closes all stored default crypto contexts. This deletes key data
     * and forces a cleanup of the crypto contexts.
     */
    public void close() {
        if (srtcpOut != null) {
            srtcpOut.close();
            srtcpOut = null;
        }
        if (srtcpIn != null) {
            srtcpIn.close();
            srtcpIn = null;
        }
    }
    /**
     * Encrypt a SRTCP packet
     * 
     * Currently SRTCP packet encryption / decryption is not supported
     * So this method does not change the packet content
     * 
     * @param pkt plain SRTCP packet to be encrypted
     * @return encrypted SRTCP packet
     */
    public RawPacket transform(RawPacket pkt) {
        if (srtcpOut == null) {
            return pkt;
        }
        return srtcpOut.transform(pkt);
    }

    /**
     * Decrypt a SRTCP packet
     * 
     * Currently SRTCP packet encryption / decryption is not supported
     * So this method does not change the packet content
     * 
     * @param pkt encrypted SRTCP packet to be decrypted
     * @return decrypted SRTCP packet
     */
    public RawPacket reverseTransform(RawPacket pkt) {
        if (srtcpIn == null) {
            return pkt;
        }
        return srtcpIn.reverseTransform(pkt);
    }

    /**
     * @param srtcpIn the srtcpIn to set
     */
    public void setSrtcpIn(PacketTransformer srtcpIn) {
        this.srtcpIn = srtcpIn;
    }

    /**
     * @param srtcpOut the srtcpOut to set
     */
    public void setSrtcpOut(PacketTransformer srtcpOut) {
        this.srtcpOut = srtcpOut;
    }

}

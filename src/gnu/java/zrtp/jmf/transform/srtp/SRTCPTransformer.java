/*
 * SIP Communicator, the OpenSource Java VoIP and Instant Messaging client.
 *
 * Distributable under LGPL license.
 * See terms of license at gnu.org.
 */
package gnu.java.zrtp.jmf.transform.srtp;

import java.util.Hashtable;

import gnu.java.zrtp.jmf.transform.PacketTransformer;
import gnu.java.zrtp.jmf.transform.RawPacket;


/**
 * SRTCPTransformer implements PacketTransformer.
 * It encapsulate the encryption / decryption logic for SRTCP packets
 * 
 * @author Bing SU (nova.su@gmail.com)
 * @author Werner Dittmann (Werner.Dittmann@t-online.de)
 */
public class SRTCPTransformer
    implements PacketTransformer
{
    private SRTPTransformEngine engine;

    /**
     * All the known SSRC's corresponding SRTCPCryptoContexts
     */
    private Hashtable<Long,SRTCPCryptoContext> contexts;

    /**
     * Constructs a SRTCPTransformer object
     *
     * @param engine The associated SRTPTransformEngine object
     */
    public SRTCPTransformer(SRTPTransformEngine engine) {
        this.engine = engine;
        this.contexts = new Hashtable<Long,SRTCPCryptoContext>();
    }

    /**
     * Encrypt a SRTCP packet
     * 
     * @param pkt plain SRTCP packet to be encrypted
     * @return encrypted SRTCP packet
     */
    public RawPacket transform(RawPacket pkt) {
        long ssrc = PacketManipulator.GetRTCPSSRC(pkt);

        SRTCPCryptoContext context = this.contexts
                .get(new Long(ssrc));

        if (context == null) {
            context = this.engine.getDefaultContextControl().deriveContext(ssrc);
            if (context != null) {
                context.deriveSrtcpKeys();
                contexts.put(new Long(ssrc), context);
            }
        }
        if (context != null) {
            context.transformPacket(pkt);
        }
        return pkt;
    }

    /**
     * Decrypt a SRTCP packet
     * 
     * @param pkt encrypted SRTCP packet to be decrypted
     * @return decrypted SRTCP packet
     */
    public RawPacket reverseTransform(RawPacket pkt) {
        long ssrc = PacketManipulator.GetRTCPSSRC(pkt);
        SRTCPCryptoContext context = this.contexts.get(new Long(ssrc));

        if (context == null) {
            context = this.engine.getDefaultContextControl().deriveContext(ssrc);
            if (context != null) {
                context.deriveSrtcpKeys();
                this.contexts.put(new Long(ssrc), context);
            }
        }

        if (context != null) {
            boolean validPacket = context.reverseTransformPacket(pkt);
            if (!validPacket) {
                return null;
            }
        }
        return pkt;
    }
}

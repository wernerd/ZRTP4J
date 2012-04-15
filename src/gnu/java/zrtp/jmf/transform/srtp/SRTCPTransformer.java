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
public class SRTCPTransformer implements PacketTransformer {
    private SRTPTransformEngine engine;

    /**
     * All the known SSRC's corresponding SRTCPCryptoContexts
     */
    private Hashtable<Long, SRTCPCryptoContext> contexts;

    /**
     * Constructs a SRTCPTransformer object
     * 
     * @param engine
     *            The associated SRTPTransformEngine object
     */
    public SRTCPTransformer(SRTPTransformEngine engine) {
        this.engine = engine;
        contexts = new Hashtable<Long, SRTCPCryptoContext>();
    }

    /**
     * Encrypt a SRTCP packet
     * 
     * @param pkt
     *            plain SRTCP packet to be encrypted
     * @return encrypted SRTCP packet
     */
    public RawPacket transform(RawPacket pkt) {
        long ssrc = PacketManipulator.GetRTCPSSRC(pkt);

        SRTCPCryptoContext context = contexts.get(ssrc);

        if (context == null) {
            context = engine.getDefaultContextControl().deriveContext(ssrc);
            if (context != null) {
                context.deriveSrtcpKeys();
                contexts.put(ssrc, context);
            }
            else 
                return pkt;
        }
        context.transformPacket(pkt);
        return pkt;
    }

    /**
     * Decrypt a SRTCP packet
     * 
     * @param pkt
     *            encrypted SRTCP packet to be decrypted
     * @return decrypted SRTCP packet
     */
    public RawPacket reverseTransform(RawPacket pkt) {
        long ssrc = PacketManipulator.GetRTCPSSRC(pkt);
        SRTCPCryptoContext context = this.contexts.get(ssrc);

        if (context == null) {
            context = engine.getDefaultContextControl().deriveContext(ssrc);
            if (context != null) {
                context.deriveSrtcpKeys();
                contexts.put(ssrc, context);
            }
            else 
                return pkt;
        }

        boolean validPacket = context.reverseTransformPacket(pkt);
        if (!validPacket) {
            return null;
        }
        return pkt;
    }

    /**
     * Close the transformer and underlying transform engine.
     * 
     * The close functions closes all stored crypto contexts. This deletes key data 
     * and forces a cleanup of the crypto contexts.
     */
    public void close() {
        engine.close();
        for(Long ssrc : contexts.keySet()) {
            SRTCPCryptoContext context = contexts.get(ssrc);
            if (context != null) {
                context.close();
                contexts.remove(ssrc);
            }
        }
    }
}

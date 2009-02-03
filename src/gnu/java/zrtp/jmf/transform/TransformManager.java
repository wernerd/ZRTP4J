/*
 * SIP Communicator, the OpenSource Java VoIP and Instant Messaging client.
 *
 * Distributable under LGPL license.
 * See terms of license at gnu.org.
 */
package gnu.java.zrtp.jmf.transform;

import gnu.java.zrtp.jmf.transform.srtp.SRTPPolicy;
import gnu.java.zrtp.jmf.transform.srtp.SRTPTransformEngine;
import gnu.java.zrtp.jmf.transform.zrtp.ZRTPTransformEngine;
import gnu.java.zrtp.jmf.transform.zrtp.ZrtpTransformConnector;

// import java.security.Provider;

import javax.media.rtp.*;

// import net.java.sip.communicator.impl.media.transform.dummy.*;

/**
 * TransformManager class encapsulate the logic of creating different kinds of
 * TransformConnectors. All TransformConnector objects should be created through
 * TransformManager class.
 * 
 * @author Bing SU (nova.su@gmail.com)
 */
public class TransformManager
{
    /**
     * Create a SRTP TransformConnector, which will provide SRTP encryption /
     * decryption functionality, using algorithms defined in RFC3711.
     * 
     * @param addr local RTP session listen address
     * @param masterKey master key of this SRTP session
     * @param masterSalt master salt of this SRTP session
     * @param srtpPolicy SRTP policy for this SRTP session
     * @param srtcpPolicy SRTCP policy for this SRTP session
     * @return the TransformConnector used for SRTP encyption/decryption
     * @throws InvalidSessionAddressException if the local RTP session address
     * is invalid
     */
    public static TransformConnector createSRTPConnector(SessionAddress addr,
            byte[] masterKey, byte[] masterSalt, SRTPPolicy srtpPolicy,
            SRTPPolicy srtcpPolicy)
            throws InvalidSessionAddressException {
        SRTPTransformEngine engine = null;

        engine = new SRTPTransformEngine(masterKey, masterSalt, srtpPolicy,
                srtcpPolicy);

        TransformConnector connector = null;
        connector = new TransformConnector(addr, engine);

        return connector;
    }

    /**
     * Create a ZRTP TransformConnector, which will provide ZRTP functionality,
     * as defined in the ZRTP spcification.
     * 
     * @return the TransformConnector used for ZRTP processing
     * @throws InvalidSessionAddressException
     *             if the local RTP session address is invalid
     */
    public static TransformConnector createZRTPConnector(SessionAddress addr)
        throws InvalidSessionAddressException
    {
        ZRTPTransformEngine engine = new ZRTPTransformEngine();

        TransformConnector connector = null;
        connector = new ZrtpTransformConnector(addr, engine);

        engine.setConnector(connector);
        return connector;
    }
    /**
     * Create a dummy TransformConnector. A dummy TransformConnector does no
     * modification (transformation) to RTP/RTCP packets. Its main purpose is to
     * test the TransformationConnector interface and provides a example code
     * of how to use the TransformConnector interfaces.
     * 
     * @param addr local RTP session address
     * @return A dummy TransformationConnector object
     * @throws InvalidSessionAddressException if the local RTP session address
     * is invalid
     *
    public static TransformConnector createDummyConnector(SessionAddress addr)
        throws InvalidSessionAddressException
    {
        DummyTransformEngine engine = new DummyTransformEngine();
        TransformConnector connector = new TransformConnector(addr, engine);
        return connector;
    }
    **** */
}

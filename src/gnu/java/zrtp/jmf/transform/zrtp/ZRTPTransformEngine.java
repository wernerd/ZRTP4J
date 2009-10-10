/*
 * SIP Communicator, the OpenSource Java VoIP and Instant Messaging client.
 *
 * Distributable under LGPL license.
 * See terms of license at gnu.org.
 */
package gnu.java.zrtp.jmf.transform.zrtp;

import gnu.java.zrtp.ZRtp;
import gnu.java.zrtp.ZrtpCallback;
import gnu.java.zrtp.ZrtpCodes;
import gnu.java.zrtp.ZrtpSrtpSecrets;
import gnu.java.zrtp.ZrtpStateClass;
import gnu.java.zrtp.ZrtpUserCallback;
import gnu.java.zrtp.ZrtpConstants;
import gnu.java.zrtp.jmf.transform.PacketTransformer;
import gnu.java.zrtp.jmf.transform.RawPacket;
import gnu.java.zrtp.jmf.transform.TransformConnector;
import gnu.java.zrtp.jmf.transform.TransformEngine;
import gnu.java.zrtp.jmf.transform.srtp.SRTPPolicy;
import gnu.java.zrtp.jmf.transform.srtp.SRTPTransformEngine;
import gnu.java.zrtp.zidfile.ZidFile;

import java.io.IOException;
import java.util.EnumSet;


/**
 * JMF extension/connector to support GNU ZRTP4J.
 * 
 * ZRTP was developed by Phil Zimmermann and provides functions to negotiate
 * keys and other necessary data (crypto data) to set-up the Secure RTP (SRTP)
 * crypto context. Refer to Phil's ZRTP specification at his <a
 * href="http://zfoneproject.com/">Zfone project</a> site to get more detailed
 * imformation about the capabilities of ZRTP.
 * 
 * <h3>Short overview of the ZRTP4J implementation</h3>
 * 
 * ZRTP is a specific protocol to negotiate encryption algorithms and the
 * required key material. ZRTP uses a RTP session to exchange its protocol
 * messages.
 * 
 * A complete GNU ZRTP4J implementation consists of two parts, the GNU ZRTP4J
 * core and specific code that binds the GNU ZRTP core to the underlying
 * RTP/SRTP stack and the operating system:
 * <ul>
 * <li> The GNU ZRTP core is independent of a specific RTP/SRTP stack and the
 * operationg system and consists of the ZRTP protocol state engine, the ZRTP
 * protocol messages, and the GNU ZRTP4J engine. The GNU ZRTP4J engine provides
 * methods to setup ZRTP message and to analyze received ZRTP messages, to
 * compute the crypto data required for SRTP, and to maintain the required
 * hashes and HMAC. </li>
 * <li> The second part of an implementation is specific <em>glue</em> code
 * the binds the GNU ZRTP core to the actual RTP/SRTP implementation and other
 * operating system specific services such as timers. </li>
 * </ul>
 * 
 * The GNU ZRTP4J core uses a callback interface class (refer to ZrtpCallback)
 * to access RTP/SRTP or operating specific methods, for example to send data
 * via the RTP/SRTP stack, to access timers, provide mutex handling, and to
 * report events to the application.
 * 
 * <h3>The ZRTPTransformEngine</h3>
 * 
 * ZRTPTransformEngine implements code that is specific to the JMF
 * implementation.
 * 
 * To perform its tasks ZRTPTransformEngine
 * <ul>
 * <li> extends specific classes to hook into the JMF RTP methods and the
 * RTP/SRTP send and receive queues </li>
 * <li> implements the ZrtpCallback interface to provide to enable data send and
 * receive other specific services (timer to GNU ZRTP4J </li>
 * <li> provides ZRTP specific methods that applications may use to control and
 * setup GNU ZRTP </li>
 * <li> can register and use an application specific callback class (refer to
 * ZrtpUserCallback) </li>
 * </ul>
 * 
 * After instantiating a GNU ZRTP4J session (see below for a short example)
 * applications may use the ZRTP specific methods of ZRTPTransformEngine to
 * control and setup GNU ZRTP, for example enable or disable ZRTP processing or
 * getting ZRTP status information.
 * 
 * GNU ZRTP4J provides a ZrtpUserCallback class that an application may extend
 * and register with ZRTPTransformEngine. GNU ZRTP4J and ZRTPTransformEngine use
 * the ZrtpUserCallback methods to report ZRTP events to the application. The
 * application may display this information to the user or act otherwise.
 * 
 * The following figure depicts the relationships between ZRTPTransformEngine,
 * JMF implementation, the GNU ZRTP4J core, and an application that provides an
 * ZrtpUserCallback class.
 * 
 * <pre>
 * 
 *                  +---------------------------+
 *                  |  ZrtpTransformConnector   |
 *                  | extends TransformConnector|
 *                  | implements RTPConnector   |
 *                  +---------------------------+
 *                                |
 *                                | uses
 *                                |
 *  +----------------+      +-----+---------------+
 *  |  Application   |      |                     |      +----------------+
 *  |  instantiates  | uses | ZRTPTransformEngine | uses |                |
 *  | a ZRTP Session +------+    implements       +------+   GNU ZRTP4J   |
 *  |  and provides  |      |   ZrtpCallback      |      |      core      |
 *  |ZrtpUserCallback|      |                     |      | implementation |
 *  +----------------+      +---------------------+      |  (ZRtp et al)  |
 *                                                       |                |
 *                                                       +----------------+
 * </pre>
 * 
 * The following short code snippets show how an application could instantiate a
 * ZrtpTransformConnector, get the ZRTP4J engine and initialize it. Then the
 * code get a RTP manager instance and initializes it with the
 * ZRTPTransformConnector. Plase note: setting the target must be done with the
 * connector, not with the RTP manager.
 * 
 * <pre>
 * ...
 *   transConnector = (ZrtpTransformConnector)TransformManager.createZRTPConnector(sa);
 *   zrtpEngine = transConnector.getEngine();
 *   zrtpEngine.setUserCallback(new MyCallback());
 *   if (!zrtpEngine.initialize("test_t.zid"))
 *       System.out.println("iniatlize failed");
 * 
 *   // initialize the RTPManager using the ZRTP connector
 * 
 *   mgr = RTPManager.newInstance();
 *   mgr.initialize(transConnector);
 * 
 *   mgr.addSessionListener(this);
 *   mgr.addReceiveStreamListener(this);
 * 
 *   transConnector.addTarget(target);
 *   zrtpEngine.startZrtp();
 * 
 *   ...
 * </pre>
 * 
 * The <em>demo</em> folder contains a small example that shows how to use GNU
 * ZRTP4J.
 * 
 * This ZRTPTransformEngine documentation shows the ZRTP specific extensions and
 * describes overloaded methods and a possible different behaviour.
 * 
 * @author Werner Dittmann <Werner.Dittmann@t-online.de>
 * 
 */
public class ZRTPTransformEngine
    implements TransformEngine, PacketTransformer, ZrtpCallback
{
    
    /**
     * Very simple Timout provider class.
     * 
     * This very simple timeout provider can handle one timeout request at
     * one time only. A secod request would overwrite the first one and would
     * lead to unexpected results.
     * 
     * @author Werner Dittmann <Werner.Dittmann@t-online.de>
     *
     */
    class TimeoutProvider extends Thread {

        public TimeoutProvider(String name) {
            super(name);
        }

        ZRTPTransformEngine executor;

        long nextDelay = 0;

        boolean newTask = false;

        boolean stop = false;

        Object sync = new Object();

        public synchronized void requestTimeout(long delay, ZRTPTransformEngine tt) {
            synchronized (sync) {
                executor = tt;
                nextDelay = delay;
                newTask = true;
                sync.notifyAll();
            }
        }

        public void stopRun() {
            synchronized (sync) {
                stop = true;
                sync.notifyAll();
            }
        }

        public void cancelRequest() {
            synchronized (sync) {
                newTask = false;
                sync.notifyAll();
            }
        }
        
        public void run() {
            while (!stop) {
                synchronized (sync) {
                    while (!newTask && !stop) {
                        try {
                            sync.wait();
                        } catch (InterruptedException e) {
                            e.printStackTrace();
                        }
                    }
                }
                long endTime = System.currentTimeMillis() + nextDelay;
                long currentTime = System.currentTimeMillis();
                synchronized (sync) {
                    while ((currentTime < endTime) && newTask && !stop) {
                        try {
                            sync.wait(endTime - currentTime);
                        } catch (InterruptedException e) {
                            e.printStackTrace();
                        }
                        currentTime = System.currentTimeMillis();
                    }
                }
                if (newTask && !stop) {
                    newTask = false;
                    executor.handleTimeout();
                }
            }

        }
    }

    // each ZRTP packet has a fixed header of 12 bytes
    protected static final int ZRTP_PACKET_HEADER = 12;
    /**
     * This is the own ZRTP connector, required to send ZRTP packets
     * via the DatagramSocket.
     */
    private TransformConnector zrtpConnector = null;
    
    /**
     * We need Out and In SRTPTransformer to transform RTP to SRTP and
     * vice versa.
     */
    private PacketTransformer srtpOutTransformer = null;
    private PacketTransformer srtpInTransformer = null;
    
    /**
     * User callback class.
     */
    private ZrtpUserCallback userCallback = null;
    
    /**
     * The ZRTP engine.
     */
    private ZRtp zrtpEngine = null;
    
    private boolean enableZrtp = false;
    
    private String clientIdString = ZrtpConstants.clientId;
    
    private int ownSSRC = 0;
    
    private short senderZrtpSeqNo = 0;
    
    private long sendPacketCount = 0;
    
    private TimeoutProvider timeoutProvider = null;
    
    private boolean started = false;


    /**
     * Construct a ZRTPTransformEngine.
     * 
     */
    public ZRTPTransformEngine() {
        senderZrtpSeqNo = 1;        // should be a random number
    }
    
    /*
     * (non-Javadoc)
     * 
     * @see net.java.sip.communicator.impl.media.transform.
     *      TransformEngine#getRTCPTransformer()
     */
    public PacketTransformer getRTCPTransformer() {
        return new ZRTPCTransformer(this);
    }

    /*
     * (non-Javadoc)
     * 
     * @see net.java.sip.communicator.impl.media.transform.
     *      TransformEngine#getRTPTransformer()
     */
    public PacketTransformer getRTPTransformer() {
        return this;
    }

    public synchronized boolean initialize(String zidFilename) {
        return initialize(zidFilename, true);
    }

    public synchronized boolean initialize(String zidFilename, boolean autoEnable) {

        if (timeoutProvider == null) {
            timeoutProvider = new TimeoutProvider("ZRTP");
            timeoutProvider.setDaemon(true);
            timeoutProvider.start();
        }

        ZidFile zf = ZidFile.getInstance();
        if (!zf.isOpen()) {
            String fname;
            if (zidFilename == null) {
                String home = System.getenv("HOME");
                String baseDir = (home != null) ? ((home) + ("/.")) : ".";
                fname = baseDir + "GNUZRTP4J.zid";
                zidFilename = fname;
            }
            if (zf.open(zidFilename) < 0) {
                enableZrtp = false;
                return false;
            }
        }
        enableZrtp = autoEnable;
        zrtpEngine = new ZRtp(zf.getZid(), this, clientIdString);
        return true;
    }

    /**
     * Start the ZRTP stack immediately, not autosensing mode.
     * 
     */
    public void startZrtp() {
        if (zrtpEngine != null) {
            zrtpEngine.startZrtpEngine();
            started = true;
        }
    }

    /**
     * Stop ZRTP engine.
     *
     */
    public void stopZrtp() {
        if (zrtpEngine != null) {
            zrtpEngine.stopZrtp();
            zrtpEngine = null;
            started = false;
        }
    }

    public void cleanup() {
        timeoutProvider.stopRun();
        timeoutProvider = null;
    }
    /* (non-Javadoc)
     * @see net.java.sip.communicator.impl.media.transform.PacketTransformer#
     * transform(net.java.sip.communicator.impl.media.transform.RawPacket)
     */
    /*
     * The data output stream calls this method to transform outgoing
     * packets.
     */
    public RawPacket transform(RawPacket pkt)
    {
        byte[] buffer = pkt.getBuffer();
        int offset = pkt.getOffset();
        if ((buffer[offset] & 0x10) == 0x10)  {
            return pkt;
        }
        /*
         * ZRTP needs the SSRC of the sending stream.
         */
        if (enableZrtp && ownSSRC == 0) {
            ownSSRC = (int)(pkt.readUnsignedIntAsLong(8) & 0xffffffff);
        }
        /*
         * If SRTP is active then srtpTransformer is set, use it.
         */
        sendPacketCount++;
        if (srtpOutTransformer == null) {
            return pkt;
        }
        return srtpOutTransformer.transform(pkt);
    }

    /* (non-Javadoc)
     * @see net.java.sip.communicator.impl.media.transform.PacketTransformer#
     * reverseTransform(net.java.sip.communicator.impl.media.transform.RawPacket)
     */
    /*
     * The input data stream calls this method to transfrom 
     * incoming packets.
     */
    public RawPacket reverseTransform(RawPacket pkt) {
        /*
         * Check if incoming packt is a ZRTP packet, if no treat
         * it as normal RTP packet and handle it accordingly.
         */
        byte[] buffer = pkt.getBuffer();
        int offset = pkt.getOffset();
        if ((buffer[offset] & 0x10) != 0x10) {
            if (!started && enableZrtp) {
                System.out.println("start zrtp");
                startZrtp();
            }
            if (srtpInTransformer == null) {
                return pkt;
            }
            pkt = srtpInTransformer.reverseTransform(pkt);
            // if packet was valid (i.e. not null) and ZRTP engine started and
            // not yet in secure state - emulate a Conf2Ack packet. See ZRTP spec
            // chap. 5.6
            if (pkt != null && zrtpEngine != null && !zrtpEngine.inState(ZrtpStateClass.ZrtpStates.SecureState)) {
                zrtpEngine.conf2AckSecure();
            }
            return pkt;
        }

        /*
         * If ZRTP is enabled process packet. In any case return null 
         * because ZRTP packets must never reach the application.
         */
        if (enableZrtp) {
            ZrtpRawPacket zPkt = new ZrtpRawPacket(pkt);
            if (!zPkt.checkCrc()) {
                userCallback.showMessage(ZrtpCodes.MessageSeverity.Warning, 
                        EnumSet.of(ZrtpCodes.WarningCodes.WarningCRCmismatch));
                return null;
            }
            // Check if it is really a ZRTP packet, if not don't process it
            if (!zPkt.hasMagic() || zrtpEngine == null) {
                return null;
            }
            // cover the case if the other party sends _only_ ZRTP packets at the
            // beginning of a session. Start ZRTP in this case as well.
            if (!started) {
                startZrtp();
             }
            byte[] extHeader = zPkt.getMessagePart();
            zrtpEngine.processZrtpMessage(extHeader, zPkt.getSSRC());
        }
        return null;
    }

    /*
     * Here the callback methods required by the ZRTP implementation
     * First allocate space to hold the complete ZRTP packet, copy
     * the message part in its place, the initalize the header, counter,
     * SSRC and crc.
     */
    public boolean sendDataZRTP(byte[] data) {

        int totalLength = ZRTP_PACKET_HEADER + data.length;
        byte[] tmp = new byte[totalLength];
        System.arraycopy(data, 0, tmp, ZRTP_PACKET_HEADER, data.length);
        ZrtpRawPacket packet = new ZrtpRawPacket(tmp, 0, tmp.length);

        packet.setSSRC(ownSSRC);

        packet.setSeqNum(senderZrtpSeqNo++);

        packet.setCrc();

        try {
            zrtpConnector.getDataOutputStream().write(packet.getBuffer(),
                    packet.getOffset(), packet.getLength());
        } catch (IOException e) {
            return false;
        }
        return true;
    }
    
    public boolean srtpSecretsReady(ZrtpSrtpSecrets secrets, EnableSecurity part) {

        SRTPPolicy srtpPolicy = null;

        if (part == EnableSecurity.ForSender) {
            // To encrypt packets: intiator uses initiator keys,
            // responder uses responder keys
            // Create a "half baked" crypto context first and store it. This is
            // the main crypto context for the sending part of the connection.
            if (secrets.getRole() == Role.Initiator) {
                srtpPolicy = new SRTPPolicy(SRTPPolicy.AESCM_ENCRYPTION,
                        secrets.getInitKeyLen() / 8,            // key length
                        SRTPPolicy.HMACSHA1_AUTHENTICATION, 20, // auth key
                                                                // length
                        secrets.getSrtpAuthTagLen() / 8,        // auth tag length
                        secrets.getInitSaltLen() / 8            // salt length
                );
                SRTPTransformEngine engine = new SRTPTransformEngine(secrets
                        .getKeyInitiator(), secrets.getSaltInitiator(),
                        srtpPolicy, srtpPolicy);
                srtpOutTransformer = engine.getRTPTransformer();
            } else {
                srtpPolicy = new SRTPPolicy(SRTPPolicy.AESCM_ENCRYPTION,
                        secrets.getRespKeyLen() / 8,            // key length
                        SRTPPolicy.HMACSHA1_AUTHENTICATION, 20, // auth key
                                                                // length
                        secrets.getSrtpAuthTagLen() / 8,        // auth taglength
                        secrets.getRespSaltLen() / 8            // salt length
                );

                SRTPTransformEngine engine = new SRTPTransformEngine(secrets
                        .getKeyResponder(), secrets.getSaltResponder(),
                        srtpPolicy, srtpPolicy);
                srtpOutTransformer = engine.getRTPTransformer();
            }
        }
        if (part == EnableSecurity.ForReceiver) {
            // To decrypt packets: intiator uses responder keys,
            // responder initiator keys
            // See comment above.
            if (secrets.getRole() == Role.Initiator) {
                srtpPolicy = new SRTPPolicy(SRTPPolicy.AESCM_ENCRYPTION,
                        secrets.getRespKeyLen() / 8,            // key length
                        SRTPPolicy.HMACSHA1_AUTHENTICATION, 20, // auth key
                                                                // length
                        secrets.getSrtpAuthTagLen() / 8,        // auth tag length
                        secrets.getRespSaltLen() / 8            // salt length
                );

                SRTPTransformEngine engine = new SRTPTransformEngine(secrets
                        .getKeyResponder(), secrets.getSaltResponder(),
                        srtpPolicy, srtpPolicy);
                srtpInTransformer = engine.getRTPTransformer();
            } else {
                srtpPolicy = new SRTPPolicy(SRTPPolicy.AESCM_ENCRYPTION,
                        secrets.getInitKeyLen() / 8,            // key length
                        SRTPPolicy.HMACSHA1_AUTHENTICATION, 20, // auth key
                                                                // length
                        secrets.getSrtpAuthTagLen() / 8,        // auth tag length
                        secrets.getInitSaltLen() / 8            // salt length
                );

                SRTPTransformEngine engine = new SRTPTransformEngine(secrets
                        .getKeyInitiator(), secrets.getSaltInitiator(),
                        srtpPolicy, srtpPolicy);
                srtpInTransformer = engine.getRTPTransformer();
            }
        }
        return true;
    }

    public void srtpSecretsOn(String c, String s, boolean verified) {

        if (userCallback != null) {
            userCallback.secureOn(c);
        }
        if (userCallback != null && s != null) {
            userCallback.showSAS(s, verified);
        }
    }

    public void srtpSecretsOff(EnableSecurity part) {
        if (part == EnableSecurity.ForSender) {
            srtpOutTransformer = null;
        }
        if (part == EnableSecurity.ForReceiver) {
            srtpInTransformer = null;
        }
        if (userCallback != null) {
            userCallback.secureOff();
        }
    }

    public int activateTimer(int time) {
        if (timeoutProvider != null) {
            timeoutProvider.requestTimeout(time, this);
        }
        return 1;
    }

    public int cancelTimer() {
        if (timeoutProvider != null) {
            timeoutProvider.cancelRequest();
        }
        return 1;
    }

    public void handleTimeout() {
        if (zrtpEngine != null) {
            zrtpEngine.processTimeout();
        }
    }

    public void sendInfo(ZrtpCodes.MessageSeverity severity, EnumSet<?> subCode) {
        if (userCallback != null) {
            userCallback.showMessage(severity, subCode);
        }
    }

    public void zrtpNegotiationFailed(ZrtpCodes.MessageSeverity severity, EnumSet<?> subCode) {
        if (userCallback != null) {
            userCallback.zrtpNegotiationFailed(severity, subCode);
        }
    }

    public void zrtpNotSuppOther() {
        if (userCallback != null) {
            userCallback.zrtpNotSuppOther();
        }
    }

    public void zrtpAskEnrollment(String info) {
        if (userCallback != null) {
            userCallback.zrtpAskEnrollment(info);
        }
    }

    public void zrtpInformEnrollment(String info) {
        if (userCallback != null) {
            userCallback.zrtpInformEnrollment(info);
        }
    }

    public void signSAS(String sas) {
        if (userCallback != null) {
            userCallback.signSAS(sas);
        }
    }

    public boolean checkSASSignature(String sas) {
        return ((userCallback != null) ? userCallback.checkSASSignature(sas) : false);
    }

    public void setEnableZrtp(boolean onOff)   {
        enableZrtp = onOff;
    }

    public boolean isEnableZrtp() {
        return enableZrtp;
    }

    public void SASVerified() {
        if (zrtpEngine != null)
            zrtpEngine.SASVerified();
    }

    public void resetSASVerified() {
        if (zrtpEngine != null)
            zrtpEngine.resetSASVerified();
    }

    public void goClearOk()    {  }

    public void requestGoClear()  { }

    public void setSrtpsSecret(byte[] data) {
        if (zrtpEngine != null)
            zrtpEngine.setSrtpsSecret(data);
    }

    public void setOtherSecret(byte[] data) {
        if (zrtpEngine != null)
            zrtpEngine.setOtherSecret(data);
    }

    public void setClientId(String id) {
        clientIdString = id;
    }

    public String getHelloHash() {
        if (zrtpEngine != null)
            return zrtpEngine.getHelloHash();
        else
            return new String();
    }

    public byte[] getMultiStrParams() {
        if (zrtpEngine != null)
            return zrtpEngine.getMultiStrParams();
        else
            return new byte[0];
    }

    public void setMultiStrParams(byte[] parameters) {
        if (zrtpEngine != null)
            zrtpEngine.setMultiStrParams(parameters);
    }

    public boolean isMultiStream() {
        return ((zrtpEngine != null) ? zrtpEngine.isMultiStream() : false);
    }

    public void acceptEnrollment(boolean accepted) {
        if (zrtpEngine != null)
            zrtpEngine.acceptEnrollment(accepted);
    }

    public boolean setSignatureData(byte[] data) {
        return ((zrtpEngine != null) ? zrtpEngine.setSignatureData(data)
                : false);
    }

    public byte[] getSignatureData() {
        if (zrtpEngine != null)
            return zrtpEngine.getSignatureData();
        else
            return new byte[0];
    }

    public int getSignatureLength() {
        return ((zrtpEngine != null) ? zrtpEngine.getSignatureLength() : 0);
    }

    public void setPBXEnrollment(boolean yesNo) {
        if (zrtpEngine != null)
            zrtpEngine.setPBXEnrollment(yesNo);
    }

    public void handleGoClear() {
        System.err.println("Need to process a GoClear message!");
    }

    /**
     * @param connector the connector to set
     */
    public void setConnector(TransformConnector connector) {
        zrtpConnector = connector;
    }
    
    public void setUserCallback(ZrtpUserCallback ub) {
        userCallback = ub;
    }
    
    public boolean isStarted() {
       return started;
    }

    /**
     * Get other party's ZID (ZRTP Identifier) data
     *
     * This functions returns the other party's ZID that was receivied 
     * during ZRTP processing. 
     *
     * The ZID data can be retrieved after ZRTP receive the first Hello
     * packet from the other party. The application may call this method
     * for example during SAS processing in showSAS(...) user callback
     * method.
     *
     * @return
     *    the ZID data as byte array.
     */
    
    public byte[] getetZid() {
        return ((zrtpEngine != null) ? zrtpEngine.getZid() : null);
    }

/*
    public static void main(String argv[]) {
        System.err.println(System.getenv("HOMEDRIVE"));
        System.err.println(System.getenv("HOMEPATH"));
    }
*/
}

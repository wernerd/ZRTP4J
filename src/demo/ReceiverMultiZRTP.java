package demo;

import gnu.java.zrtp.ZrtpCodes;
import gnu.java.zrtp.ZrtpConfigure;
import gnu.java.zrtp.ZrtpConstants;
import gnu.java.zrtp.ZrtpUserCallback;
import gnu.java.zrtp.jmf.transform.TransformManager;
import gnu.java.zrtp.jmf.transform.zrtp.ZRTPTransformEngine;
import gnu.java.zrtp.jmf.transform.zrtp.ZrtpTransformConnector;

import java.net.*;
import java.util.EnumSet;
import java.util.Iterator;

import javax.media.*;
//import javax.media.control.*;
import javax.media.protocol.*;
import javax.media.rtp.*;
import javax.media.rtp.event.*;



/**
 */
public class ReceiverMultiZRTP implements ReceiveStreamListener, SessionListener,
        BufferTransferHandler {
    
    ZrtpTransformConnector transConnector = null;
    ZRTPTransformEngine zrtpEngine = null;

    ZrtpTransformConnector transConnectorMulti = null;
    ZRTPTransformEngine zrtpEngineMulti = null;

    protected class MyCallback extends ZrtpUserCallback {
        String prefix = new String("");

        MyCallback() {
        }
        
        public void secureOn(String cipher) {
            System.err.println(prefix + "Rx Cipher: " + cipher);
            if (zrtpEngineMulti == null)
                System.err.println(prefix + "Rx peer hello hash: " + zrtpEngine.getPeerHelloHash());
            else
                System.err.println(prefix + "Rx peer hello hash: " + zrtpEngineMulti.getPeerHelloHash());
        }

        public void showSAS(String sas, boolean verified) {
            System.err.println(prefix + "Rx SAS: " + sas);               
        }

        public void showMessage(ZrtpCodes.MessageSeverity sev, EnumSet<?> subCode) {
            Iterator<?> ii = subCode.iterator();
            if (sev == ZrtpCodes.MessageSeverity.Info) {
                ZrtpCodes.InfoCodes inf = (ZrtpCodes.InfoCodes)ii.next();
                System.err.println(prefix + "Rx show message sub code: " + inf);
                if (inf == ZrtpCodes.InfoCodes.InfoSecureStateOn) {
                    initializeMulti();
                }
                return;
            }
            System.err.println(prefix + "Rx show message sub code: " + ii.next());
        }

        public void zrtpNegotiationFailed(ZrtpCodes.MessageSeverity severity,
                    EnumSet<?> subCode) {
            Iterator<?> ii = subCode.iterator();
            System.err.println(prefix + "Rx negotiation failed sub code: " + ii.next());
        }
        
        public void secureOff() {
            System.err.println(prefix + "Rx Security off");
        }

        public void zrtpNotSuppOther() {
            System.err.println(prefix + "Rx ZRTP not supported");
        }

        public void signSAS(byte[] sasHash) {
            System.err.println("Receiver: SAS to sign: ");
            byte[] sign = new byte[12];
            sign[0] = sasHash[0];
            sign[1] = sasHash[1];
            sign[2] = sasHash[2];
            sign[3] = sasHash[3];
            sign[4] = (byte)'R';
            sign[5] = (byte)'E';
            sign[6] = (byte)'C';
            sign[7] = (byte)'E';
            sign[8] = (byte)'I';
            sign[9] = (byte)'V';
            sign[10] = (byte)'E';
            sign[11] = (byte)'R';
            try {
                Thread.sleep(150);
            } catch (InterruptedException e) {
                // TODO Auto-generated catch block
                e.printStackTrace();
            }
            System.err.println("Receiver set signature data result: " + zrtpEngine.setSignatureData(sign));
        }

        public boolean checkSASSignature(byte[] sasHash) {
            System.err.print("Receiver: check signature: ");
            byte[] sign = zrtpEngine.getSignatureData();
            String signStrng = new String(sign);
            System.err.println(signStrng);
            try {
                Thread.sleep(150);
            } catch (InterruptedException e) {
                // TODO Auto-generated catch block
                e.printStackTrace();
            }
            return true;
        }
        
        void setPrefix(String pre) {
            prefix = pre;
        }
    }
    
    protected class MyCallbackMulti extends MyCallback {
        MyCallbackMulti() {
        }
        
        public void showMessage(ZrtpCodes.MessageSeverity sev, EnumSet<?> subCode) {
            Iterator<?> ii = subCode.iterator();
            System.err.println(prefix + "Rx show message sub code: " + ii.next());
        }

    }

    private RTPManager mgr = null;
    private RTPManager mgrMulti = null;
    private PushBufferStream multiPbs = null; 
    
    public ReceiverMultiZRTP() {
    }

    public void run() {
        this.initialize();
    }

    /**
     * Initializes a RTP/ZRTP/SRTP session
     */
    protected void initialize() {

        InetAddress ia = null;
        try {
            ia = InetAddress.getByName("localhost");
        } catch (java.net.UnknownHostException ex) {
            System.err.println("Unknown local host: " + ex.getMessage());
        }
        System.err.println("Internet address: " + ia);
        SessionAddress sa = new SessionAddress(ia, 5002);
        SessionAddress target = new SessionAddress(ia, 5004);

        try {
            // create a ZRTP connector with own bind address
            transConnector = (ZrtpTransformConnector) TransformManager
                    .createZRTPConnector(sa);
            zrtpEngine = transConnector.getEngine();
            zrtpEngine.setSignSas(true);
            zrtpEngine.setUserCallback(new MyCallback());
            ZrtpConfigure config = new ZrtpConfigure();
            config.setStandardConfig();
//            config.addHashAlgo(ZrtpConstants.SupportedHashes.S384);
           
            if (!zrtpEngine.initialize("test_t.zid", config))
                System.out.println("iniatlize failed");

            System.out.println("Rx Hello hash: " + zrtpEngine.getHelloHash());
            zrtpEngine.setOwnSSRC(1);
            // initialize the RTPManager using the ZRTP connector

            mgr = RTPManager.newInstance();

            mgr.addSessionListener(this);
            mgr.addReceiveStreamListener(this);

            transConnector.addTarget(target);
            mgr.initialize(transConnector);
//            zrtpEngine.startZrtp();
        } catch (Exception e) {
            System.err.println("Cannot create the RTP Session: "
                    + e.getMessage());
            e.printStackTrace();
        }
    }

    protected void initializeMulti() {

        InetAddress ia = null;
        try {
            ia = InetAddress.getByName("localhost");
        } catch (java.net.UnknownHostException ex) {
            System.err.println("Unknown local host: " + ex.getMessage());
        }
        System.err.println("Multi Internet address: " + ia);
        SessionAddress sa = new SessionAddress(ia, 5002+10);
        SessionAddress target = new SessionAddress(ia, 5004+10);

        try {
            // create a ZRTP connector with own bind address
            transConnectorMulti = (ZrtpTransformConnector) TransformManager
                    .createZRTPConnector(sa);
            zrtpEngineMulti = transConnectorMulti.getEngine();

            // IMPORTANT: crypto provider must be set before initialization
            if (!zrtpEngineMulti.initialize("test_t.zid"))
                System.out.println("Multi iniatlize failed");

            // IMPORTANT: set other data only _after_ initialization
            MyCallbackMulti mcb = new MyCallbackMulti();
            mcb.setPrefix("multi - ");
            zrtpEngineMulti.setUserCallback(mcb);
            
            byte[] multiParams = zrtpEngine.getMultiStrParams();
            zrtpEngineMulti.setMultiStrParams(multiParams);
            System.out.println("multi - Rx Hello hash: " + zrtpEngineMulti.getHelloHash());
            zrtpEngineMulti.setOwnSSRC(2);

            // initialize the RTPManager using the ZRTP connector

            mgrMulti = RTPManager.newInstance();
            mgrMulti.initialize(transConnectorMulti);

            mgrMulti.addSessionListener(this);
            mgrMulti.addReceiveStreamListener(this);

            transConnectorMulti.addTarget(target);
//            zrtpEngineMulti.startZrtp();
        } catch (Exception e) {
            System.err.println("Cannot create the Multi RTP Session: "
                    + e.getMessage());
            e.printStackTrace();
        }
    }

    /**
     * Closes the players and the session manager.
     */
    protected void close() {

        // close the RTP session.

        mgr.removeReceiveStreamListener(this);
        mgr.dispose();
        mgr = null;
    }

    /**
     * SessionListener.
     */

    /*
     * (Kein Javadoc)
     * 
     * @see javax.media.rtp.SessionListener#update(javax.media.rtp.event.SessionEvent)
     */
    public synchronized void update(SessionEvent evt) {
        // System.err.println("RX: SessionEvent received: " + evt);
        if (evt instanceof NewParticipantEvent) {
            // nothing to do
        }
    }

    /**
     * ReceiveStreamListener.
     */

    /*
     * (Kein Javadoc)
     * 
     * @see javax.media.rtp.ReceiveStreamListener#update(javax.media.rtp.event.ReceiveStreamEvent)
     */
    public synchronized void update(ReceiveStreamEvent evt) {

//        System.err.println("RX: ReceiveStreamEvent received: " + evt);
        RTPManager mngr = (RTPManager) evt.getSource();
        if (mngr == mgrMulti)
            System.err.println("Update Multi mngr");
        Participant participant = evt.getParticipant(); // could be null.
        ReceiveStream stream = null;

        if (evt instanceof RemotePayloadChangeEvent) {

            System.err
                    .println("RemotePayloadChangeEvent received. Can't handle this event. "
                            + evt);
        } else if (evt instanceof NewReceiveStreamEvent) {

            try {
                stream = ((NewReceiveStreamEvent) evt).getReceiveStream();
                PushBufferDataSource ds = (PushBufferDataSource)stream.getDataSource();
                // Find out the formats.
                RTPControl ctl = (RTPControl) ds
                        .getControl("javax.media.rtp.RTPControl");
                if (ctl != null) {
                    System.err.println("Received new RTP stream: "
                            + ctl.getFormat());
                } else {
                    System.err.println("Received new RTP stream");
                }

                // System.err.println("DS is: " + ds.toString());
                PushBufferStream[] pbs = ds.getStreams();
                // System.err.println("Number of pbs: " + pbs.length);
                // System.err.println("pbs format: " + pbs[0].getFormat());
                pbs[0].setTransferHandler(this);
                
                if (mngr == mgrMulti)       // if this is the multi part - remember the stream
                    multiPbs = pbs[0];

                ds.start();

            } catch (Exception e) {
                System.err.println("NewReceiveStreamEvent exception "
                        + e.getMessage());
                return;
            }

        } else if (evt instanceof StreamMappedEvent) {
            if (participant != null) {
                System.err.println("RX: Mapped to participant: " + participant.getCNAME());
            }
            else {
                System.err.println("RX: Mapped");
            }
        } else if (evt instanceof ByeEvent) {
            if (participant != null) {
                System.err.println("RX: BYE from: " + participant.getCNAME());
            }
            else {
                System.err.println("RX: BYE");
            }
            if (mngr == mgrMulti)
                zrtpEngineMulti.close();
            else
                zrtpEngine.close();
            
            mngr.removeReceiveStreamListener(this);
            mngr.dispose();
        } else {
            System.err.println("RX: Unknown Event: " + evt);
        }
    }

    /*
     * Method required by BufferTransferHandler
     */
    public void transferData(PushBufferStream stream) {
        // System.err.println("Received a transferData request from: " +
        // stream.toString());
        Buffer buf = new Buffer();
        try {
            stream.read(buf);
        } catch (java.io.IOException ex) {
            System.err.println("Buffer read exception: " + ex.getMessage());
        }
        Format fmt = buf.getFormat();
        Class<?> cls = fmt.getDataType();
        // System.err.println("buf length: " + buf.getLength() + ", timestamp: "
        // + buf.getTimeStamp());
        // System.err.println("buffer: " + buf.getFormat().toString());

        if (cls == Format.byteArray) {
            byte[] data = (byte[]) buf.getData();
            if (stream != multiPbs)
                System.err.println("RX Data: '"
                        + new String(data, buf.getOffset(), buf.getLength())
                        + "'");
            else
                System.err.println("multi - RX Data: '"
                        + new String(data, buf.getOffset(), buf.getLength())
                        + "'");
        }
    }

    public static void main(String[] args) {

        ReceiverMultiZRTP rcv = new ReceiverMultiZRTP();
        //	rcv.start();
        rcv.run();
        try {
            Thread.sleep(20000);
        } catch (InterruptedException ie) {
        }

        System.exit(0);
    }
}

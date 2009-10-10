package demo;

import gnu.java.zrtp.ZrtpCodes;
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
            zrtpEngine.setUserCallback(new MyCallback());
            
            if (!zrtpEngine.initialize("test_t.zid"))
                System.out.println("iniatlize failed");

            // initialize the RTPManager using the ZRTP connector

            mgr = RTPManager.newInstance();
            mgr.initialize(transConnector);

            mgr.addSessionListener(this);
            mgr.addReceiveStreamListener(this);

            transConnector.addTarget(target);
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
        //System.err.println("buf length: " + buf.getLength() + ", timestamp: "
        //        + buf.getTimeStamp());
        // System.err.println("buffer: " + buf.getFormat().toString());

        if (cls == Format.byteArray) {
            byte[] data = (byte[]) buf.getData();
            System.err.println("RX Data: '"
                    + new String(data, buf.getOffset(), buf.getLength()) + "'");
        }
    }

    public static void main(String[] args) {

        ReceiverMultiZRTP rcv = new ReceiverMultiZRTP();
        //	rcv.start();
        rcv.run();
        try {
            Thread.sleep(60000);
        } catch (InterruptedException ie) {
        }

        System.exit(0);
    }
}

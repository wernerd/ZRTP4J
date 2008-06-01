package demo;

import gnu.java.zrtp.jmf.transform.TransformConnector;
import gnu.java.zrtp.jmf.transform.TransformManager;
import gnu.java.zrtp.jmf.transform.srtp.SRTPPolicy;

import java.net.*;
import java.security.Provider;

import javax.media.*;
import javax.media.control.*;
import javax.media.protocol.*;
import javax.media.rtp.*;
import javax.media.rtp.event.*;


/**
 */
public class ReceiverSRTP implements ReceiveStreamListener, SessionListener,
        BufferTransferHandler {
    TransformConnector transConnector = null;

    private RTPManager mgr = null;

    public ReceiverSRTP() {
    }

    public void run() {
        this.initialize();
    }

    /**
     * Initializes an RTP session
     */
    protected void initialize() {
        Provider cryptoProvider = null;
        try {
            Class<?> c = Class
                    .forName("org.bouncycastle.jce.provider.BouncyCastleProvider");
            cryptoProvider = (Provider) c.newInstance();
        } catch (ClassNotFoundException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        } catch (InstantiationException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        } catch (IllegalAccessException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        }

        InetAddress ia = null;
        try {
            ia = InetAddress.getByName("localhost");
        } catch (java.net.UnknownHostException ex) {
            System.err.println("Unkone local host: " + ex.getMessage());
        }
        System.err.println("Internet address: " + ia);
        SessionAddress sa = new SessionAddress(ia, 5002);
        SessionAddress target = new SessionAddress(ia, 5004);
        SRTPPolicy srtpPolicy = new SRTPPolicy(SRTPPolicy.AESCM_ENCRYPTION, 16,
                SRTPPolicy.HMACSHA1_AUTHENTICATION, 20, 10, 14);

        // TODO currently master key and master salt are hardcoded,
        // when we have a key management protocol later, then
        // we will use the negotiated result
        byte[] masterKey = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f };

        byte[] masterSalt = { 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
                0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d };

        try {
            // create a SRTP connector with own bind address
            transConnector = TransformManager.createSRTPConnector(sa,
                    masterKey, masterSalt, srtpPolicy, srtpPolicy, cryptoProvider);

            // initialize the RTPManager using the SRTP connector

            mgr = RTPManager.newInstance();
            mgr.initialize(transConnector);

            mgr.addSessionListener(this);
            mgr.addReceiveStreamListener(this);

            transConnector.addTarget(target);

            BufferControl bc = (BufferControl) mgr
                    .getControl("javax.media.control.BufferControl");
            if (bc != null) {
                System.err.println("Buffer length: " + bc.getBufferLength()
                        + ", Threshold: " + bc.getEnabledThreshold()
                        + ", minimum: " + bc.getMinimumThreshold());
                // bc.setEnabledThreshold(false);
                bc.setBufferLength(20);

                System.err.println("Buffer length: " + bc.getBufferLength());
            }
        } catch (Exception e) {
            System.err.println("Cannot create the RTP Session: "
                    + e.getMessage());
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
        System.err.println("SessionEvent received: " + evt);
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

        System.err.println("ReceiveStreamEvent received: " + evt);
//        RTPManager mgr = (RTPManager) evt.getSource();
        Participant participant = evt.getParticipant(); // could be null.
        ReceiveStream stream = evt.getReceiveStream(); // could be null.

        if (evt instanceof RemotePayloadChangeEvent) {

            System.err
                    .println("RemotePayloadChangeEvent received. Can't handle this event. "
                            + evt);
        } else if (evt instanceof NewReceiveStreamEvent) {

            try {
                /**
                 * @todo is this really neccessary? already got stream above?
                 */
                stream = ((NewReceiveStreamEvent) evt).getReceiveStream();
                PushBufferDataSource ds = (PushBufferDataSource)stream.getDataSource();
//               com.sun.media.protocol.rtp.DataSource ds = (com.sun.media.protocol.rtp.DataSource) stream
//                        .getDataSource();
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

        } else if (evt instanceof ByeEvent) {

            System.err.println("BYE from: " + participant.getCNAME());
        } else {
            System.err.println("Unknown Event: " + evt);
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
        Class cls = fmt.getDataType();
        System.err.println("buf length: " + buf.getLength() + ", timestamp: "
                + buf.getTimeStamp());
        // System.err.println("buffer: " + buf.getFormat().toString());

        if (cls == Format.byteArray) {
            byte[] data = (byte[]) buf.getData();
            System.err.println("Data: '"
                    + new String(data, buf.getOffset(), buf.getLength()) + "'");
        }
    }

    public static void main(String[] args) {

        ReceiverSRTP rcv = new ReceiverSRTP();
        //	rcv.start();
        rcv.run();
        try {
            Thread.sleep(60000);
        } catch (InterruptedException ie) {
        }

        System.exit(0);
    }
}

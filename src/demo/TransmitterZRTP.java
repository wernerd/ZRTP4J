
package demo;

import gnu.java.zrtp.ZrtpCodes;
import gnu.java.zrtp.ZrtpUserCallback;
import gnu.java.zrtp.jmf.transform.TransformManager;
import gnu.java.zrtp.jmf.transform.zrtp.ZRTPTransformEngine;
import gnu.java.zrtp.jmf.transform.zrtp.ZrtpTransformConnector;

import java.net.*;
import java.util.EnumSet;
import java.util.Iterator;

import javax.media.rtp.*;
import javax.media.rtp.event.NewSendStreamEvent;
import javax.media.rtp.event.SendStreamEvent;


public class TransmitterZRTP implements SendStreamListener {

    
    protected class MyCallback extends ZrtpUserCallback {
        MyCallback() {
        }
        
        public void secureOn(String cipher) {
            System.err.println("Tx Cipher: " + cipher);
        }

        public void showSAS(String sas, boolean verified) {
            System.err.println("Tx SAS: " + sas);
        }

        public void showMessage(ZrtpCodes.MessageSeverity sev, EnumSet<?> subCode) {
            Iterator<?> ii = subCode.iterator();
            ZrtpCodes.InfoCodes inf = (ZrtpCodes.InfoCodes)ii.next();
            System.err.println("Tx show message sub code: " + ii.next());
            if (inf == ZrtpCodes.InfoCodes.InfoSecureStateOn) {
                System.err.println("Tx peer hello hash: " + zrtpEngine.getPeerHelloHash());
            }
        }

        public void zrtpNegotiationFailed(ZrtpCodes.MessageSeverity severity, EnumSet<?> subCode) {
            Iterator<?> ii = subCode.iterator();
            System.err.println("Tx negotiation failed sub code: " + ii.next());
        }
        
        public void secureOff() {
            System.err.println("Tx Security off");
        }

        public void zrtpNotSuppOther() {
            System.err.println("Tx ZRTP not supported");
        }

    }

    public SimpleDataSource dataOutput = null;

    RTPManager rtpManager = null;

    SessionAddress sa = null;

    SessionAddress target = null;

    ZrtpTransformConnector transConnector = null;
    ZRTPTransformEngine zrtpEngine = null;

    public TransmitterZRTP() {
        InetAddress ia = null;
        try {
            ia = InetAddress.getByName("localhost");
        } catch (java.net.UnknownHostException ex) {
            System.err.println("Unknown local host: " + ex.getMessage());
        }

        System.err.println("Internet address: " + ia);
        sa = new SessionAddress(ia, 5004);
        target = new SessionAddress(ia, 5002);

        // create a send stream for the output data source
        dataOutput = createDataSource();
    }

    public void run() {

        // create the RTP Manager
        rtpManager = RTPManager.newInstance();

        try {
            // create a ZRTP connector with own bind address
            transConnector = (ZrtpTransformConnector)TransformManager.createZRTPConnector(sa);
            zrtpEngine = transConnector.getEngine();
            zrtpEngine.setUserCallback(new MyCallback());
            
            if (!zrtpEngine.initialize("test_r.zid"))
                System.err.println("Initialize failed");

            // initialize the RTPManager using the SRTP connector
            int versions = zrtpEngine.getNumberSupportedVersions();
            for (int idx = 0; idx < versions; idx++)
                System.err.println("Hello hash: " + zrtpEngine.getHelloHash(idx));
            rtpManager.initialize(transConnector);
            rtpManager.addSendStreamListener(this);

            // open the connection, must be done in connector
            // System.err.println("transconnector-1: " + transConnector);
            transConnector.addTarget(target);

            SendStream sendStream = rtpManager.createSendStream(dataOutput, 0);
            sendStream.start();
        } catch (java.io.IOException ex) {
            System.err.println("Cannot start sendStream: " + ex.getMessage());
        } catch (javax.media.rtp.InvalidSessionAddressException ex) {
            System.err.println("Invalid session address: " + ex.getMessage());
        } catch (javax.media.format.UnsupportedFormatException ex) {
            System.err.println("Unsupported format: " + ex.getMessage());
        }
    }

    public void stopIt() {

        // close the connection if no longer needed.
        transConnector.removeTarget(target);

        // call dispose at the end of the life-cycle of this RTPManager so
        // it is prepared to be garbage-collected.
        rtpManager.dispose();
    }

    SimpleDataSource createDataSource() {
        SimpleDataSource sps = new SimpleDataSource();
        return sps;
    }

    
    public void update(SendStreamEvent evt) {
        System.err.println("TX: SendStreamEvent received: " + evt);
        if (evt instanceof NewSendStreamEvent) {
            SendStream ss = evt.getSendStream();
            System.err.println("My SSRC is: " + ss.getSSRC());
        }
    }
    
    public static void main(String[] args) {

        TransmitterZRTP trans = new TransmitterZRTP();
        trans.run();
        System.err.println("starting send loop");
        for (int i = 0; i < 10; i++) {
            trans.dataOutput.pushData();
            try {
                Thread.sleep(500);
            } catch (InterruptedException ie) {
            }
        }
        trans.stopIt();

        System.exit(0);
    }

}

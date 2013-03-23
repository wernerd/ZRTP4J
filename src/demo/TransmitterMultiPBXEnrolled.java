
package demo;

import gnu.java.zrtp.ZrtpCodes;
import gnu.java.zrtp.ZrtpConstants;
import gnu.java.zrtp.ZrtpUserCallback;
import gnu.java.zrtp.ZrtpConfigure;
import gnu.java.zrtp.jmf.transform.TransformManager;
import gnu.java.zrtp.jmf.transform.zrtp.ZRTPTransformEngine;
import gnu.java.zrtp.jmf.transform.zrtp.ZrtpTransformConnector;

import java.net.*;
import java.util.EnumSet;
import java.util.Iterator;

import javax.media.rtp.*;
import javax.media.rtp.event.NewSendStreamEvent;
import javax.media.rtp.event.SendStreamEvent;

public class TransmitterMultiPBXEnrolled {

    Thread senderThread = null;
    Thread multiSenderThread = null;
    SenderMulti senderFirst = null;
    SenderMulti senderSecond = null;
    
    public class SenderMulti implements SendStreamListener, Runnable {

        public SimpleDataSource dataOutput = null;

        RTPManager rtpManager = null;

        SessionAddress sa = null;

        SessionAddress target = null;

        ZrtpTransformConnector transConnector = null;

        ZRTPTransformEngine zrtpEngine = null;
       
        boolean multiStream = false;
        
        byte[] multiParams = null;

        InetAddress ia = null;
        
        protected class MyCallback extends ZrtpUserCallback {
            
            String prefix = new String("");
            MyCallback() {
            }

            public void secureOn(String cipher) {
                System.err.println(prefix + "Tx Cipher: " + cipher);
            }

            public void showSAS(String sas, boolean verified) {
                System.err.println(prefix + "Tx SAS: " + sas);
            }

            public void showMessage(ZrtpCodes.MessageSeverity sev,
                    EnumSet<?> subCode) {
                Iterator<?> ii = subCode.iterator();
                if (sev == ZrtpCodes.MessageSeverity.Info) {
                    ZrtpCodes.InfoCodes inf = (ZrtpCodes.InfoCodes)ii.next();
                    System.err.println(prefix + "Tx show message sub code: " + inf);
                    if (inf == ZrtpCodes.InfoCodes.InfoSecureStateOn) {
                        senderSecond.setMultiStreamParams(senderFirst.getMultiStreamParams());
                        multiSenderThread.start();
                        
                        /*
                         * The first  (primary) ZRTP session switched to secure mode. 
                         * 
                         * We are testing trusted PBX here: 
                         * get the SAS type (rendering scheme) of he other (often non-enrolled) party
                         * and construct a specific SAS hash value for simpler testing. 
                         * 
                         * Normally the PBX ZRTP relay service would call the other (often non-enrolled)
                         * party's session to retrieve its SAS hash vaule and to forward it to the 
                         * enrolled party.
                         */
                        ZrtpConstants.SupportedSASTypes sasType = senderFirst.zrtpEngine.getSasType();
                        byte[] sasHash = new byte[32];
                        sasHash[0] = 0x11;
                        sasHash[1] = 0x22;
                        sasHash[2] = 0x33;
                        sasHash[4] = 0x44;
                        senderFirst.zrtpEngine.sendSASRelayPacket(sasHash, sasType);
                    }
                    return;
                }
                System.err.println(prefix + "Tx show message sub code: " + ii.next());
            }

            public void zrtpNegotiationFailed(
                    ZrtpCodes.MessageSeverity severity, EnumSet<?> subCode) {
                Iterator<?> ii = subCode.iterator();
                System.err.println(prefix + "Tx negotiation failed sub code: "
                        + ii.next());
            }

            public void secureOff() {
                System.err.println(prefix + "Tx Security off");
            }

            public void zrtpNotSuppOther() {
                System.err.println(prefix + "Tx ZRTP not supported");
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
                System.err.println(prefix + "Tx show message sub code: " + ii.next());
            }

        }

        public SenderMulti() {
            try {
                ia = InetAddress.getByName("localhost");
            } catch (java.net.UnknownHostException ex) {
                System.err.println("Unknown local host: " + ex.getMessage());
            }

            System.err.println("Internet address: " + ia);

        }

        public void init() {
            if (!multiStream) {
                sa = new SessionAddress(ia, 5004);
                target = new SessionAddress(ia, 5002);
            }
            else {
                sa = new SessionAddress(ia, 5004+10);
                target = new SessionAddress(ia, 5002+10);
                
            }
            // create a send stream for the output data source
            dataOutput = createDataSource();

            // create the RTP Manager
            rtpManager = RTPManager.newInstance();

            try {
                // create a ZRTP connector with own bind address
                transConnector = (ZrtpTransformConnector) TransformManager
                        .createZRTPConnector(sa);
                zrtpEngine = transConnector.getEngine();
                
                ZrtpConfigure config = new ZrtpConfigure();
                config.setStandardConfig();
//                config.addHashAlgo(ZrtpConstants.SupportedHashes.S384);
//                config.setMandatoryOnly();
                
                // IMPORTANT: The following mode must be set _before_ intialization
                // - MitM (PBX) mode
                
                zrtpEngine.setMitmMode(true);
                if (!zrtpEngine.initialize("test_mitm_t.zid", config))
                    System.err.println("TX: Initialize failed, multi: "
                            + multiStream);

                int versions = zrtpEngine.getNumberSupportedVersions();
                for (int idx = 0; idx < versions; idx++)
                    System.out.println("Hello hash: " + zrtpEngine.getHelloHash(idx));
                
                // IMPORTANT: set other data only _after_ initialization
                if (multiStream) {
                    MyCallbackMulti mcb = new MyCallbackMulti();
                    mcb.setPrefix("multi - ");
                    zrtpEngine.setUserCallback(mcb);
                    zrtpEngine.setMultiStrParams(multiParams);
                } else {
                    zrtpEngine.setUserCallback(new MyCallback());
                }
                // initialize the RTPManager using the SRTP connector
                rtpManager.addSendStreamListener(this);
                // Add a transmit target, must be done in connector
                transConnector.addTarget(target);
                
                rtpManager.initialize(transConnector);
                
                SendStream sendStream = rtpManager.createSendStream(dataOutput,
                        0);
                sendStream.start();
            } catch (java.io.IOException ex) {
                System.err.println("Cannot start sendStream: "
                        + ex.getMessage());
            } catch (javax.media.rtp.InvalidSessionAddressException ex) {
                System.err.println("Invalid session address: "
                        + ex.getMessage());
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
            // System.err.println("TX: SendStreamEvent received: " + evt);
            if (evt instanceof NewSendStreamEvent) {
                SendStream ss = evt.getSendStream();
                // System.err.println("My SSRC is: " + ss.getSSRC());
                zrtpEngine.setOwnSSRC(ss.getSSRC());
                zrtpEngine.startZrtp();
            }
        }

        byte[] getMultiStreamParams() {
            return zrtpEngine.getMultiStrParams();            
        }

        void setMultiStreamParams(byte[] params) {
            multiParams = params;
            multiStream = true;
        }

        public void run() {
            init();
            System.err.println("starting send loop");
            for (int i = 0; i < 10; i++) {
                dataOutput.pushData();
                try {
                    Thread.sleep(500);
                } catch (InterruptedException ie) {
                }
            }
            try {
                Thread.sleep(500);
            } catch (InterruptedException ie) {
            }
            stopIt();

        }
    }

    public void doIt() {
        senderFirst = new SenderMulti();
        senderThread = new Thread(senderFirst);

        senderSecond = new SenderMulti();
        multiSenderThread = new Thread(senderSecond);

        // start first sender
        senderThread.start();
        try {
            senderThread.join();
        } catch (InterruptedException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        }
        try {
            multiSenderThread.join();
        } catch (InterruptedException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        }
    }
    
    public static void main(String[] args) {

        TransmitterMultiPBXEnrolled trans = new TransmitterMultiPBXEnrolled();
        trans.doIt();
        try {
            Thread.sleep(2000);
        } catch (InterruptedException ie) {
        }

        System.exit(0);
    }

}

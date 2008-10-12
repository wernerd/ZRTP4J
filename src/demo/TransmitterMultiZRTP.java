
package demo;

import gnu.java.zrtp.ZrtpCodes;
import gnu.java.zrtp.ZrtpUserCallback;
import gnu.java.zrtp.jmf.transform.TransformManager;
import gnu.java.zrtp.jmf.transform.zrtp.ZRTPTransformEngine;
import gnu.java.zrtp.jmf.transform.zrtp.ZrtpTransformConnector;

import java.net.*;
import java.util.EnumSet;
import java.util.Iterator;

import java.security.Provider;

import javax.media.rtp.*;
import javax.media.rtp.event.NewSendStreamEvent;
import javax.media.rtp.event.SendStreamEvent;

public class TransmitterMultiZRTP {

    Thread senderThread = null;
    Thread multiSenderThread = null;
    SenderMulti senderFirst = null;
    SenderMulti senderSecond = null;
    Provider cryptoProvider = null;
    
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
            MyCallback() {
            }

            public void secureOn(String cipher) {
                System.err.println("Tx Cipher: " + cipher);
            }

            public void showSAS(String sas, boolean verified) {
                System.err.println("Tx SAS: " + sas);
            }

            public void showMessage(ZrtpCodes.MessageSeverity sev,
                    EnumSet<?> subCode) {
                Iterator<?> ii = subCode.iterator();
                if (sev == ZrtpCodes.MessageSeverity.Info) {
                    ZrtpCodes.InfoCodes inf = (ZrtpCodes.InfoCodes)ii.next();
                    System.err.println("Tx show message sub code: " + inf);
                    if (inf == ZrtpCodes.InfoCodes.InfoSecureStateOn) {
                        senderSecond.setMultiStreamParams(senderFirst.getMultiStreamParams());
                        multiSenderThread.start();
                    }
                    return;
                }
                System.err.println("Tx show message sub code: " + ii.next());
            }

            public void zrtpNegotiationFailed(
                    ZrtpCodes.MessageSeverity severity, EnumSet<?> subCode) {
                Iterator<?> ii = subCode.iterator();
                System.err.println("Tx negotiation failed sub code: "
                        + ii.next());
            }

            public void secureOff() {
                System.err.println("Tx Security off");
            }

            public void zrtpNotSuppOther() {
                System.err.println("Tx ZRTP not supported");
            }

        }

        protected class MyCallbackMulti extends ZrtpUserCallback {
            MyCallbackMulti() {
            }

            public void secureOn(String cipher) {
                System.err.println("Tx Multi Cipher: " + cipher);
            }

            public void showSAS(String sas, boolean verified) {
                System.err.println("Tx Multi SAS: " + sas);
            }

            public void showMessage(ZrtpCodes.MessageSeverity sev,
                    EnumSet<?> subCode) {
                Iterator<?> ii = subCode.iterator();
                System.err.println("Tx Multi show message sub code: " + ii.next());
            }

            public void zrtpNegotiationFailed(
                    ZrtpCodes.MessageSeverity severity, EnumSet<?> subCode) {
                Iterator<?> ii = subCode.iterator();
                System.err.println("Tx Multi negotiation failed sub code: "
                        + ii.next());
            }

            public void secureOff() {
                System.err.println("Tx Multi Security off");
            }

            public void zrtpNotSuppOther() {
                System.err.println("Tx Multi ZRTP not supported");
            }

        }

        public SenderMulti() {
            try {
                ia = InetAddress.getByName("localhost");
            } catch (java.net.UnknownHostException ex) {
                System.err.println("Unknown local host: " + ex.getMessage());
            }

            System.err.println("Internet address: " + ia);
            if (cryptoProvider == null) {
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
            }

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
                // create a SRTP connector with own bind address
                transConnector = (ZrtpTransformConnector) TransformManager
                        .createZRTPConnector(sa);
                zrtpEngine = transConnector.getEngine();
                zrtpEngine.setCryptoProvider(cryptoProvider);
                if (!zrtpEngine.initialize("test_r.zid"))
                    System.err.println("TX: Initialize failed, multi: " + multiStream);

                if (multiStream) {
                   zrtpEngine.setUserCallback(new MyCallbackMulti());
                   zrtpEngine.setMultiStrParams(multiParams);
                }
                else {
                    zrtpEngine.setUserCallback(new MyCallback());
                }
                // initialize the RTPManager using the SRTP connector
                rtpManager.initialize(transConnector);
                rtpManager.addSendStreamListener(this);

                // open the connection, must be done in connector
                System.err.println("transconnector-1: " + transConnector);
                transConnector.addTarget(target);

                SendStream sendStream = rtpManager.createSendStream(dataOutput,
                        0);
                // zrtpEngine.startZrtp();
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
                System.err.println("My SSRC is: " + ss.getSSRC());
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

        TransmitterMultiZRTP trans = new TransmitterMultiZRTP();
        trans.doIt();
        
        System.exit(0);
    }

}

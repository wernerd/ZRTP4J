
package demo;

import java.net.*;

import javax.media.rtp.*;
import javax.media.rtp.event.*;

public class Transmitter implements SendStreamListener {

    public SimpleDataSource dataOutput = null;

    RTPManager rtpManager = null;

    SessionAddress sa = null;

    SessionAddress target = null;

    public Transmitter() {
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
            // initialize the RTPManager
            rtpManager.initialize(sa);
            rtpManager.addSendStreamListener(this);

            // open the connection
            rtpManager.addTarget(target);

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

        try {
            // close the connection if no longer needed.
            rtpManager.removeTarget(target, "client disconnected.");

            // call dispose at the end of the life-cycle of this RTPManager so
            // it is prepared to be garbage-collected.
            rtpManager.dispose();
        } catch (javax.media.rtp.InvalidSessionAddressException ex) {
            System.err.println("Invalid session address: " + ex.getMessage());
        }
    }

    public void update(SendStreamEvent evt) {
        System.err.println("SendStreamEvent received: " + evt);
        if (evt instanceof NewSendStreamEvent) {
            SendStream ss = evt.getSendStream();
            System.err.println("My SSRC is: " + ss.getSSRC());
        }

    }
    
    SimpleDataSource createDataSource() {
        SimpleDataSource sps = new SimpleDataSource();
        return sps;
    }

    public static void main(String[] args) {

        Transmitter trans = new Transmitter();
        trans.run();

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

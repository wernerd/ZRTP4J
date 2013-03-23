/**
 * Copyright (C) 2006-2008 Werner Dittmann
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 * Authors: Werner Dittmann <Werner.Dittmann@t-online.de>
 */

package gnu.java.zrtp;


import gnu.java.zrtp.ZRtp.HelloPacketVersion;
import gnu.java.zrtp.packets.ZrtpPacketBase;
import gnu.java.zrtp.packets.ZrtpPacketCommit;
import gnu.java.zrtp.packets.ZrtpPacketConf2Ack;
import gnu.java.zrtp.packets.ZrtpPacketConfirm;
import gnu.java.zrtp.packets.ZrtpPacketDHPart;
import gnu.java.zrtp.packets.ZrtpPacketError;
import gnu.java.zrtp.packets.ZrtpPacketErrorAck;
import gnu.java.zrtp.packets.ZrtpPacketHello;
import gnu.java.zrtp.packets.ZrtpPacketHelloAck;
import gnu.java.zrtp.packets.ZrtpPacketPing;
import gnu.java.zrtp.packets.ZrtpPacketPingAck;
import gnu.java.zrtp.packets.ZrtpPacketRelayAck;
import gnu.java.zrtp.packets.ZrtpPacketSASRelay;

import java.util.EnumSet;


/**
 * This class is the ZRTP protocol state engine.
 *
 * This class is responsible to handle the ZRTP protocol. It does not
 * handle the ZRTP HMAC, DH, and other data management. This is done in
 * class ZRtp which is the parent of this class.
 *
 * The methods of this class implement the ZRTP state actions.
 *
 * @author Werner Dittmann <Werner.Dittmann@t-online.de>
 *
 */

public class ZrtpStateClass {
    
    private ZRtp parent;

    /*
     * The event to process
     */
    private Event event;

    /*
     * The last packet that was sent.
     *
     * If we are <code>Initiator</code> then resend this packet in case of
     * timeout.
     */
    private ZrtpPacketBase sentPacket = null;

    /*
     * Points to prepared Commit packet after receiving a Hello packet
     */
    private ZrtpPacketCommit commitPkt = null;
    
    /*
     * Timer data to control protocol timeouts
     */
    private ZrtpTimer t1, t2;

    /*
     * If this is set to true the protocol engine handle the multi-stream
     * variant of ZRTP. Refer to chapter 5.4.2 in the ZRTP specification.
     */
    private boolean multiStream = false;

    /*
     * The state we are in
     */
    private ZrtpStates inState;
    
    /*
     * The secure substate
     */
    private SecureSubStates secSubstate = SecureSubStates.Normal;
    /*
     * Offset to the first message type byte in ZRTP packet 
     */
    private static final int MESSAGE_OFFSET = 4; 

    /**
     * Hello packet version sent to other partner
     */
    private int sentVersion;

    //  The ZRTP states
    public enum ZrtpStates {
        Initial,
        Detect,
        AckDetected,
        AckSent,
        WaitCommit,
        CommitSent,
        WaitDHPart2,
        WaitConfirm1,
        WaitConfirm2,
        WaitConfAck,
        WaitClearAck,
        SecureState,
        WaitErrorAck,
        numberOfStates
    }

    public enum SecureSubStates {
        Normal,
        WaitSasRelayAck,
        numberofSecureSubStates
    }
    
    protected enum EventDataType {
        ZrtpInitial,
        ZrtpClose,
        ZrtpPacket,
        Timer,
        ErrorPkt
    }

    protected class Event {
        private  EventDataType type;
        private byte[] packet;

        public Event(EventDataType evt, byte[] pckt) {
            type = evt;
            packet = pckt;
        }

        /**
         * @return the packet
         */
        protected byte[] getPacket() {
            return packet;
        }

        /**
         * @return the type
         */
        protected EventDataType getType() {
            return type;
        }
    }

    /**
     * The ZRTP timer structure.
     *
     * This structure holds all necessary data to compute the timer for
     * the protocol timers. The state engine allocate one structure for
     * each timer. ZRTP uses two timers, T1 and T2, to monitor protocol
     * timeouts. As a slight misuse but to make overall handling a bit
     * simpler this structure also contains the resend counter. This is
     * possible in ZRTP because it uses a simple timeout strategy.
     */
    private class ZrtpTimer {
        int time,
        start,
        capping,
        counter,
        maxResend;
        
        ZrtpTimer(int s, int r, int c) {
            start = s;
            capping = c;
            maxResend = r;
        }
        
        int startTimer() {
            time = start;
            counter = 0;
            return time;
        }
        
        int nextTimer() {
            time += time;
            time = (time > capping)? capping : time;
            counter++;
            if (counter > maxResend) {
                return -1;
            }
            return time;
        }
        
        void setMaxResend(int newResend) {
            maxResend = newResend;
        }
    }

    protected ZrtpStateClass(ZRtp p) {
        parent = p;

        // Set up timers according to ZRTP spec
        t1 = new ZrtpTimer(50, 20, 200);
        t2 = new ZrtpTimer(150, 10, 600);
        
        inState = ZrtpStates.Initial;

    }

    public long getTimeoutValue() {
        long res = 0;
        int counter = 0;
        int time = t1.start;

        do {
            res += time;
            time += time;
            time = (time > t1.capping)? t1.capping : time;
            counter++;
        }
        while(counter < t1.maxResend);

        return res;
    }

    protected synchronized void processEvent(Event ev) {

        char first, middle, last;
        byte[] pkt;

        event = ev;

        if (event.type == EventDataType.ZrtpPacket) {
            pkt = event.packet;

            first = (char) pkt[MESSAGE_OFFSET];
            first = Character.toLowerCase(first);
            middle = (char) pkt[MESSAGE_OFFSET + 4];
            middle = Character.toLowerCase(middle);
            last = (char) pkt[MESSAGE_OFFSET + 7];
            last = Character.toLowerCase(last);

            // Check if this is an Error packet.
            if (first == 'e' && middle == 'r' && last == ' ') {
                /*
                 * Process a received Error packet.
                 * 
                 * In any case stop timer to prevent resending packets. Use
                 * callback method to prepare and get an ErrorAck packet. Modify
                 * event type to "ErrorPkt" and hand it over to current state
                 * for further processing.
                 */
                cancelTimer();
                ZrtpPacketError epkt = new ZrtpPacketError(pkt);
                ZrtpPacketErrorAck eapkt = parent.prepareErrorAck(epkt);
                parent.sendPacketZRTP(eapkt);
                event.type = EventDataType.ErrorPkt;
            // Check for Ping packet
            } else if (first == 'p' && middle == ' ' && last == ' ') {
                ZrtpPacketPing ppkt = new ZrtpPacketPing(pkt);
                ZrtpPacketPingAck ppktAck = parent.preparePingAck(ppkt);
                parent.sendPacketZRTP(ppktAck);
                return;
            } else if (first == 's' && last == 'y') {
                ZrtpCodes.ZrtpErrorCodes[] errorCode = new ZrtpCodes.ZrtpErrorCodes[1];
                ZrtpPacketSASRelay srly = new ZrtpPacketSASRelay(pkt);
                ZrtpPacketRelayAck rapkt = parent.prepareRelayAck(srly, errorCode);
                parent.sendPacketZRTP(rapkt);
                return;
            }
        }
        /*
         * Shut down protocol state engine: cancel outstanding timer, further
         * processing in current state.
         */
        else if (event.type == EventDataType.ZrtpClose) {
            cancelTimer();
        }
        dispatchEvent();
    }

    protected void stopZrtpStates() {

        // If not in Initial state: close the protocol engine
        // before destroying it. This will free pending packets
        // if necessary.
        if (inState != ZrtpStates.Initial) {
            cancelTimer();
            event = new Event(EventDataType.ZrtpClose, null);

            dispatchEvent();
        }
    }

    protected void dispatchEvent() {
 
        switch (inState) {
        case Initial:
            evInitial();
            break;

        case Detect:
            evDetect();
            break;

        case AckDetected:
            evAckDetected();
            break;

        case AckSent:
            evAckSent();
            break;

        case WaitCommit:
            evWaitCommit();
            break;

        case CommitSent:
            evCommitSent();
            break;

        case WaitDHPart2:
            evWaitDHPart2();
            break;

        case WaitConfirm1:
            evWaitConfirm1();
            break;

        case WaitConfirm2:
            evWaitConfirm2();
            break;

        case WaitConfAck:
            evWaitConfAck();
            break;

        case WaitClearAck:
            evWaitClearAck();
            break;

        case SecureState:
            evSecureState();
            break;

        case WaitErrorAck:
            evWaitErrorAck();
            break;

        default:
            break;
        }
    }
    
    
    protected void evInitial() {

        if (event.type == EventDataType.ZrtpInitial) {
            ZrtpPacketHello hello = parent.prepareHello();
            sentVersion = hello.getVersionInt();

            // remember packet for easy resend in case timer triggers
            sentPacket = hello;

            if (!parent.sendPacketZRTP(sentPacket)) {
                sendFailed(); // returns to state Initial
                return;
            }
            if (startTimer(t1) <= 0) {
                // returns to state Initial
                timerFailed(ZrtpCodes.SevereCodes.SevereNoTimer);
                return;
            }
            inState = ZrtpStates.Detect;
        }
    }

    /*
     * Detect state.
     *
     * When in this state the protocol engine sent an initial Hello packet
     * to the peer.
     *
     * When entering this state transition function then:
     * - Assume Initiator mode, mode may change later on peer reaction
     * - Instance variable sentPacket contains the sent Hello packet
     * - Hello timer T1 may be active. This is the case if the other peer
     *   has prepared its RTP session and answers our Hello packets nearly 
     *   immediately, i.e. before the Hello timeout counter expires. If the
     *   other peer does not send a Hello during this time the state engine
     *   reports "other peer does not support ZRTP" but stays
     *   in state Detect with no active timer (passiv mode). Staying in state 
     *   Detect allows another peer to start its detect phase any time later.
     *
     *   This restart capability is the reason why we use "startTimer(&T1)" in 
     *   case we received a Hello packet from another peer. This effectively 
     *   restarts the Hello timeout counter.
     *
     *   In this state we also handle ZrtpInitialize event. This forces a
     *   restart of ZRTP discovery if an application calls ZrtpQueue#startZrtp
     *   again. This may happen after a previous discovery phase were not 
     *   successful.
     *
     *   Usually applications use some sort of signaling protocol, for example
     *   SIP, to negotiate the RTP parameters. Thus the RTP sessions setup is
     *   fairly sychronized and thus also the ZRTP detection phase. Applications
     *   that use some other ways to setup the RTP sessions this restart capability
     *   comes in handy because no RTP setup sychronization is necessary.
     * 
     * Possible events in this state are:
     * - timeout for sent Hello packet: causes a resend check and 
     *   repeat sending of Hello packet
     * - received a HelloAck: stop active timer, prepare and send Hello packet,
     *   switch to state AckDeteced.
     * - received a Hello: stop active timer, send HelloAck, prepare Commit 
     *   packet, switch to state AckSent.
     *
     */
    private void evDetect() {

        char first, last;
        byte[] pkt;
        ZrtpCodes.ZrtpErrorCodes[] errorCode = new ZrtpCodes.ZrtpErrorCodes[1];

        /*
         * First switch according the general event type, then 
         * discrimnate the real event.
         */
        switch (event.type) {
        case ZrtpPacket:
            pkt = event.packet;

            first = (char) pkt[MESSAGE_OFFSET];
            first = Character.toLowerCase(first);
            last = (char) pkt[MESSAGE_OFFSET + 7];
            last = Character.toLowerCase(last);
            /*
             * HelloAck: 
             * - our peer acknowledged our Hello packet 
             * - cancel timer T1 to stop resending Hello 
             * - switch to state AckDetected, wait for peer's Hello (F3)
             */
            if (first == 'h' && last == 'k') {
                cancelTimer();
                sentPacket = null;
                inState = ZrtpStates.AckDetected;
                return;
            }
            /*
             * Hello: 
             * - send HelloAck packet to acknowledge the received Hello
             *   packet 
             * - use received Hello packet to prepare own Commit packet.
             *   We need to do it at this point because we need the hash value
             *   computed from peer's Hello packet. Follwing states my use the
             *   prepared Commit. 
             * - switch to new state AckSent which sends own Hello packet (F3)
             *   until peer acknowledges this 
             * - Don't clear sentPacket, points to Hello
             */
            if (first == 'h' && last == ' ') {
                // Use peer's Hello packet to create my commit packet, store it
                // for possible later usage in state AckSent
                ZrtpPacketHello hpkt = new ZrtpPacketHello(pkt);
                cancelTimer();

                /*
                 * Check and negotiate the ZRTP protocol version first.
                 *
                 * This selection mechanism relies on the fact that we sent the highest supported protocol version in
                 * the initial Hello packet with as stated in RFC6189, section 4.1.1
                 */
                int recvVersion = hpkt.getVersionInt();
                if (recvVersion > sentVersion) {   // We don't support this version, stay in state with timer active
                    if (startTimer(t1) <= 0) {
                        timerFailed(ZrtpCodes.SevereCodes.SevereNoTimer);      // returns to state Initial
                    }
                    return;
                }

                /*
                 * The versions don't match. Start negotiating versions. This negotiation stays in the Detect state.
                 * Only if the received version matches our own sent version we start to send a HelloAck.
                 */
                if (recvVersion != sentVersion) {
                    HelloPacketVersion hpv[] = parent.helloPackets;

                    int index;
                    for (index = 0; index < ZRtp.MAX_ZRTP_VERSIONS && hpv[index].packet != parent.currentHelloPacket; index++)   // Find current sent Hello
                        ;

                    for(; index >= 0 && hpv[index].version > recvVersion; index--)   // find a supported version less-equal to received version
                        ;

                    if (index < 0) {
                        sendErrorPacket(ZrtpCodes.ZrtpErrorCodes.UnsuppZRTPVersion);
                        return;
                    }
                    parent.currentHelloPacket = hpv[index].packet;
                    sentVersion = parent.currentHelloPacket.getVersionInt();

                    // remember packet for easy resend in case timer triggers
                    sentPacket = parent.currentHelloPacket;

                    if (!parent.sendPacketZRTP(sentPacket)) {
                        sendFailed();                 // returns to state Initial
                        return;
                    }
                    if (startTimer(t1) <= 0) {
                        timerFailed(ZrtpCodes.SevereCodes.SevereNoTimer);      // returns to state Initial
                        return;
                    }
                    return;
                }                
                ZrtpPacketHelloAck helloAck = parent.prepareHelloAck();

                if (!parent.sendPacketZRTP(helloAck)) {
                    parent.zrtpNegotiationFailed(
                            ZrtpCodes.MessageSeverity.Severe,
                            EnumSet.of(ZrtpCodes.SevereCodes.SevereCannotSend));
                    return;
                }
                commitPkt = parent.prepareCommit(hpkt, errorCode);

                inState = ZrtpStates.AckSent;
                if (commitPkt == null) {
                    sendErrorPacket(errorCode[0]); // switches to Error state
                    return;
                }
                if (startTimer(t1) <= 0) { // restart own Hello timer/counter
                    // returns to state Initial
                    timerFailed(ZrtpCodes.SevereCodes.SevereNoTimer); // Initial
                }
                t1.setMaxResend(60);        // this give >12 seconds, see chapter 6
            }
            break;
            
        // Timer event triggered - this is Timer T1 to resend Hello
        case Timer:
            if (!parent.sendPacketZRTP(sentPacket)) {
                sendFailed(); // returns to state Initial
                return;
            }
            if (nextTimer(t1) <= 0) {
                commitPkt = null;
                parent.zrtpNotSuppOther();
                inState = ZrtpStates.Detect;
            }
            break;
        
        // If application call zrtpStart() to restart discovery
        case ZrtpInitial:
            cancelTimer();
            if (!parent.sendPacketZRTP(sentPacket)) {
                sendFailed(); // returns to state Initial
                return;
            }
            if (startTimer(t1) <= 0) {
                // returns to state Initial
                timerFailed(ZrtpCodes.SevereCodes.SevereNoTimer);
            }
            break;
            
        default: // unknown Event type for this state (covers Error and
            // ZrtpClose)
            if (event.type != EventDataType.ZrtpClose) {
                parent.zrtpNegotiationFailed(ZrtpCodes.MessageSeverity.Severe,
                        EnumSet.of(ZrtpCodes.SevereCodes.SevereProtocolError));
            }
            sentPacket = null;
            inState = ZrtpStates.Initial;
        }

    }

    /*
     * AckDetected state.
     * 
     * The protocol engine received a HelloAck in state Detect, thus the peer
     * acknowledged our the Hello. According to ZRTP RFC xxxx our peer must send
     * its Hello until our protocol engine sees it (refer also to comment for
     * state AckSent). This protocol sequence gurantees that both peers got at
     * least one Hello.
     * 
     * When entering this transition function 
     * - instance variable sentPacket is NULL, Hello timer stopped
     * 
     * Possible events in this state are: 
     * Hello: 
     * we have to choices:
     *  1) we can acknowledge the peer's Hello with a HelloAck 
     *  2) we can acknowledge the peer's Hello with a Commit 
     * 
     * Both choices are implemented and may be enabled by un-commenting the 
     * code. Currently we use choice 1) here.
     */

    protected void evAckDetected() {
        char first, last;
        byte[] pkt;
        ZrtpCodes.ZrtpErrorCodes[] errorCode = new ZrtpCodes.ZrtpErrorCodes[1];

        switch (event.type) {
        case ZrtpPacket:
            pkt = event.packet;

            first = (char) pkt[MESSAGE_OFFSET];
            first = Character.toLowerCase(first);
            last = (char) pkt[MESSAGE_OFFSET + 7];
            last = Character.toLowerCase(last);
 
            /*
             * Implementation for choice 1)
             * Hello:
             * - Acknowledge peers Hello, sending HelloACK (F4)
             * - switch to state WaitCommit, wait for peer's Commit
             * - we are going to be in the Responder role
             */

            if (first == 'h' && last == ' ') {
                // Parse Hello packet and build an own Commit packet even if the
                // Commit is not send to the peer. We need to do this to check the
                // Hello packet and prepare the shared secret stuff.
                ZrtpPacketHello hpkt = new ZrtpPacketHello(pkt);
                ZrtpPacketCommit commit = parent.prepareCommit(hpkt, errorCode);

                // Something went wrong during processing of the Hello packet, for
                // example wrong version, duplicate ZID.
                if (commit == null) {
                    sendErrorPacket(errorCode[0]);
                    return;
                }
                ZrtpPacketHelloAck helloAck = parent.prepareHelloAck();
                inState = ZrtpStates.WaitCommit;

                // remember packet for easy resend
                sentPacket = helloAck;
                if (!parent.sendPacketZRTP(helloAck)) {
                    sendFailed();
                }
            }


            /*
             * Implementation for choice 2)
             * Hello:
             * - Acknowledge peers Hello by sending Commit (F5)
             *   instead of HelloAck (F4)
             * - switch to state CommitSent
             * - Initiator role, thus start timer T2 to monitor timeout for Commit
             *

            if (first == 'h' && last == ' ') {
                // Parse peer's packet data into a Hello packet
                ZrtpPacketHello hpkt = new ZrtpPacketHello(pkt);
                ZrtpPacketCommit commit = parent.prepareCommit(hpkt, errorCode);
                // Something went wrong during processing of the Hello packet  
                if (commit == null) {
                    sendErrorPacket(EnumSet.of(errorCode[0]));
                    return;
                }
                inState = ZrtpStates.CommitSent;

                // remember packet for easy resend in case timer triggers
                // Timer trigger received in new state CommitSend
                sentPacket = commit;
                if (!parent.sendPacketZRTP(sentPacket)) {
                    sendFailed();
                    return;
                }
                if (startTimer(t2) <= 0) {
                    timerFailed(ZrtpCodes.SevereCodes.SevereNoTimer);
                }
            }
            */
            break;

        default:  // default Event type for this state (covers Error and ZrtpClose)
            if (event.type != EventDataType.ZrtpClose) {
                parent.zrtpNegotiationFailed(ZrtpCodes.MessageSeverity.Severe,
                        EnumSet.of(ZrtpCodes.SevereCodes.SevereProtocolError));
            }
            inState = ZrtpStates.Initial;
        }
    }

    /*
     * AckSent state.
     *
     * The protocol engine got a Hello packet from peer and answered with a
     * HelloAck response.  According to the protocol we must also send a 
     * Hello after HelloAck (refer to figure 1 in ZRTP RFC xxxx, message 
     * HelloACK (F2) must be followed by Hello (F3)). We use the timeout in 
     * this state to send the required Hello (F3).
     *
     * Our peer can acknowledge the Hello either with HelloAck or Commit.
     * Figure 1 shows the HelloAck, chapter 7 states that a Commit may be send 
     * to acknowledge Hello. There is one constraint when using a Commit to
     * acknowledge Hello: refer to chapter 4.1 that requires that both parties
     * have completed the Hello/HelloAck discovery handshake. This implies that 
     * only message F4 may be replaced by a Commit. This constraint guarantees
     * that both peers have seen at least one Hello.
     *
     * When entering this transition function:
     * - The instance variabe sentPacket contains own Hello packet
     * - The instance variabe commitPkt points to prepared Commit packet 
     * - Timer T1 is active
     *
     * Possible events in this state are:
     * - timeout for sent Hello packet: causes a resend check and repeat sending
     *   of Hello packet
     * - HelloAck: The peer answered with HelloAck to own HelloAck/Hello. Send
     *   prepared Commit packet and try Initiator mode.
     * - Commit: The peer answered with Commit to HelloAck/Hello, thus switch to
     *   responder mode.
     * - Hello: If the protcol engine receives another Hello it repeats the 
     *   HelloAck/Hello response until Timer T1 exceeds its maximum. This may 
     *   happen if the other peer sends Hello only (maybe due to network problems)
     */
    protected void evAckSent() {

        char first, last;
        byte[] pkt;
        ZrtpCodes.ZrtpErrorCodes[] errorCode = new ZrtpCodes.ZrtpErrorCodes[1];

        /*
         * First check the general event type, then discrimnate
         * the real event.
         */
        switch(event.type) {
        
        case ZrtpPacket:
            pkt = event.packet;

            first = (char) pkt[MESSAGE_OFFSET];
            first = Character.toLowerCase(first);
            last = (char) pkt[MESSAGE_OFFSET + 7];
            last = Character.toLowerCase(last);

            /*
             * HelloAck:
             * The peer answers with HelloAck to own HelloAck/Hello. Send Commit
             * and try Initiator mode. The requirement defined in chapter 4.1 to
             * have a complete Hello/HelloAck is fulfilled.
             * - stop Hello timer T1
             * - send own Commit message
             * - switch state to CommitSent, start Commit timer, assume Initiator
             */
            if (first == 'h' && last == 'k') {
                cancelTimer();

                // remember packet for easy resend in case timer triggers
                // Timer trigger received in new state CommitSend
                sentPacket = commitPkt;
                commitPkt = null; // now stored in sentPacket
                inState = ZrtpStates.CommitSent;
                if (!parent.sendPacketZRTP(sentPacket)) {
                    sendFailed(); // returns to state Inital
                    return;
                }
                if (startTimer(t2) <= 0) {
                    timerFailed(ZrtpCodes.SevereCodes.SevereNoTimer); // to Initial
                }
                return;
            }
            /*
             * Hello: 
             * - peer didn't receive our HelloAck 
             * - repeat HelloAck/Hello response:
             *  -- get HelloAck packet, send it
             *  -- The timeout trigger of T1 sends our Hello packet
             *  -- stay in state AckSent
             * 
             * Similar to Detect state: just acknowledge the Hello, the next
             * timeout sends the following Hello.
             */

            if (first == 'h' && last ==' ') {
                ZrtpPacketHelloAck helloAck = parent.prepareHelloAck();

                if (!parent.sendPacketZRTP(helloAck)) {
                    inState = ZrtpStates.Detect;
                    parent.zrtpNegotiationFailed(ZrtpCodes.MessageSeverity.Severe,
                            EnumSet.of(ZrtpCodes.SevereCodes.SevereCannotSend));
                }
                return;
            }
            /*
             * Commit:
             * The peer answers with Commit to HelloAck/Hello, thus switch to
             * responder mode.
             * - stop timer T1
             * - prepare and send our DHPart1
             * - switch to state WaitDHPart2 and wait for peer's DHPart2
             * - don't start timer, we are responder
             */
            if (first == 'c') {
                cancelTimer();
                ZrtpPacketCommit cpkt = new ZrtpPacketCommit(pkt);

                if (!multiStream) {
                    ZrtpPacketDHPart dhPart1 = parent.prepareDHPart1(cpkt, errorCode);
                   // Error detected during processing of received commit
                    // packet
                    if (dhPart1 == null) {
                        if (errorCode[0] != ZrtpCodes.ZrtpErrorCodes.IgnorePacket) {
                            sendErrorPacket(errorCode[0]);
                        }
                        return;
                    }
                    commitPkt = null;
                    inState = ZrtpStates.WaitDHPart2;

                    // remember packet for easy resend in new state
                    sentPacket = dhPart1;
                } else {
                    ZrtpPacketConfirm confirm = parent.prepareConfirm1MultiStream(cpkt, errorCode);

                    // Something went wrong during processing of the Commit packet
                    if (confirm == null) {
                        if (errorCode[0] != ZrtpCodes.ZrtpErrorCodes.IgnorePacket) {
                            sendErrorPacket(errorCode[0]);
                        }
                        return;
                    }
                    sentPacket = confirm;
                    inState = ZrtpStates.WaitConfirm2;
                }
                if (!parent.sendPacketZRTP(sentPacket)) {
                    sendFailed();      // returns to state Initial
                }
            }
            break;
 
            /*
             * Timer: 
             * - resend Hello packet, stay in state, restart timer until
             *   repeat counter triggers 
             * - if repeat counter triggers switch to state Detect, 
             *   don't clear sentPacket, Detect requires it to point
             *   to own Hello message
             */
        case Timer:
            if (!parent.sendPacketZRTP(sentPacket)) {
                sendFailed();      // returns to state Initial
                return;
            }
            if (nextTimer(t1) <= 0) {
                parent.zrtpNotSuppOther();
                commitPkt = null;
                // Switch to state Detect to be prepared to get a hello from
                // other peer any time later
                inState = ZrtpStates.Detect;
            }
            break;

        default:   // deafult Event type for this state (covers Error and ZrtpClose)
            if (event.type != EventDataType.ZrtpClose) {
                parent.zrtpNegotiationFailed(ZrtpCodes.MessageSeverity.Severe,
                        EnumSet.of(ZrtpCodes.SevereCodes.SevereProtocolError));
            }
            commitPkt = null;
            sentPacket = null;
            inState = ZrtpStates.Initial;
            break;
        }
    }

    /*
     * WaitCommit state.
     *
     * This state is only used if we use choice 1) in AckDetected.
     *
     * When entering this transition function
     * - instance variable sentPacket contains a HelloAck packet
     * 
     * Possible events in this state are:
     * - Hello: just resend our HelloAck
     * - Commit: prepare and send our DHPart1 message to start first
     *   half of DH key agreement. Switch to state WaitDHPart2, don't
     *   start any timer, we are Responder.
     */
    protected void evWaitCommit() {
        char first, last;
        byte[] pkt;
        ZrtpCodes.ZrtpErrorCodes[] errorCode = new ZrtpCodes.ZrtpErrorCodes[1];

        /*
         * First check the general event type, then discrimnate the real event.
         */
        switch (event.type) {
            
        case ZrtpPacket:
            pkt = event.packet;

            first = (char) pkt[MESSAGE_OFFSET];
            first = Character.toLowerCase(first);
            last = (char) pkt[MESSAGE_OFFSET + 4];
            last = Character.toLowerCase(last);

            
            /*
             * Hello:
             * - resend HelloAck
             * - stay in WaitCommit
             */
            if (first == 'h') {
                if (!parent.sendPacketZRTP(sentPacket)) {
                    sendFailed();       // returns to state Initial
                }
                return;
            }
            /*
             * Commit:
             * - prepare DH1Part packet or Confirm1 if multi stream mode
             * - send it to peer
             * - switch state to WaitDHPart2 or WaitConfirm2 if multi stream mode
             * - don't start timer, we are responder
             */
            if (first == 'c') {
                ZrtpPacketCommit cpkt = new ZrtpPacketCommit(pkt);
                
                if (!multiStream) {
                    ZrtpPacketDHPart dhPart1 = parent.prepareDHPart1(cpkt,
                            errorCode);

                    // Something went wrong during processing of the Commit
                    // packet
                    if (dhPart1 == null) {
                        if (errorCode[0] != ZrtpCodes.ZrtpErrorCodes.IgnorePacket) {
                            sendErrorPacket(errorCode[0]);
                        }
                        return;
                    }
                    sentPacket = dhPart1;
                    inState = ZrtpStates.WaitDHPart2;
                } else {
                    ZrtpPacketConfirm confirm = parent.prepareConfirm1MultiStream(cpkt, errorCode);

                    // Something went wrong during processing of the Commit packet
                    if (confirm == null) {
                        if (errorCode[0] != ZrtpCodes.ZrtpErrorCodes.IgnorePacket) {
                            sendErrorPacket(errorCode[0]);
                        }
                        return;
                    }
                    sentPacket = confirm;
                    inState = ZrtpStates.WaitConfirm2;
                }
                if (!parent.sendPacketZRTP(sentPacket)) {
                    sendFailed();       // returns to state Initial
                }
            }
            break;

        default:  // unknown Event type for this state (covers Error and ZrtpClose)
            if (event.type != EventDataType.ZrtpClose) {
                parent.zrtpNegotiationFailed(ZrtpCodes.MessageSeverity.Severe,
                        EnumSet.of(ZrtpCodes.SevereCodes.SevereProtocolError));
            }
            commitPkt = null;
            sentPacket = null;
            inState = ZrtpStates.Initial;
            break;
        }

    }

    /*
     * CommitSent state.
     *
     * This state either handles a DH1Part1 message to start the first
     * half of DH key agreement or it handles a Commit clash. If handling a
     * Commit clash it may happen that we change our role from Initiator to
     * Responder.
     *
     * When entering this transition function
     * - assume Initiator mode, may change if we reveice a Commit here
     * - sentPacket contains Commit packet
     * - Commit timer (T2) active
     *
     * Possible events in this state are:
     * - timeout for sent Commit packet: causes a resend check and repeat sending
     *   of Commit packet
     * - Commit: This is a Commit clash. Break the tie accroding to chapter 5.2
     * - DHPart1: start first half of DH key agreement. Perpare and send own DHPart2
     *   and switch to state WaitConfirm1.
     */
    protected void evCommitSent() {
        char first, last;
        byte[] pkt;
        ZrtpCodes.ZrtpErrorCodes[] errorCode = new ZrtpCodes.ZrtpErrorCodes[1];

        /*
         * First check the general event type, then discrimnate the real event.
         */
        switch (event.type) {
        
        case ZrtpPacket:
            pkt = event.packet;

            first = (char) pkt[MESSAGE_OFFSET];
            first = Character.toLowerCase(first);
            last = (char) pkt[MESSAGE_OFFSET + 7];
            last = Character.toLowerCase(last);

            /*
             * HelloAck or Hello:
             * - delayed "HelloAck" or "Hello", maybe due to network latency, just 
             *   ignore it
             * - no switch in state, leave timer as it is
             */
            if (first == 'h' && (last =='k' || last == ' ')) {
                return;
            }

            /*
             * Commit:
             * We have a "Commit" clash. Resolve it.
             *
             * - switch off resending Commit
             * - compare my hvi with peer's hvi
             * - if my hvi is greater
             *   - we are Initiator, stay in state, wait for peer's DHPart1 packet
             *  - else
             *   - we are Responder, stop timer
             *   - prepare and send DH1Packt,
             *   - switch to state WaitDHPart2, implies Responder path
             */
            if (first == 'c' && last == ' ') {
                ZrtpPacketCommit zpCo = new ZrtpPacketCommit(pkt);

                if (!parent.verifyH2(zpCo)) {
                    return;
                }
                cancelTimer();         // this cancels the Commit timer T2

                // if our hvi is less than peer's hvi: switch to Responder mode and
                // send DHPart1 packet. Peer (as Initiator) will retrigger if
                // necessary
                //
                if (parent.compareCommit(zpCo) < 0) {
                    if (!multiStream) {
                        ZrtpPacketDHPart dhPart1 = parent.prepareDHPart1(zpCo,
                                errorCode);

                        // Something went wrong during processing of the Commit
                        // packet
                        if (dhPart1 == null) {
                            if (errorCode[0] != ZrtpCodes.ZrtpErrorCodes.IgnorePacket) {
                                sendErrorPacket(errorCode[0]);
                            }
                            return;
                        }
                        inState = ZrtpStates.WaitDHPart2;
                        sentPacket = dhPart1;
                    } else {
                        ZrtpPacketConfirm confirm = parent.prepareConfirm1MultiStream(zpCo, errorCode);

                        // Something went wrong during processing of the Commit packet
                        if (confirm == null) {
                            if (errorCode[0] != ZrtpCodes.ZrtpErrorCodes.IgnorePacket) {
                                sendErrorPacket(errorCode[0]);
                            }
                            return;
                        }
                        sentPacket = confirm;
                        inState = ZrtpStates.WaitConfirm2;

                    }
                    if (!parent.sendPacketZRTP(sentPacket)) {
                        sendFailed();       // returns to state Initial
                    }
                }
                // Stay in state, we are Initiator, wait for DHPart1 packet from peer.
                // Resend Commit after timeout until we get a DHPart1
                else {
                    if (startTimer(t2) <= 0) { // restart the Commit timer, gives peer more time to react
                        timerFailed(ZrtpCodes.SevereCodes.SevereNoTimer);
                    }
                }
                return;
            }

            /*
             * DHPart1:
             * - switch off resending Commit
             * - Prepare and send DHPart2
             * - switch to WaitConfirm1
             * - start timer to resend DHPart2 if necessary, we are Initiator
             */
            if (first == 'd') {
                ZrtpPacketDHPart dpkt = new ZrtpPacketDHPart(pkt);
                ZrtpPacketDHPart dhPart2 = parent.prepareDHPart2(dpkt, errorCode);

                // Something went wrong during processing of the DHPart1 packet
                if (dhPart2 == null) {
                    if (errorCode[0] != ZrtpCodes.ZrtpErrorCodes.IgnorePacket) {
                        sendErrorPacket(errorCode[0]);
                    }
                    return;
                }
                cancelTimer();
                sentPacket = dhPart2;
                inState = ZrtpStates.WaitConfirm1;

                if (!parent.sendPacketZRTP(sentPacket)) {
                    sendFailed();       // returns to state Initial
                    return;
                }
                if (startTimer(t2) <= 0) {
                    timerFailed(ZrtpCodes.SevereCodes.SevereNoTimer);       // returns to state Initial
                }
            }
            
            if (multiStream && (first == 'c' && last == '1')) {
                cancelTimer();
                ZrtpPacketConfirm cpkt = new ZrtpPacketConfirm(pkt);

                ZrtpPacketConfirm confirm = parent.prepareConfirm2MultiStream(cpkt, errorCode);

                // Something went wrong during processing of the Confirm1 packet
                if (confirm == null) {
                    sendErrorPacket(errorCode[0]);
                    return;
                }
                inState = ZrtpStates.WaitConfAck;
                sentPacket = confirm;

                if (!parent.sendPacketZRTP(sentPacket)) {
                    sendFailed();         // returns to state Initial
                    return;
                }
                if (startTimer(t2) <= 0) {
                    timerFailed(ZrtpCodes.SevereCodes.SevereNoTimer);  // returns to state Initial
                }
                if (!parent.srtpSecretsReady(ZrtpCallback.EnableSecurity.ForReceiver)) {
                    parent.sendInfo(ZrtpCodes.MessageSeverity.Severe, EnumSet
                            .of(ZrtpCodes.SevereCodes.SevereSecurityException));
                    sendErrorPacket(ZrtpCodes.ZrtpErrorCodes.CriticalSWError);
                    return;
                }
            }
            break;
            
        // Timer event triggered, resend the Commit packet
        case Timer:
            if (!parent.sendPacketZRTP(sentPacket)) {
                    sendFailed();       // returns to state Initial
                    return;
            }
            if (nextTimer(t2) <= 0) {
                timerFailed(ZrtpCodes.SevereCodes.SevereTooMuchRetries);       // returns to state Initial
            }
            break;

        default:  // unknown Event type for this state (covers Error and ZrtpClose)
            if (event.type != EventDataType.ZrtpClose) {
                parent.zrtpNegotiationFailed(ZrtpCodes.MessageSeverity.Severe,
                        EnumSet.of(ZrtpCodes.SevereCodes.SevereProtocolError));
            }
            sentPacket = null;
            inState = ZrtpStates.Initial;
        }
    }

    /*
     * WaitDHPart2 state.
     *
     * This state handles the second part of SH key agreement. Only the Resonder
     * can enter this state.
     *
     * When entering this transition function
     * - sentPacket contains DHPart1 packet, no timer active
     *
     * Possible events in this state are:
     * - Commit: Our peer didn't receive out DHPart1 thus the peer sends Commit again.
     *   Just repeat our DHPart1.
     * - DHPart2: start second half of DH key agreement. Perpare and send own Confirm1
     *   and switch to state WaitConfirm2.
     */
    protected void evWaitDHPart2() {

        char first, last;
        byte[] pkt;
        ZrtpCodes.ZrtpErrorCodes[] errorCode = new ZrtpCodes.ZrtpErrorCodes[1];

        /*
         * First check the general event type, then discrimnate the real event.
         */
        switch (event.type) {
        
        case ZrtpPacket:
            pkt = event.packet;

            first = (char) pkt[MESSAGE_OFFSET];
            first = Character.toLowerCase(first);
            last = (char) pkt[MESSAGE_OFFSET + 7];
            last = Character.toLowerCase(last);
            
            /*
             * Commit:
             * - resend DHPart1
             * - stay in state
             */
            if (first == 'c') {
                if (!parent.sendPacketZRTP(sentPacket)) {
                    sendFailed();       // returns to state Initial
                }
                return;
            }
            /*
             * DHPart2:
             * - prepare Confirm1 packet
             * - switch to WaitConfirm2
             * - No timer, we are responder
             */
            if (first == 'd') {
                ZrtpPacketDHPart dpkt = new ZrtpPacketDHPart(pkt);
                ZrtpPacketConfirm confirm = parent.prepareConfirm1(dpkt, errorCode);

                if (confirm == null) {
                    if (errorCode[0] != ZrtpCodes.ZrtpErrorCodes.IgnorePacket) {
                        sendErrorPacket(errorCode[0]);
                    }
                    return;
                }
                inState = ZrtpStates.WaitConfirm2;
                sentPacket = confirm;
                if (!parent.sendPacketZRTP(sentPacket)) {
                    sendFailed();       // returns to state Initial
                }
            }
            break;
            
        default:        // unknown Event type for this state (covers Error and
                        // ZrtpClose)
            if (event.type != EventDataType.ZrtpClose) {
                parent.zrtpNegotiationFailed(ZrtpCodes.MessageSeverity.Severe,
                        EnumSet.of(ZrtpCodes.SevereCodes.SevereProtocolError));
            }
            sentPacket = null;
            inState = ZrtpStates.Initial;
        }
   }

    /*
     * WaitConirm1 state.
     *
     * This state handles a received Confirm1 message and only the Initiator
     * can enter this state.
     *
     * When entering this transition function
     * - Initiator mode
     * - sentPacket contains DHPart2 packet, DHPart2 timer active
     *
     * Possible events in this state are:
     * - timeout for sent DHPart2 packet: causes a resend check and repeat sending
     *   of DHPart2 packet
     * - Confirm1: Check Confirm1 message. If it is ok then prepare and send own
     *   Confirm2 packe and switch to state WaitConfAck.
     */
    protected void evWaitConfirm1() {
        char first, last;
        byte[] pkt;
        ZrtpCodes.ZrtpErrorCodes[] errorCode = new ZrtpCodes.ZrtpErrorCodes[1];

        /*
         * First check the general event type, then discrimnate the real event.
         */
        switch (event.type) {
        
        case ZrtpPacket:
            pkt = event.packet;

            first = (char) pkt[MESSAGE_OFFSET];
            first = Character.toLowerCase(first);
            last = (char) pkt[MESSAGE_OFFSET + 7];
            last = Character.toLowerCase(last);

            /*
             * Confirm1:
             * - Switch off resending DHPart2
             * - prepare a Confirm2 packet
             * - switch to state WaitConfAck
             * - set timer to monitor Confirm2 packet, we are initiator
             */
            if (first == 'c' && last == '1') {
                cancelTimer();
                ZrtpPacketConfirm cpkt= new ZrtpPacketConfirm(pkt);

                ZrtpPacketConfirm confirm = parent.prepareConfirm2(cpkt, errorCode);

                // Something went wrong during processing of the Confirm1 packet
                if (confirm == null) {
                    sendErrorPacket(errorCode[0]);
                    return;
                }
                inState = ZrtpStates.WaitConfAck;
                sentPacket = confirm;

                if (!parent.sendPacketZRTP(sentPacket)) {
                    sendFailed();         // returns to state Initial
                    return;
                }
                if (startTimer(t2) <= 0) {
                    timerFailed(ZrtpCodes.SevereCodes.SevereNoTimer);  // sets state to Initial
                    return;
                }
                if (!parent.srtpSecretsReady(ZrtpCallback.EnableSecurity.ForReceiver)) {
                    parent.sendInfo(ZrtpCodes.MessageSeverity.Severe, EnumSet
                            .of(ZrtpCodes.SevereCodes.SevereSecurityException));
                    sendErrorPacket(ZrtpCodes.ZrtpErrorCodes.CriticalSWError);
                    return;
                }
            }
            break;
            
        case Timer:
            if (!parent.sendPacketZRTP(sentPacket)) {
                sendFailed();             // returns to state Initial
                return;
            }
            if (nextTimer(t2) <= 0) {
                timerFailed(ZrtpCodes.SevereCodes.SevereTooMuchRetries);     // returns to state Initial
            }
            break;

        default:  // unknown Event type for this state (covers Error and ZrtpClose)
            if (event.type != EventDataType.ZrtpClose) {
                parent.zrtpNegotiationFailed(ZrtpCodes.MessageSeverity.Severe,
                        EnumSet.of(ZrtpCodes.SevereCodes.SevereProtocolError));
            }
            sentPacket = null;
            inState = ZrtpStates.Initial;
        }
    }

    /*
     * WaitConfirm2 state.
     *
     * Handles the Confirm2 message that closes the key agreement handshake. Only
     * the Responder can enter this state. If the Confirm2 message is ok send a 
     * Conf2Ack to our peer. Switch to secure mode after sending Conf2Ack, our 
     * peer switches to secure mode after receiving Conf2Ack.
     *
     * TODO - revise documentation comments
     * 
     * When entering this transition function
     * - Responder mode
     * - sentPacket contains Confirm1 packet, no timer active
     * - Security switched on
     *
     * Possible events in this state are:
     * - DHPart2: Our peer didn't receive our Confirm1 thus sends DHPart2 again.
     *   Just repeat our Confirm1.
     * - Confirm2: close DH key agreement. Perpare and send own Conf2Ack
     *   and switch to state SecureState.
     */
    protected void evWaitConfirm2() {
        char first, last;
        byte[] pkt;
        ZrtpCodes.ZrtpErrorCodes[] errorCode = new ZrtpCodes.ZrtpErrorCodes[1];

        /*
         * First check the general event type, then discrimnate the real event.
         */
        switch (event.type) {
        
        case ZrtpPacket:
            pkt = event.packet;

            first = (char) pkt[MESSAGE_OFFSET];
            first = Character.toLowerCase(first);
            last = (char) pkt[MESSAGE_OFFSET + 7];
            last = Character.toLowerCase(last);

            /*
             * DHPart2 or Commit in multi stream mode:
             * - resend Confirm1 packet via SRTP
             * - stay in state
             */
            if (first == 'd' || (multiStream && (first == 'c' && last == ' '))) {
                if (!parent.sendPacketZRTP(sentPacket)) {
                    sendFailed();             // returns to state Initial
                }
                return;
            }
            /*
             * Confirm2:
             * - prepare ConfAck
             * - switch on security
             * - switch to SecureState
             */
            if (first == 'c' && last == '2') {
                ZrtpPacketConfirm cpkt= new ZrtpPacketConfirm(pkt);
                ZrtpPacketConf2Ack confack = parent.prepareConf2Ack(cpkt, errorCode);

                // Something went wrong during processing of the confirm2 packet
                if (confack == null) {
                    sendErrorPacket(errorCode[0]);
                    return;
                }
                sentPacket = confack;

                if (!parent.sendPacketZRTP(sentPacket)) {
                    sendFailed();             // returns to state Initial
                    return;
                }
                if (!parent
                        .srtpSecretsReady(ZrtpCallback.EnableSecurity.ForSender)
                        || !parent
                                .srtpSecretsReady(ZrtpCallback.EnableSecurity.ForReceiver)) {
                    parent.sendInfo(ZrtpCodes.MessageSeverity.Severe, EnumSet
                            .of(ZrtpCodes.SevereCodes.SevereSecurityException));
                    sendErrorPacket(ZrtpCodes.ZrtpErrorCodes.CriticalSWError);
                    return;
                }
                inState = ZrtpStates.SecureState;
                parent.sendInfo(ZrtpCodes.MessageSeverity.Info, EnumSet.of(ZrtpCodes.InfoCodes.InfoSecureStateOn));
            }
            break;
            
        default:  // unknown Event type for this state (covers Error and ZrtpClose)
            if (event.type != EventDataType.ZrtpClose) {
                parent.zrtpNegotiationFailed(ZrtpCodes.MessageSeverity.Severe,
                        EnumSet.of(ZrtpCodes.SevereCodes.SevereProtocolError));
            }
            sentPacket = null;
            inState = ZrtpStates.Initial;
        }

    }

    /*
     * WaitConf2Ack state.
     *
     * This state handles the Conf2Ack message that acknowledges the successfull
     * processing of Confirm2. Only the Initiator can enter this state. Switch on
     * secure mode and switch to state SecureState.
     *
     * When entering this transition function
     * - Initiator mode
     * - sentPacket contains Confirm2 packet, Confirm2 timer active
     * - sender and receiver security switched on
     *
     * Possible events in this state are:
     * - timeout for sent Confirm2 packet: causes a resend check and repeat sending
     *   of Confirm2 packet
     * - Conf2Ack: Key agreement was successfull, switch to secure mode.
     */
    protected void evWaitConfAck() {

        char first, last;
        byte[] pkt;

        /*
         * First check the general event type, then discrimnate the real event.
         */
        switch (event.type) {

        case ZrtpPacket:
            pkt = event.packet;

            first = (char) pkt[MESSAGE_OFFSET];
            first = Character.toLowerCase(first);
            last = (char) pkt[MESSAGE_OFFSET + 7];
            last = Character.toLowerCase(last);

            /*
             * ConfAck: - Switch off resending Confirm2 - switch to SecureState
             */
            if (first == 'c') {
                cancelTimer();
                sentPacket = null;
                // Receiver was already enabled after sending Confirm2 packet
                // see previous states.
                if (!parent
                        .srtpSecretsReady(ZrtpCallback.EnableSecurity.ForSender)) {
                    parent.sendInfo(ZrtpCodes.MessageSeverity.Severe, EnumSet
                            .of(ZrtpCodes.SevereCodes.SevereSecurityException));
                    sendErrorPacket(ZrtpCodes.ZrtpErrorCodes.CriticalSWError);
                    return;
                }
                inState = ZrtpStates.SecureState;
                parent.sendInfo(ZrtpCodes.MessageSeverity.Info, EnumSet
                        .of(ZrtpCodes.InfoCodes.InfoSecureStateOn));
            }
            break;
        case Timer:
            if (!parent.sendPacketZRTP(sentPacket)) {
                sendFailed(); // returns to state Initial
                return;
            }
            if (nextTimer(t2) <= 0) {
                // returns to state initial
                timerFailed(ZrtpCodes.SevereCodes.SevereTooMuchRetries);
            }
            break;
        default: // unknown Event type for this state (covers Error and
            // ZrtpClose)
            if (event.type != EventDataType.ZrtpClose) {
                parent.zrtpNegotiationFailed(ZrtpCodes.MessageSeverity.Severe,
                        EnumSet.of(ZrtpCodes.SevereCodes.SevereProtocolError));
            }
            sentPacket = null;
            inState = ZrtpStates.Initial;
            parent.srtpSecretsOff(ZrtpCallback.EnableSecurity.ForReceiver);
        }
    }

    protected void evWaitClearAck() {

    }

    protected void evSecureState() {

        char first, last;
        byte[] pkt;

        /*
         * Handle a possible substate. If substate handling was ok just return.
         */
        if (secSubstate == SecureSubStates.WaitSasRelayAck) {
            if (subEvWaitRelayAck())
                return; 
        }
        /*
         * First check the general event type, then discrimnate the real event.
         */
        switch (event.type) {
        
        case ZrtpPacket:
            pkt = event.packet;

            first = (char) pkt[MESSAGE_OFFSET];
            first = Character.toLowerCase(first);
            last = (char) pkt[MESSAGE_OFFSET + 7];
            last = Character.toLowerCase(last);

            /*
             * Confirm2:
             * - resend Conf2Ack packet
             * - stay in state
             */
            if (first == 'c' && last == '2') {
                if (sentPacket != null && !parent.sendPacketZRTP(sentPacket)) {
                    sentPacket = null;
                    inState = ZrtpStates.Initial;
                    parent.srtpSecretsOff(ZrtpCallback.EnableSecurity.ForSender);
                    parent.srtpSecretsOff(ZrtpCallback.EnableSecurity.ForReceiver);
                    parent.zrtpNegotiationFailed(ZrtpCodes.MessageSeverity.Severe, 
                            EnumSet.of(ZrtpCodes.SevereCodes.SevereCannotSend));
                }
                return;
            }
            /*
             * GoClear received, handle it.
             *
            if (first == 'g' && last == 'r') {
                ZrtpPacketGoClear gpkt(pkt);
                ZrtpPacketClearAck* clearAck = parent->prepareClearAck(&gpkt);

                if (!parent->sendPacketZRTP(static_cast<ZrtpPacketBase *>(clearAck))) {
                    return(Done);
                }
            }
            */
            break;

        case Timer: 
            break;

        default: // unknown Event type for this state (covers Error and ZrtpClose)
            sentPacket = null;
            inState = ZrtpStates.Initial;
            parent.srtpSecretsOff(ZrtpCallback.EnableSecurity.ForSender);
            parent.srtpSecretsOff(ZrtpCallback.EnableSecurity.ForReceiver);
            if (event.type != EventDataType.ZrtpClose) {
                parent.zrtpNegotiationFailed(ZrtpCodes.MessageSeverity.Severe, 
                        EnumSet.of(ZrtpCodes.SevereCodes.SevereProtocolError));
            }
            parent.sendInfo(ZrtpCodes.MessageSeverity.Info, 
                    EnumSet.of(ZrtpCodes.InfoCodes.InfoSecureStateOff));
        }
    }
    
    /*
     * Secure Sub state WaitSasRelayAck.
     *
     * This state belongs to the secure substates and handles
     * SAS Relay Ack. 
     *
     * When entering this transition function
     * - sentPacket contains Error packet, Error timer active
     *
     * Possible events in this state are:
     * - timeout for sent SAS Relay packet: causes a resend check and repeat sending
     *   of packet
     * - SASRelayAck: Stop timer and switch to secure substate Normal.
     */
    protected boolean subEvWaitRelayAck() {
        char first, last;
        byte[] pkt;

        /*
         * First check the general event type, then discrimnate the real event.
         */
        switch (event.type) {

        case ZrtpPacket:
            pkt = event.packet;

            first = (char) pkt[MESSAGE_OFFSET];
            first = Character.toLowerCase(first);
            last = (char) pkt[MESSAGE_OFFSET + 7];
            last = Character.toLowerCase(last);
            /*
             * SAS relayAck:
             * - stop resending SASRelay,
             * - switch to secure substate Normal
             */
            if (first == 'r' && last =='k') {
                cancelTimer();
                secSubstate = SecureSubStates.Normal;
                sentPacket = null;
            }
            return true;
        case Timer:
            if (!parent.sendPacketZRTP(sentPacket)) {
                sendFailed(); // returns to state Initial
                return false;
            }
            if (nextTimer(t2) <= 0) {
                // returns to state initial
                // timerFailed(ZrtpCodes.SevereCodes.SevereTooMuchRetries);
                return false;
            }
            return true;
        default: // unknown Event type for this state (covers Error and close)
            break;
        }
        return false;
    }


    /*
     * WaitErrorAck state.
     *
     * This state belongs to the "error handling state overlay" and handles
     * ErrorAck message. Most of the ZRTP states can send an Error message, for
     * example if they detect wrong packets. After sending an Error message
     * the protocol engine switches to WaitErrorAck state. Receiving an
     * ErrorAck message completes the ZRTP error handling.
     *
     * When entering this transition function
     * - sentPacket contains Error packet, Error timer active
     *
     * Possible events in this state are:
     * - timeout for sent Error packet: causes a resend check and repeat sending
     *   of Error packet
     * - ErrorAck: Stop timer and switch to state Initial.
     */
    protected void evWaitErrorAck() {
        char first, last;
        byte[] pkt;

        /*
         * First check the general event type, then discrimnate the real event.
         */
        switch (event.type) {

        case ZrtpPacket:
            pkt = event.packet;

            first = (char) pkt[MESSAGE_OFFSET];
            first = Character.toLowerCase(first);
            last = (char) pkt[MESSAGE_OFFSET + 7];
            last = Character.toLowerCase(last);
            /*
             * ErrorAck:
             * - stop resending Error,
             * - switch to state Initial
             */
            if (first == 'e' && last =='k') {
                cancelTimer();
                inState = ZrtpStates.Initial;
                sentPacket = null;
            }
            break;
        case Timer:
            if (!parent.sendPacketZRTP(sentPacket)) {
                sendFailed(); // returns to state Initial
                return;
            }
            if (nextTimer(t2) <= 0) {
                // returns to state initial
                timerFailed(ZrtpCodes.SevereCodes.SevereTooMuchRetries);
            }
            break;
        default: // unknown Event type for this state (covers Error and
            // ZrtpClose)
            if (event.type != EventDataType.ZrtpClose) {
                parent.zrtpNegotiationFailed(ZrtpCodes.MessageSeverity.Severe,
                        EnumSet.of(ZrtpCodes.SevereCodes.SevereProtocolError));
            }
            sentPacket = null;
            inState = ZrtpStates.Initial;
        }
    }

    /**
     * Initialize and activate a timer.
     *
     * @param t
     *    The ZRTP timer structure to use for the timer.
     * @return
     *    1 timer was activated
     *    0 activation failed
     */
    private int startTimer(ZrtpTimer t) {
        return parent.activateTimer(t.startTimer());
    }

    /**
     * Compute and set the next timeout value.
     *
     * @param t
     *    The ZRTP timer structure to use for the timer.
     * @return
     *    1 timer was activated
     *    0 activation failed
     *   -1 resend counter exceeded
     */
    private int nextTimer(ZrtpTimer t) {

        int time = t.nextTimer();
        return (time < 0) ? time : parent.activateTimer(time);
    }

    /**
     * Cancel the active timer.
     *
     * @return
     *    1 timer was canceled
     *    0 cancelation failed
     */
    private int cancelTimer() {
        return parent.cancelTimer();
    }

    /**
     * Set status if an error occured while sending a ZRTP packet.
     * 
     * This functions clears data and sets the state to Initial after the engine
     * detected a problem while sending a ZRTP packet.
     * 
     * @return Fail code
     */
    private void sendFailed() {
        sentPacket = null;
        inState = ZrtpStates.Initial;
        parent.zrtpNegotiationFailed(ZrtpCodes.MessageSeverity.Severe,
                EnumSet.of(ZrtpCodes.SevereCodes.SevereCannotSend));
    }

    /**
     * Set status if a timer problems occure.
     * 
     * This functions clears data and set state to Initial after a timer error
     * occured. Either no timer available or resend counter exceedeed.
     * 
     * @param subCode defines the reason why the timer failed, either no
     *        timer available (resource) or retry count failed.
     * 
     * @return Fail code
     */
    private void timerFailed(ZrtpCodes.SevereCodes subCode) {
        sentPacket = null;
        inState = ZrtpStates.Initial;
        parent.zrtpNegotiationFailed(ZrtpCodes.MessageSeverity.Severe,
                EnumSet.of(subCode));
    }

    /**
     * Prepare and send an Error packet.
     *
     * Preparse an Error packet and sends it. It stores the Error
     * packet in the sentPacket variable to enable resending. The
     * method switches to protocol state Initial.
     * 
     * @param errorCode Is the sub error code of ZrtpError. The method sends
     *   the value of this sub code to the peer.
     */
    private void sendErrorPacket(ZrtpCodes.ZrtpErrorCodes errorCode) {
        cancelTimer();

        ZrtpPacketError err = parent.prepareError(errorCode);
        parent.zrtpNegotiationFailed(ZrtpCodes.MessageSeverity.ZrtpError,
                EnumSet.of(errorCode));

        sentPacket = err;
        inState = ZrtpStates.WaitErrorAck;
        if (!parent.sendPacketZRTP(err) || (startTimer(t2) <= 0)) {
            sendFailed();
        }
    }

    /**
     * Send a SAS relay packet.
     *
     * Get the SAS relay packet and send it. It stores the
     * packet in the sentPacket variable to enable resending. The
     * method switches to secure substate WaitSasRelayAck.
     * 
     * @param errorCode Is the sub error code of ZrtpError. The method sends
     *   the value of this sub code to the peer.
     */
    protected void sendSASRelay(ZrtpPacketSASRelay relay) {
        cancelTimer();
        sentPacket = relay;
        secSubstate = SecureSubStates.WaitSasRelayAck;
        if (!parent.sendPacketZRTP(relay) || (startTimer(t2) <= 0)) {
            sendFailed();
        }
    }

    /**
     * @return the multiStream
     */
    protected boolean isMultiStream() {
        return multiStream;
    }

    /**
     * @param multiStream the multiStream to set
     */
    protected void setMultiStream(boolean multiStream) {
        this.multiStream = multiStream;
    }

    /**
     * Check current state of the ZRTP state engine
     *
     * @param state
     *    The state to check.
     * @return
     *    Returns true id ZRTP engine is in the given state, false otherwise.
     */
    protected boolean isInState(ZrtpStateClass.ZrtpStates state) {
        return (state == inState);
    }

}

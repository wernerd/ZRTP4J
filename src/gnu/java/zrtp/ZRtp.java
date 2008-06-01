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

import gnu.java.zrtp.packets.ZrtpPacketBase;
import gnu.java.zrtp.packets.ZrtpPacketCommit;
import gnu.java.zrtp.packets.ZrtpPacketConf2Ack;
import gnu.java.zrtp.packets.ZrtpPacketConfirm;
import gnu.java.zrtp.packets.ZrtpPacketDHPart;
import gnu.java.zrtp.packets.ZrtpPacketError;
import gnu.java.zrtp.packets.ZrtpPacketErrorAck;
import gnu.java.zrtp.packets.ZrtpPacketHello;
import gnu.java.zrtp.packets.ZrtpPacketHelloAck;
import gnu.java.zrtp.utils.Base32;
import gnu.java.zrtp.utils.ZrtpUtils;
import gnu.java.zrtp.zidfile.ZidFile;
import gnu.java.zrtp.zidfile.ZidRecord;

import java.util.EnumSet;
import java.util.Random;
import java.util.Arrays;

import java.math.BigInteger;
import java.security.Provider;
import java.security.MessageDigest;
import java.security.KeyPair;
import java.security.KeyFactory;
import java.security.KeyPairGenerator;
import java.security.GeneralSecurityException;

import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import javax.crypto.KeyAgreement;
import javax.crypto.interfaces.DHPublicKey;
import javax.crypto.spec.DHPublicKeySpec;


/**
 * The main ZRTP class.
 *
 * This is the main class of the RTP/SRTP independent part of the GNU
 * ZRTP. It handles the ZRTP HMAC, DH, and other data management. The
 * user of this class needs to know only a few methods and needs to
 * provide only a few external functions to connect to a Timer
 * mechanism and to send data via RTP and SRTP. Refer to the
 * ZrtpCallback class to get detailed information regarding the
 * callback methods required by GNU RTP.
 *
 * The class ZrtpQueue is the GNU ccRTP specific implementation that
 * extends standard ccRTP RTP provide ZRTP support. Refer to the
 * documentation of ZrtpQueue to get more information about the usage
 * of ZRtp and associated classes.
 *
 * The main entry into the ZRTP class is the processExtensionHeader()
 * method.
 *
 * This class does not directly handle the protocol states, timers,
 * and packet resend. The protocol state engine is responsible for
 * these actions.
 * 
 * Example how to use ZRtp:
 *<pre>
 *   transConnector = (ZrtpTransformConnector)TransformManager.createZRTPConnector(sa);
 *   zrtpEngine = transConnector.getEngine();
 *   zrtpEngine.setUserCallback(new MyCallback());
 *   if (!zrtpEngine.initialize(&quot;test_t.zid&quot;))
 *       System.out.println(&quot;iniatlize failed&quot;);
 *
 *    zrtpEngine->startZrtpEngine();
 *</pre>
 * @see ZrtpCallback
 *
 * @author Werner Dittmann <Werner.Dittmann@t-online.de>
 *
 */

public class ZRtp {

    /**
     * The state engine takes care of protocol processing.
     */
    private ZrtpStateClass stateEngine = null;;

    /**
     * This is my ZID that I send to the peer.
     */
    private byte[] zid = new byte[ZidRecord.IDENTIFIER_LENGTH];

    /**
     * The peer's ZID
     */
    private byte[] peerZid = null;

    /**
     * The callback class provides me with the interface to send
     * data and to deal with timer management of the hosting system.
     */
    private ZrtpCallback callback = null;

    /**
     * My active Diffie-Helman context
     */
    private KeyAgreement dhContext;
    private KeyPairGenerator dhKeyPairGen;
    private KeyPair myKeyPair = null;
    private KeyFactory DHKeyFactory = null;
    private Provider cryptoProvider= null;
    private Cipher AEScipher = null;
    /**
     * The computed DH shared secret
     */
    byte[] DHss = null;

    /**
     * My computed public key
     */
    private byte[] pubKeyBytes = null;

    /**
     * My Role in the game
     */
    private ZrtpCallback.Role myRole;

    /**
     * The human readable SAS value
     */
    private String SAS;

    /**
     * The SAS hash for signaling and alike. Refer to chapters
     * 5.5, 6.13, 9.4. sasValue and the SAS string are derived
     * from sasHash.
     */
    private byte[] sasHash = null;
    /**
     * The variables for the retained shared secrets
     */
    private byte[] rs1IDr = null;
    private byte[] rs2IDr = null;
    private byte[] s3IDr = null;
    private byte[] pbxSecretIDr = null;

    private byte[] rs1IDi = null;
    private byte[] rs2IDi = null;
    private byte[] s3IDi = null;
    private byte[] pbxSecretIDi = null;
    /**
     * My hvi
     */
    private byte[] hvi = null;

    /**
     * The peer's hvi
     */
    private byte[] peerHvi = null;

    /**
     * Context to compute the4 SHA256 hash of selected messages.
     * Used to compute the s0, refer to chapter 5.4.1.4
     */
    private MessageDigest msgShaContext;
    private MessageDigest sha256;       // used for various SHA256 computations 
    private Mac hmacSha256;             // used for various HMAC computations
    /**
     * Commited Hash, Cipher, and public key algorithms
     */
    private ZrtpConstants.SupportedHashes hash;
    private ZrtpConstants.SupportedSymCiphers cipher;
    private ZrtpConstants.SupportedPubKeys pubKey;
    /**
     * The selected SAS type.
     */
    private ZrtpConstants.SupportedSASTypes sasType;

    /**
     * The selected SAS type.
     */
    private ZrtpConstants.SupportedAuthLengths authLength;

    /**
     * The Hash images as defined in chapter 5.1.1 (H0 is a random value,
     * not stored here). Need full SHA 256 lenght to store hash value but
     * only the leftmost 128 bits are used in computations and comparisons.
     */
    private byte[] H0 = new byte[ZrtpConstants.SHA256_DIGEST_LENGTH];
    private byte[] H1 = null;
    private byte[] H2 = null;
    private byte[] H3 = null;
    private byte[] helloHash = null;

    // need 128 bits only to store peer's values
    private byte[] peerH2 = null;
    private byte[] peerH3 = null;

    /**
     * The SHA256 hash over selected messages
     */
    private byte[] messageHash = null;
    /**
     * The s0
     */
    private byte[] s0 = new byte[ZrtpConstants.SHA256_DIGEST_LENGTH];

    /**
     * The new Retained Secret
     */
    private byte[] newRs1 = null;

    /**
     * The GoClear HMAC keys and confirm HMAC key
     */
    private byte[] hmacKeyI = null;
    private byte[] hmacKeyR = null;

    /**
     * The Initiator's srtp key and salt
     */
    private byte[] srtpKeyI = null;
    private byte[] srtpSaltI = null;

    /**
     * The Responder's srtp key and salt
     */
    private byte[] srtpKeyR = null;
    private byte[] srtpSaltR = null;

    /**
     * The keys used to encrypt/decrypt the confirm message
     */
    private byte[] zrtpKeyI = null;
    private byte[] zrtpKeyR = null;

    /**
     * The ZRTP Session Key
     * Refer to chapter 5.4.1.4
     */
    private byte[] zrtpSession = null;

    /**
     * True if this ZRTP instance uses multi-stream mode.
     */
    private boolean multiStream = false;

    /**
     * True if PBX enrollment is enabled.
     */
    private boolean PBXEnrollment = false;;

    /**
     * Pre-initialized packets.
     */
    private ZrtpPacketHello    zrtpHello = new ZrtpPacketHello();
    private ZrtpPacketHelloAck zrtpHelloAck = new ZrtpPacketHelloAck();
    private ZrtpPacketConf2Ack zrtpConf2Ack = new ZrtpPacketConf2Ack();
//    ZrtpPacketClearAck zrtpClearAck;
//    ZrtpPacketGoClear  zrtpGoClear;
    private ZrtpPacketError    zrtpError = new ZrtpPacketError();
    private ZrtpPacketErrorAck zrtpErrorAck = new ZrtpPacketErrorAck();
    private ZrtpPacketDHPart   zrtpDH1 = new ZrtpPacketDHPart();
    private ZrtpPacketDHPart   zrtpDH2 = new ZrtpPacketDHPart();
    private ZrtpPacketCommit   zrtpCommit = new ZrtpPacketCommit();
    private ZrtpPacketConfirm  zrtpConfirm1 = new ZrtpPacketConfirm();
    private ZrtpPacketConfirm  zrtpConfirm2 = new ZrtpPacketConfirm();

    /**
     * Random IV data to encrypt the confirm data, 128 bit for AES
     */
    private byte[] randomIV = new byte[16];

    private byte[] tempMsgBuffer = new byte[1024];
    private int lengthOfMsgData;

    /**
     * Variables to store signature data. Includes the signature type block
     */
    private byte[] signatureData = null;       // will be allocated when needed
    private int  signatureLength = 0;     // overall length in bytes


    
    /**
     * Constructor intializes all relevant data but does not start the
     * engine.
     */
    public ZRtp(byte[] myZid, ZrtpCallback cb, String id, Provider prov) throws GeneralSecurityException {

         System.arraycopy(myZid, 0, zid, 0, ZidRecord.IDENTIFIER_LENGTH);
         cryptoProvider = prov;
         callback = cb;
         
         if (cryptoProvider == null) {
            throw new GeneralSecurityException("ZRTP engine: no crypto provider available");
         }
        /*
         * Get all required crypto algorithms here, used everywhere :-)
         */
        sha256 = MessageDigest.getInstance("SHA256", cryptoProvider);
        msgShaContext = MessageDigest.getInstance("SHA256", cryptoProvider);
        hmacSha256 = Mac.getInstance("HMACSHA256", cryptoProvider);
        dhContext = KeyAgreement.getInstance("DH", cryptoProvider);
        dhKeyPairGen = KeyPairGenerator.getInstance("DH", cryptoProvider);
        DHKeyFactory = KeyFactory.getInstance("DH", cryptoProvider);
        AEScipher = Cipher.getInstance("AES/CFB128/NOPADDING", cryptoProvider);


        /*
         * Generate H0 as a random number (256 bits, 32 bytes) and then the hash
         * chain, refer to chapter 10
         */
        Random ran = new Random();
        ran.nextBytes(H0);
        H1 = sha256.digest(H0);        // hash H0 and generate H1
        H2 = sha256.digest(H1);        // H2
        H3 = sha256.digest(H2);        // H3

        zrtpHello.setH3(H3);            // set H3 in Hello, included in helloHash

        ran.nextBytes(randomIV);        // IV used in ZRTP packet encryption

        zrtpHello.setZid(zid);
        setClientId(id);                // set id, compute HMAC and final helloHash

        stateEngine = new ZrtpStateClass(this);
    }

    /*
     * First the public methods.
     */
    /**
     * Kick off the ZRTP protocol engine.
     * 
     * This method calls the ZrtpStateClass#evInitial() state of the state
     * engine. After this call we are able to process ZRTP packets from our peer
     * and to process them.
     */
    public void startZrtpEngine() {
        if (stateEngine != null) {
            ZrtpStateClass.Event ev = stateEngine.new Event(
                    ZrtpStateClass.EventDataType.ZrtpInitial, null);

            stateEngine.processEvent(ev);
        }
    }

    /**
     * Stop ZRTP security.
     * 
     */
    public void stopZrtp() {
        if (stateEngine != null) {
            ZrtpStateClass.Event ev = stateEngine.new Event(
                    ZrtpStateClass.EventDataType.ZrtpClose, null);

            stateEngine.processEvent(ev);
        }
     }

    /**
     * Process RTP extension header.
     *
     * This method expects to get a pointer to the extension header of
     * a RTP packet. The method checks if this is really a ZRTP
     * packet. If this check fails the method returns 0 (false) in
     * case this is not a ZRTP packet. We return a 1 if we processed
     * the ZRTP extension header and the caller may process RTP data
     * after the extension header as usual.  The method return -1 the
     * call shall dismiss the packet and shall not forward it to
     * further RTP processing.
     *
     * @param extHeader
     *    A pointer to the first byte of the extension header. Refer to
     *    RFC3550.
     */
    public void  processZrtpMessage(byte[] extHeader) {
        if (stateEngine != null) {
            ZrtpStateClass.Event ev = stateEngine.new Event(
                    ZrtpStateClass.EventDataType.ZrtpPacket, extHeader);
            stateEngine.processEvent(ev);            
        }
    }

    /**
     * Process a timeout event.
     * 
     * We got a timeout from the timeout provider. Forward it to the protocol
     * state engine.
     * 
     */
    public void processTimeout() {
        if (stateEngine != null) {
            ZrtpStateClass.Event ev = stateEngine.new Event(
                    ZrtpStateClass.EventDataType.Timer, null);

            stateEngine.processEvent(ev);
        }
    }

    /**
     * Check for and handle GoClear ZRTP packet header.
     * 
     * This method checks if this is a GoClear packet. If not, just return
     * false. Otherwise handle it according to the specification.
     * 
     * @param extHeader
     *            A pointer to the first byte of the extension header. Refer
     *            to RFC3550.
     * @return False if not a GoClear, true otherwise.
     * 
     // bool handleGoClear(uint *extHeader);
     */

    /**
     * Set the srtps secret.
     *
     * USe this method to set the srtps secret data. Refer to ZRTP
     * specification, chapter 3.2.1
     *
     * @param data
     *     Points to the srtps secret data. The data must have a length
     *      of 32 bytes (length of SHA256 hash)
     */
    public void setSrtpsSecret(byte[] data) {
        
    }

    /**
     * Set the other secret.
     *
     * USe this method to set the other secret data. Refer to ZRTP
     * specification, chapter 3.2.1
     *
     * @param data
     *     Points to the other secret data.
     */
    public void setOtherSecret(byte[] data) {
        
    }

    /**
     * Check current state of the ZRTP state engine
     *
     * @param state
     *    The state to check.
     * @return
     *    Returns true id ZRTP engine is in the given state, false otherwise.
     */
    public boolean inState(ZrtpStateClass.ZrtpStates state) {
        if (stateEngine != null) {
            return stateEngine.isInState(state);
        }
        else 
            return false;
    }

    /**
     * Set SAS as verified.
     * 
     * Call this method if the user confirmed (verfied) the SAS. ZRTP remembers
     * this together with the retained secrets data.
     */
    public void SASVerified() {
        // Initialize a ZID record to get peer's retained secrets
        ZidRecord zidRec = new ZidRecord(peerZid);
        ZidFile zidf = ZidFile.getInstance();

        zidf.getRecord(zidRec);
        zidRec.setSasVerified();
        zidf.saveRecord(zidRec);

    }

    /**
     * Reset the SAS verfied flag for the current active user's retained
     * secrets.
     * 
     */
    public void resetSASVerified() {
        // Initialize a ZID record to get peer's retained secrets
        ZidRecord zidRec = new ZidRecord(peerZid);
        ZidFile zidf = ZidFile.getInstance();

        zidf.getRecord(zidRec);
        zidRec.resetSasVerified();
        zidf.saveRecord(zidRec);

    }

    /**
     * Get the ZRTP Hello Hash data.
     * 
     * Use this method to get the ZRTP Hello Hash data. The method returns the
     * data as a string containing hex-digits. Refer to ZRTP specification,
     * chapter 9.1.
     * 
     * @return a std:string containing the Hello hash value as hex-digits. The
     *         hello hash is available immediately after class instantiation.
     */
    public String getHelloHash() {
        return new String(ZrtpUtils.bytesToHexString(helloHash,
                ZrtpConstants.SHA256_DIGEST_LENGTH));
    }

    /**
     * Get Multi-stream parameters.
     *
     * Use this method to get the Multi-stream that were computed during
     * the ZRTP handshake. An application may use these parameters to
     * enable multi-stream processing for an associated SRTP session.
     *
     * Refer to chapter 5.4.2 in the ZRTP specification for further details
     * and restriction how and when to use multi-stream mode.
     *
     * @return
     *    a string that contains the multi-stream parameters. The application
     *    must not modify the contents of this string, it is opaque data. The
     *    application may hand over this string to a new ZrtpQueue instance
     *    to enable multi-stream processing for this ZrtpQueue.
     *    If ZRTP was 
     *    not started or ZRTP is not yet in secure state the method returns an
     *    empty string.
     */
    public byte[] getMultiStrParams() {
        byte[] tmp = null;
        
        if (inState(ZrtpStateClass.ZrtpStates.SecureState) && !multiStream) {
            // digest length + cipher + authLength
            tmp = new byte[ZrtpConstants.SHA256_DIGEST_LENGTH + 1 + 1];
            // construct array that holds zrtpSession, cipher type and auth-length
            System.arraycopy(zrtpSession, 0, tmp, 0, ZrtpConstants.SHA256_DIGEST_LENGTH);
            tmp[ZrtpConstants.SHA256_DIGEST_LENGTH] = (byte)cipher.value;          //cipher is enumeration (int)
            tmp[ZrtpConstants.SHA256_DIGEST_LENGTH + 1] = (byte)authLength.value;  //authLength is enumeration (int)
        }
        return tmp;
    }

    /**
     * Set Multi-stream parameters.
     * 
     * Use this method to set the parameters required to enable Multi-stream
     * processing of ZRTP. The multi-stream parameters must be set before the
     * application starts the ZRTP protocol engine.
     * 
     * Refer to chapter 5.4.2 in the ZRTP specification for further details of
     * multi-stream mode.
     * 
     * @param parameters
     *            A string that contains the multi-stream parameters that this
     *            new ZrtpQueue instanace shall use. See also
     *            <code>getMultiStrParams()</code>
     */
    public void setMultiStrParams(byte[] parameters) {

        System.arraycopy(parameters, 0, zrtpSession, 0,
                ZrtpConstants.SHA256_DIGEST_LENGTH);
        for (ZrtpConstants.SupportedSymCiphers c : ZrtpConstants.SupportedSymCiphers
                .values()) {
            if (c.value == (parameters[ZrtpConstants.SHA256_DIGEST_LENGTH] & 0xff)) {
                cipher = c;
                break;
            }
        }
        for (ZrtpConstants.SupportedAuthLengths a : ZrtpConstants.SupportedAuthLengths
                .values()) {
            if (a.value == (parameters[ZrtpConstants.SHA256_DIGEST_LENGTH + 1] & 0xff)) {
                authLength = a;
                break;
            }
        }
    }

    /**
     * Check if this ZRTP use Multi-stream.
     *
     * Use this method to check if this ZRTP instance uses multi-stream. Even
     * if the application provided multi-stram parameters it may happen that
     * full DH mode was used. Refer to chapters 5.2 and 5.4.2 in the ZRTP #
     * when this may happen.
     *
     * @return
     *     True if multi-stream is used, false otherwise.
     */
    public boolean isMultiStream() {
        return multiStream;
    }
    

    /**
     * Accept a PBX enrollment request.
     *
     * If a PBX service asks to enroll the MiTM key and the user accepts this
     * request, for example by pressing an OK button, the client application
     * shall call this method and set the parameter <code>accepted</code> to
     * true. If the user does not accept the request set the parameter to 
     * false.
     *
     * @param accepted
     *     True if the enrollment request is accepted, false otherwise.
     */
    public void acceptEnrollment(boolean accepted) {
        
    }

    /**
     * Enable PBX enrollment
     *
     * The application calls this method to allow or disallow PBX enrollment.
     * If the applications allows PBX enrollment then the ZRTP implementation
     * honors the PBX enrollment flag in Confirm packets. Refer to chapter 8.3
     * for further details of PBX enrollment.
     *
     * @param yesNo
     *    If set to true then ZRTP honors the PBX enrollment flag in Commit
     *    packets and calls the appropriate user callback methods. If
     *    the parameter is set to false ZRTP ignores the PBX enrollment flags.
     */
    public void setPBXEnrollment(boolean yesNo) {
        PBXEnrollment = yesNo;
    }

    /**
     * Set signature data
     *
     * This functions stores signature data and transmitts it during ZRTP
     * processing to the other party as part of the Confirm packets. Refer to 
     * chapters 6.7 and 8.2.
     *
     * The signature data must be set before ZRTP the application calls
     * <code>start()</code>.
     *
     * @param data
     *    The signature data including the signature type block. The method
     *    copies this data into the Confirm packet at signature type block.
     *    The length of the signature data must be multiple of 4 bytes.
     * @return
     *    True if the method stored the data, false otherwise.
     */
    public boolean setSignatureData(byte[] data) {
        return false;
    }

    /**
     * Get signature data
     *
     * This functions returns signature data that was receivied during ZRTP
     * processing. Refer to chapters 6.7 and 8.2.
     *
     * The signature data can be retrieved after ZRTP enters secure state.
     * <code>start()</code>.
     *
     * @return
     *    Signature data in a byte array.
     */
    public byte[] getSignatureData() {
        return signatureData;
    }

    /**
     * Get length of signature data
     *
     * This functions returns the length of signature data that was receivied 
     * during ZRTP processing. Refer to chapters 6.7 and 8.2.
     *
     * @return
     *    Length in bytes of the received signature data. The method returns
     *    zero if no signature data avilable.
     */
    public int getSignatureLength() {
        return signatureLength;
    }
    
    
    /*
     * The following methods are helper functions for ZrtpStateClass.
     * ZrtpStateClass calls them to prepare packets, send data, report
     * problems, etc.
     */
    /**
     * Send a ZRTP packet.
     *
     * The state engines calls this method to send a packet via the RTP
     * stack.
     *
     * @param packet
     *    Points to the ZRTP packet.
     * @return
     *    false if sending failed, true if packet was send
     */
    protected boolean sendPacketZRTP(ZrtpPacketBase packet) {
        // the packetBuffer reflects the real size of the data including the CRC field.
        return ((packet == null) ? false :
            callback.sendDataZRTP(packet.getHeaderBase() /*, (packet.getLength() * 4) + 4) */));
    }

    /**
     * Activate a Timer using the host callback.
     *
     * @param tm
     *    The time in milliseconds.
     * @return
     *    zero if activation failed, one if timer was activated
     */
    protected int activateTimer(int tm) {
        return callback.activateTimer(tm); 
    }

    /**
     * Cancel the active Timer using the host callback.
     *
     * @return
     *    zero if activation failed, one if timer was activated
     */
    protected int cancelTimer() {
        return callback.cancelTimer();
    }

    /**
     * Prepare a Hello packet.
     *
     * Just take the preinitialized Hello packet and return it. No
     * further processing required.
     *
     * @return
     *    A pointer to the initialized Hello packet.
     */
    protected ZrtpPacketHello prepareHello() {
        return zrtpHello;
    }

    /**
     * Prepare a HelloAck packet.
     *
     * Just take the preinitialized HelloAck packet and return it. No
     * further processing required.
     *
     * @return
     *    A pointer to the initialized HelloAck packet.
     */
    protected ZrtpPacketHelloAck prepareHelloAck() {
        return zrtpHelloAck;
    }

    /**
     * Prepare a Commit packet.
     *
     * We have received a Hello packet from our peer. Check the offers
     * it makes to us and select the most appropriate. Using the
     * selected values prepare a Commit packet and return it to protocol
     * state engine.
     *
     * @param hello
     *    Points to the received Hello packet
     * @return
     *    A pointer to the prepared Commit packet
     */
    protected ZrtpPacketCommit prepareCommit(ZrtpPacketHello hello,
            ZrtpCodes.ZrtpErrorCodes[] errMsg) {
        sendInfo(ZrtpCodes.MessageSeverity.Info, EnumSet
                .of(ZrtpCodes.InfoCodes.InfoHelloReceived));

        if (!hello.isSameVersion(ZrtpConstants.zrtpVersion)) {
            errMsg[0] = ZrtpCodes.ZrtpErrorCodes.UnsuppZRTPVersion;
            return null;
        }
        // Save our peer's (presumably the Responder) ZRTP id

        peerZid = hello.getZid();
        // peers have the same ZID?
        if (ZrtpUtils.byteArrayCompare(peerZid, zid,
                ZidRecord.IDENTIFIER_LENGTH) == 0) {
            errMsg[0] = ZrtpCodes.ZrtpErrorCodes.EqualZIDHello;
            return null;
        }
        peerH3 = hello.getH3();

        /*
         * The Following section extracts the algorithm from the Hello packet.
         * Always the best possible (offered) algorithms are used. If the
         * received Hello does not contain algo specifiers or offers only
         * unsupported (optional) alogos then replace these with mandatory algos
         * and put them into the Commit packet. Refer to the findBest*()
         * functions.
         */
        cipher = hello.findBestCipher();
        hash = hello.findBestHash();
        pubKey = hello.findBestPubkey();
        System.err.println("best pubkey: " + pubKey);

        sasType = hello.findBestSASType();
        authLength = hello.findBestAuthLen();

        // Generate the DH data and keys according to the selected DH algorithm
        int maxPubKeySize;
        try {
            if (pubKey == ZrtpConstants.SupportedPubKeys.DH3K) {
                dhKeyPairGen.initialize(ZrtpConstants.specDh3k);
                maxPubKeySize = 384;
            } else {
                errMsg[0] = ZrtpCodes.ZrtpErrorCodes.CriticalSWError;
                return null;
                // Error - shouldn't happen
            }
        } catch (GeneralSecurityException e) {
            sendInfo(ZrtpCodes.MessageSeverity.Severe, EnumSet
                    .of(ZrtpCodes.SevereCodes.SevereSecurityException));
            errMsg[0] = ZrtpCodes.ZrtpErrorCodes.CriticalSWError;
            return null;
        }
        myKeyPair = dhKeyPairGen.generateKeyPair();
        pubKeyBytes = ((DHPublicKey)myKeyPair.getPublic()).getY().toByteArray();

        // check for leading zero byte if public key resulted in negtive
        // value. BigInteger adds a leading zero to hide the negative sign bit
        if (pubKeyBytes.length > maxPubKeySize) {
            if (pubKeyBytes[0] == 0) {
                byte[] tmp = new byte[maxPubKeySize];
                System.arraycopy(pubKeyBytes, 1, tmp, 0, maxPubKeySize);
                pubKeyBytes = tmp;
            } else {
                errMsg[0] = ZrtpCodes.ZrtpErrorCodes.CriticalSWError;
                return null;
            }
        }
        sendInfo(ZrtpCodes.MessageSeverity.Info, EnumSet
                .of(ZrtpCodes.InfoCodes.InfoCommitDHGenerated));

        /*
         * Prepare our DHPart2 packet here. Required to compute HVI. If we stay
         * in Initiator role then we reuse this packet later in
         * prepareDHPart2(). To create this DH packet we have to compute the
         * retained secret ids first. Thus get our peer's retained secret data
         * first.
         */
        ZidRecord zidRec = new ZidRecord(peerZid);
        ZidFile zidFile = ZidFile.getInstance();
        zidFile.getRecord(zidRec);

        // Compute the Initator's and Responder's retained secret ids.
        computeSharedSecretSet(zidRec);

        // Construct a DHPart2 message (Initiator's DH message). This packet
        // is required to compute the HVI (Hash Value Initiator), refer to
        // chapter 5.4.1.1.

        // Fill the values in the DHPart2 packet
        zrtpDH2.setPubKeyType(pubKey);
        zrtpDH2.setMessageType(ZrtpConstants.DHPart2Msg);
        zrtpDH2.setRs1Id(rs1IDi);
        zrtpDH2.setRs2Id(rs2IDi);
        zrtpDH2.setS3Id(s3IDi);
        zrtpDH2.setPbxSecretId(pbxSecretIDi);
        zrtpDH2.setPv(pubKeyBytes);
        zrtpDH2.setH1(H1);

        int len = zrtpDH2.getLength() * ZrtpPacketBase.ZRTP_WORD_SIZE;

        // Compute HMAC over Hello, excluding the HMAC field (2*ZTP_WORD_SIZE)
        // and store in Hello
        byte[] hmac = computeMsgHmac(H0, zrtpDH2);
        zrtpDH2.setHMAC(hmac);

        // Compute the HVI, refer to chapter 5.4.1.1 of the specification
        computeHvi(zrtpDH2, hello);

        // setHashType(sh.value, sh.name);

        zrtpCommit.setZid(zid);
        zrtpCommit.setHashType(hash.name);
        zrtpCommit.setCipherType(cipher.name);
        zrtpCommit.setAuthLen(authLength.name);
        zrtpCommit.setPubKeyType(pubKey.name);
        zrtpCommit.setSasType(sasType.name);
        zrtpCommit.setHvi(hvi);
        zrtpCommit.setH2(H2);

        len = zrtpCommit.getLength() * ZrtpPacketBase.ZRTP_WORD_SIZE;

        // Compute HMAC over Hello, excluding the HMAC field (2*ZTP_WORD_SIZE)
        // and store in Hello
        hmac = computeMsgHmac(H1, zrtpCommit);
        zrtpCommit.setHMAC(hmac);

        // hash first messages to produce overall message hash
        // First the Responder's Hello message, second the Commit
        // (always Initator's)
        msgShaContext.update(hello.getHeaderBase(), 0, hello.getLength()
                * ZrtpPacketBase.ZRTP_WORD_SIZE);
        msgShaContext.update(zrtpCommit.getHeaderBase(), 0, len);

        // store Hello data temporarily until we can check HMAC after receiving
        // Commit as
        // Responder or DHPart1 as Initiator 
        storeMsgTemp(hello);
        return zrtpCommit;
    }

    /**
     * Prepare the DHPart1 packet.
     *
     * This method prepares a DHPart1 packet. The input to the method is always
     * a Commit packet received from the peer. Also we are in the role of the
     * Responder.
     *
     * When we receive a Commit packet we get the selected ciphers, hashes, etc
     * and cross-check if this is ok. Then we need to initialize a set of DH
     * keys according to the selected cipher. Using this data we prepare our DHPart1
     * packet.
     */
    protected ZrtpPacketDHPart prepareDHPart1(ZrtpPacketCommit commit,
            ZrtpCodes.ZrtpErrorCodes[] errMsg) {
        sendInfo(ZrtpCodes.MessageSeverity.Info, EnumSet
                .of(ZrtpCodes.InfoCodes.InfoRespCommitReceived));

        // The following code check the hash chain according chapter 10 to
        // detect
        // false ZRTP packets

        peerH2 = commit.getH2();
        byte[] tmpH3 = sha256.digest(peerH2);

        if (ZrtpUtils.byteArrayCompare(tmpH3, peerH3,
                ZrtpConstants.SHA256_DIGEST_LENGTH) != 0) {
            errMsg[0] = ZrtpCodes.ZrtpErrorCodes.IgnorePacket;
            return null;
        }

        // Check HMAC of previous Hello packet stored in temporary buffer. The
        // HMAC key of peer's Hello packet is peer's H2 that is contained in the
        // Commit packet. Refer to chapter 9.1.
        if (!checkMsgHmac(peerH2)) {
            sendInfo(ZrtpCodes.MessageSeverity.Severe, EnumSet
                    .of(ZrtpCodes.SevereCodes.SevereHelloHMACFailed));
            return null;
        }

        // check if we support the commited Cipher type
        cipher = commit.getCipher();
        if (cipher == ZrtpConstants.SupportedSymCiphers.END) {
            errMsg[0] = ZrtpCodes.ZrtpErrorCodes.UnsuppCiphertype;
            return null;
        }

        // check if we support the commited Authentication length
        authLength = commit.getAuthlen();
        if (authLength == ZrtpConstants.SupportedAuthLengths.END) {
            errMsg[0] = ZrtpCodes.ZrtpErrorCodes.UnsuppSRTPAuthTag;
            return null;
        }

        hash = commit.getHash();
        if (hash == ZrtpConstants.SupportedHashes.END) {
            errMsg[0] = ZrtpCodes.ZrtpErrorCodes.UnsuppHashType;
            return null;
        }

        // check if we support the commited pub key type
        pubKey = commit.getPubKey();
        if (pubKey == ZrtpConstants.SupportedPubKeys.END) {
            errMsg[0] = ZrtpCodes.ZrtpErrorCodes.UnsuppPKExchange;
            return null;
        }

        // check if we support the commited SAS type
        sasType = commit.getSas();
        if (sasType == ZrtpConstants.SupportedSASTypes.END) {
            errMsg[0] = ZrtpCodes.ZrtpErrorCodes.UnsuppSASScheme;
            return null;
        }

        sendInfo(ZrtpCodes.MessageSeverity.Info, EnumSet
                .of(ZrtpCodes.InfoCodes.InfoDH1DHGenerated));

        // Setup a DHPart1 packet.
        zrtpDH1.setPubKeyType(pubKey);
        zrtpDH1.setMessageType(ZrtpConstants.DHPart1Msg);
        zrtpDH1.setRs1Id(rs1IDr);
        zrtpDH1.setRs2Id(rs2IDr);
        zrtpDH1.setS3Id(s3IDr);
        zrtpDH1.setPbxSecretId(pbxSecretIDr);
        zrtpDH1.setPv(pubKeyBytes);
        zrtpDH1.setH1(H1);

        // Compute HMAC over DHPart1, excluding the HMAC field (2*ZTP_WORD_SIZE)
        // and store in DHPart1
        byte[] hmac = computeMsgHmac(H0, zrtpDH1);
        zrtpDH1.setHMAC(hmac);

        // We are definitly responder. Save the peer's hvi for later compare.
        myRole = ZrtpCallback.Role.Responder;
        peerHvi = commit.getHvi();

        // We are responder. Release a possibly pre-computed SHA256 context
        // because this was prepared for Initiator. Then create a new one.
        msgShaContext.reset();

        // Hash messages to produce overall message hash:
        // First the Responder's (my) Hello message, second the Commit
        // (always Initator's), then the DH1 message (which is always a
        // Responder's message)
        msgShaContext.update(zrtpHello.getHeaderBase(), 0, zrtpHello
                .getLength()
                * ZrtpPacketBase.ZRTP_WORD_SIZE);
        msgShaContext.update(commit.getHeaderBase(), 0, commit.getLength()
                * ZrtpPacketBase.ZRTP_WORD_SIZE);
        msgShaContext.update(zrtpDH1.getHeaderBase(), 0, zrtpDH1.getLength()
                * ZrtpPacketBase.ZRTP_WORD_SIZE);

        // store Commit data temporarily until we can check HMAC after receiving DHPart2
        storeMsgTemp(commit);

        return zrtpDH1;
    }

    /**
     * Prepare the DHPart2 packet.
     * 
     * This method prepares a DHPart2 packet. The input to the method is always
     * a DHPart1 packet received from the peer. Our peer sends the DH1Part as
     * response to our Commit packet. Thus we are in the role of the Initiator.
     * 
     */
    ZrtpPacketDHPart prepareDHPart2(ZrtpPacketDHPart dhPart1,
            ZrtpCodes.ZrtpErrorCodes[] errMsg) {
        sendInfo(ZrtpCodes.MessageSeverity.Info, EnumSet
                .of(ZrtpCodes.InfoCodes.InfoInitDH1Received));

        // Because we are initiator the protocol engine didn't receive Commit
        // thus could not store a peer's H2. A two step SHA256 is required to
        // re-compute H3. Then compare with peer's H3 from peer's Hello packet.
        peerH2 = sha256.digest(dhPart1.getH1()); // Compute peer's H2
        byte[] tmpHash = sha256.digest(peerH2); // Compute peer's H3 (tmpHash)

        if (ZrtpUtils.byteArrayCompare(tmpHash, peerH3,
                ZrtpConstants.SHA256_DIGEST_LENGTH) != 0) {
            errMsg[0] = ZrtpCodes.ZrtpErrorCodes.IgnorePacket;
            return null;
        }

        // Check HMAC of previous Hello packet stored in temporary buffer. The
        // HMAC key of the Hello packet is peer's H2 that was computed above.
        // Refer to chapter 9.1 and chapter 10.
        if (!checkMsgHmac(peerH2)) {
            sendInfo(ZrtpCodes.MessageSeverity.Severe, EnumSet
                    .of(ZrtpCodes.SevereCodes.SevereHelloHMACFailed));
            errMsg[0] = ZrtpCodes.ZrtpErrorCodes.CriticalSWError;
            return null;
        }

        // get and check Responder's public value, see chap. 5.4.3 in the spec
        byte[] pvrBytes = dhPart1.getPv();
        BigInteger pvrBigInt = new BigInteger(1, pvrBytes);
        DHPublicKeySpec dhs = null;

        if (pubKey == ZrtpConstants.SupportedPubKeys.DH3K) {
            if (!checkPubKey(pvrBigInt, ZrtpConstants.SupportedPubKeys.DH3K)) {
                errMsg[0] = ZrtpCodes.ZrtpErrorCodes.DHErrorWrongPV;
                return null;
            }
            dhs = new DHPublicKeySpec(pvrBigInt, ZrtpConstants.specDh3k.getP(),
                    ZrtpConstants.specDh3k.getG());

        }
        // generate the resonpder's public key from the pvr data and the key
        // specs, then compute the shared secret.
        try {
            DHPublicKey pvr = null;
            pvr = (DHPublicKey) DHKeyFactory.generatePublic(dhs);
            dhContext.init(myKeyPair.getPrivate());
            dhContext.doPhase(pvr, true);
        } catch (GeneralSecurityException e) {
            sendInfo(ZrtpCodes.MessageSeverity.Severe, EnumSet
                    .of(ZrtpCodes.SevereCodes.SevereSecurityException));
            errMsg[0] = ZrtpCodes.ZrtpErrorCodes.CriticalSWError;
            return null;
        }
        DHss = dhContext.generateSecret();

        myRole = ZrtpCallback.Role.Initiator;

        // We are Inititaor: the Responder's Hello and the Initiator's (our)
        // Commit are already hashed in the context. Now hash the 
        // Responder's DH1 and then the Initiator's (our) DH2 in that order.
        msgShaContext.update(dhPart1.getHeaderBase(), 0, dhPart1.getLength()
                * ZrtpPacketBase.ZRTP_WORD_SIZE);
        msgShaContext.update(zrtpDH2.getHeaderBase(), 0, zrtpDH2.getLength()
                * ZrtpPacketBase.ZRTP_WORD_SIZE);

        // Compute the message Hash
        messageHash = msgShaContext.digest();
        msgShaContext = null;

        // To compute the S0 for the Initiator we need the retained secrets of
        // our peer. Get them from the storage.
        ZidRecord zidRec = new ZidRecord(peerZid);
        ZidFile zidf = ZidFile.getInstance();
        zidf.getRecord(zidRec);

        // Now compute the S0, all dependend keys and the new RS1
        generateS0Initiator(dhPart1, zidRec);
        zidf.saveRecord(zidRec);
        
        dhContext = null;

        // store DHPart1 data temporarily until we can check HMAC after
        // receiving Confirm1
        storeMsgTemp(dhPart1);
        return zrtpDH2;
    }

    /**
     * Prepare the Confirm1 packet.
     *
     * This method prepare the Confirm1 packet. The input to this method is the
     * DHPart2 packect received from our peer. The peer sends the DHPart2 packet
     * as response of our DHPart1. Here we are in the role of the Responder
     *
     */
    protected ZrtpPacketConfirm prepareConfirm1(ZrtpPacketDHPart dhPart2, ZrtpCodes.ZrtpErrorCodes[] errMsg) {
        sendInfo(ZrtpCodes.MessageSeverity.Info, EnumSet.of(ZrtpCodes.InfoCodes.InfoRespDH2Received));

        // Because we are responder we received a Commit and stored its H2. 
        // Now re-compute H2 from received H1 and compare with stored peer's H2.
        byte[] tmpHash = sha256.digest(dhPart2.getH1());
        if (ZrtpUtils.byteArrayCompare(tmpHash, peerH2, ZrtpConstants.SHA256_DIGEST_LENGTH) != 0) {
            errMsg[0] = ZrtpCodes.ZrtpErrorCodes.IgnorePacket;
            return null;
        }

        // Check HMAC of Commit packet stored in temporary buffer. The
        // HMAC key of the Commit packet is peer's H1 that is contained in.
        // DHPart2. Refer to chapter 9.1 and chapter 10.
        if (!checkMsgHmac(dhPart2.getH1())) {
            sendInfo(ZrtpCodes.MessageSeverity.Severe, EnumSet.of(ZrtpCodes.SevereCodes.SevereCommitHMACFailed));
            errMsg[0] = ZrtpCodes.ZrtpErrorCodes.CriticalSWError;
            return null;
        }
        // Get and check the Initiator's public value, see chap. 5.4.2 of the spec
        // get and check Responder's public value, see chap. 5.4.3 in the spec
        byte[] pviBytes = dhPart2.getPv();
        BigInteger pviBigInt = new BigInteger(1, pviBytes);
        DHPublicKeySpec dhs = null;

        if (pubKey == ZrtpConstants.SupportedPubKeys.DH3K) {
            if (!checkPubKey(pviBigInt, ZrtpConstants.SupportedPubKeys.DH3K)) {
                errMsg[0] = ZrtpCodes.ZrtpErrorCodes.DHErrorWrongPV;
                return null;
            }
            dhs = new DHPublicKeySpec(pviBigInt, ZrtpConstants.specDh3k.getP(),
                    ZrtpConstants.specDh3k.getG());

        }
        // generate the resonpder's public key from the pvr data and the key
        // specs, then compute the shared secret.
        try {
            DHPublicKey pvi = null;
            pvi = (DHPublicKey) DHKeyFactory.generatePublic(dhs);
            dhContext.init(myKeyPair.getPrivate());
            dhContext.doPhase(pvi, true);
        } catch (GeneralSecurityException e) {
            sendInfo(ZrtpCodes.MessageSeverity.Severe, EnumSet
                    .of(ZrtpCodes.SevereCodes.SevereSecurityException));
            errMsg[0] = ZrtpCodes.ZrtpErrorCodes.CriticalSWError;
            return null;
        }
        DHss = dhContext.generateSecret();

        // Now we have the peer's pvi. Because we are responder re-compute my hvi
        // using my Hello packet and the Initiator's DHPart2 and compare with
        // hvi sent in commit packet. If it doesn't macht then a MitM attack
        // may have occured.
        computeHvi(dhPart2, zrtpHello);
        if (ZrtpUtils.byteArrayCompare(hvi, peerHvi, ZrtpConstants.SHA256_DIGEST_LENGTH) != 0) {
            errMsg[0] = ZrtpCodes.ZrtpErrorCodes.DHErrorWrongHVI;
            return null;
        }
        // Hash the Initiator's DH2 into the message Hash (other messages already
        // prepared, see method prepareDHPart1().
        msgShaContext.update(dhPart2.getHeaderBase(), 0,
                  dhPart2.getLength() * ZrtpPacketBase.ZRTP_WORD_SIZE);
        messageHash = msgShaContext.digest();
        msgShaContext = null;

        // To compute the S0 for the Initiator we need the retained secrets of our
        // peer. Get them from the storage.
        ZidRecord zidRec = new ZidRecord(peerZid);
        ZidFile zidf = ZidFile.getInstance();
        zidf.getRecord(zidRec);

        /*
         * The expected shared secret Ids were already computed when we built the
         * DHPart1 packet. Generate s0, all depended keys, and the new RS1 value
         * for the ZID record.
         */
        generateS0Responder(dhPart2, zidRec);
        zidf.saveRecord(zidRec);

        dhContext = null;

        // Fill in Confirm1 packet.
        zrtpConfirm1.setMessageType(ZrtpConstants.Confirm1Msg);
        zrtpConfirm1.setSignatureLength(0);

        // Check if user verfied the SAS in a previous call and thus verfied
        // the retained secret.
        if (zidRec.isSasVerified()) {
            zrtpConfirm1.setSASFlag();
        }
        zrtpConfirm1.setExpTime(0xFFFFFFFF);
        zrtpConfirm1.setIv(randomIV);
        zrtpConfirm1.setHashH0(H0);

        // Encrypt and HMAC with Responder's key - we are Respondere here
        // see ZRTP specification chapter xYxY
        byte[] dataToSecure = zrtpConfirm1.getDataToSecure();
        int keylen = (cipher == ZrtpConstants.SupportedSymCiphers.AES1) ? 16 : 32;

        SecretKey encryptionKey = new SecretKeySpec(zrtpKeyR, 0, keylen, "AES");
        IvParameterSpec ivp = new IvParameterSpec(randomIV);
        
        try {
            AEScipher.init(Cipher.ENCRYPT_MODE, encryptionKey, ivp);
            AEScipher.doFinal(dataToSecure, 0, dataToSecure.length, dataToSecure);
        } catch (GeneralSecurityException e) {
            sendInfo(ZrtpCodes.MessageSeverity.Severe, EnumSet
                    .of(ZrtpCodes.SevereCodes.SevereSecurityException));
            errMsg[0] = ZrtpCodes.ZrtpErrorCodes.CriticalSWError;
            return null;
        }
        byte[] confMac = computeHmac(hmacKeyR, dataToSecure, dataToSecure.length);
        zrtpConfirm1.setDataToSecure(dataToSecure);
        zrtpConfirm1.setHmac(confMac);

       // store DHPart2 data temporarily until we can check HMAC after receiving Confirm2
        storeMsgTemp(dhPart2);
        return zrtpConfirm1;
    }

    /**
     * Prepare the Confirm2 packet.
     *
     * This method prepare the Confirm2 packet. The input to this method is the
     * Confirm1 packet received from our peer. The peer sends the Confirm1 packet
     * as response of our DHPart2. Here we are in the role of the Initiator
     */
    protected ZrtpPacketConfirm prepareConfirm2(ZrtpPacketConfirm confirm1, ZrtpCodes.ZrtpErrorCodes[] errMsg) {
        sendInfo(ZrtpCodes.MessageSeverity.Info, EnumSet.of(ZrtpCodes.InfoCodes.InfoInitConf1Received));

        // Use the Responder's keys here to decrypt because we are 
        // Initiator and receive packets from Responder
        int keylen = (cipher == ZrtpConstants.SupportedSymCiphers.AES1) ? 16 : 32;
        byte[] dataToSecure = confirm1.getDataToSecure();
        
        byte[] confMac = computeHmac(hmacKeyR, dataToSecure, dataToSecure.length);
        
        if (ZrtpUtils.byteArrayCompare(confMac, confirm1.getHmac(), 2*ZrtpPacketBase.ZRTP_WORD_SIZE) != 0) {
            errMsg[0] = ZrtpCodes.ZrtpErrorCodes.ConfirmHMACWrong;
            return null;
        }
        SecretKey decryptionKey = new SecretKeySpec(zrtpKeyR, 0, keylen, "AES");
        IvParameterSpec ivp = new IvParameterSpec(confirm1.getIv());
        
        try {
            AEScipher.init(Cipher.DECRYPT_MODE, decryptionKey, ivp);
            AEScipher.doFinal(dataToSecure, 0, dataToSecure.length, dataToSecure);
        } catch (GeneralSecurityException e) {
            sendInfo(ZrtpCodes.MessageSeverity.Severe, EnumSet
                    .of(ZrtpCodes.SevereCodes.SevereSecurityException));
            errMsg[0] = ZrtpCodes.ZrtpErrorCodes.CriticalSWError;
            return null;
        }
        confirm1.setDataToSecure(dataToSecure);
        
        // Check HMAC of DHPart1 packet stored in temporary buffer. The
        // HMAC key of the DHPart1 packet is peer's H0 that is contained in
        // Confirm1. Refer to chapter 9.1 and chapter 10.
        if (!checkMsgHmac(confirm1.getHashH0())) {
            sendInfo(ZrtpCodes.MessageSeverity.Severe, EnumSet.of(ZrtpCodes.SevereCodes.SevereDH1HMACFailed));
            errMsg[0] = ZrtpCodes.ZrtpErrorCodes.CriticalSWError;
            return null;
        }
        /*
         * The Confirm1 is ok, handle the Retained secret stuff and inform
         * GUI about state.
         */
        boolean sasFlag = confirm1.isSASFlag();

        // Initialize a ZID record to get peer's retained secrets
        ZidRecord zidRec = new ZidRecord(peerZid);

        ZidFile zidf = ZidFile.getInstance();
        zidf.getRecord(zidRec);

        // Our peer did not confirm the SAS in last session, thus reset
        // our SAS flag too.
        if (!sasFlag) {
          zidRec.resetSasVerified();
        }

        // get verified flag from current RS1 before set a new RS1. This
        // may not be set even if peer's flag is set in confirm1 message.
        sasFlag = zidRec.isSasVerified() ? true : false;

        // Inform GUI about security state and SAS state
        boolean sasVerified = zidRec.isSasVerified();
        String cs = new String((cipher == ZrtpConstants.SupportedSymCiphers.AES1) ? "AES-CM-128" : "AES-CM-256");
        callback.srtpSecretsOn(cs, SAS, sasVerified);

        // now we are ready to save the new RS1 which inherits the verified
        // flag from old RS1
        zidRec.setNewRs1(newRs1, -1);
        zidf.saveRecord(zidRec);

        // now generate my Confirm2 message
        zrtpConfirm2.setMessageType(ZrtpConstants.Confirm2Msg);
        zrtpConfirm2.setSignatureLength(0);
        zrtpConfirm2.setHashH0(H0); 

        if (sasFlag) {
            zrtpConfirm2.setSASFlag();
        }
        zrtpConfirm2.setExpTime(0xFFFFFFFF);
        zrtpConfirm2.setIv(randomIV);

        // Encrypt and HMAC with Initiator's key - we are Initiator here
        // see ZRTP specification chapter xYxY
        dataToSecure = zrtpConfirm2.getDataToSecure();

        SecretKey encryptionKey = new SecretKeySpec(zrtpKeyI, 0, keylen, "AES");
        ivp = new IvParameterSpec(randomIV);
        
        try {
            AEScipher.init(Cipher.ENCRYPT_MODE, encryptionKey, ivp);
            AEScipher.doFinal(dataToSecure, 0, dataToSecure.length, dataToSecure);
        } catch (GeneralSecurityException e) {
            sendInfo(ZrtpCodes.MessageSeverity.Severe, EnumSet
                    .of(ZrtpCodes.SevereCodes.SevereSecurityException));
            errMsg[0] = ZrtpCodes.ZrtpErrorCodes.CriticalSWError;
            return null;
        }
        confMac = computeHmac(hmacKeyI, dataToSecure, dataToSecure.length);
        zrtpConfirm2.setDataToSecure(dataToSecure);
        zrtpConfirm2.setHmac(confMac);
        
        return zrtpConfirm2;
    }

    /**
     * Prepare the Conf2Ack packet.
     * 
     * This method prepare the Conf2Ack packet. The input to this method is the
     * Confirm2 packet received from our peer. The peer sends the Confirm2
     * packet as response of our Confirm1. Here we are in the role of the
     * Initiator
     */
    protected ZrtpPacketConf2Ack prepareConf2Ack(ZrtpPacketConfirm confirm2,
            ZrtpCodes.ZrtpErrorCodes[] errMsg) {
        sendInfo(ZrtpCodes.MessageSeverity.Info, EnumSet
                .of(ZrtpCodes.InfoCodes.InfoRespConf2Received));

        // Use the Initiator's keys here because we are Responder here and
        // reveice packets from Initiator
        int keylen = (cipher == ZrtpConstants.SupportedSymCiphers.AES1) ? 16
                : 32;
        byte[] dataToSecure = confirm2.getDataToSecure();

        byte[] confMac = computeHmac(hmacKeyI, dataToSecure,
                dataToSecure.length);

        if (ZrtpUtils.byteArrayCompare(confMac, confirm2.getHmac(),
                2 * ZrtpPacketBase.ZRTP_WORD_SIZE) != 0) {
            errMsg[0] = ZrtpCodes.ZrtpErrorCodes.ConfirmHMACWrong;
            return null;
        }
        SecretKey decryptionKey = new SecretKeySpec(zrtpKeyI, 0, keylen, "AES");
        IvParameterSpec ivp = new IvParameterSpec(confirm2.getIv());

        try {
            AEScipher.init(Cipher.DECRYPT_MODE, decryptionKey, ivp);
            AEScipher.doFinal(dataToSecure, 0, dataToSecure.length,
                    dataToSecure);
        } catch (GeneralSecurityException e) {
            sendInfo(ZrtpCodes.MessageSeverity.Severe, EnumSet
                    .of(ZrtpCodes.SevereCodes.SevereSecurityException));
            errMsg[0] = ZrtpCodes.ZrtpErrorCodes.CriticalSWError;
            return null;
        }
        confirm2.setDataToSecure(dataToSecure);
        // Check HMAC of DHPart2 packet stored in temporary buffer. The
        // HMAC key of the DHPart2 packet is peer's H0 that is contained in
        // Confirm2. Refer to chapter 9.1 and chapter 10.
        if (!checkMsgHmac(confirm2.getHashH0())) {
            sendInfo(ZrtpCodes.MessageSeverity.Severe, EnumSet
                    .of(ZrtpCodes.SevereCodes.SevereDH2HMACFailed));
            errMsg[0] = ZrtpCodes.ZrtpErrorCodes.CriticalSWError;
            return null;
        }
        /*
         * The Confirm2 is ok, handle the Retained secret stuff and inform GUI
         * about state.
         */
        boolean sasFlag = confirm2.isSASFlag();

        // Initialize a ZID record to get peer's retained secrets
        ZidRecord zidRec = new ZidRecord(peerZid);

        ZidFile zidf = ZidFile.getInstance();
        zidf.getRecord(zidRec);

        // Our peer did not confirm the SAS in last session, thus reset
        // our SAS flag too.
        if (!sasFlag) {
            zidRec.resetSasVerified();
        }

        // Inform GUI about security state and SAS state
        boolean sasVerified = zidRec.isSasVerified();
        String cs = new String(
                (cipher == ZrtpConstants.SupportedSymCiphers.AES1) ? "AES-CM-128"
                        : "AES-CM-256");
        callback.srtpSecretsOn(cs, SAS, sasVerified);

        // save new RS1, this inherits the verified flag from old RS1
        zidRec.setNewRs1(newRs1, -1);
        zidf.saveRecord(zidRec);

        return zrtpConf2Ack;
    }

    /**
     * Prepare the ErrorAck packet.
     *
     * This method prepares the ErrorAck packet. The input to this method is the
     * Error packet received from the peer.
     */
    protected ZrtpPacketErrorAck prepareErrorAck(ZrtpPacketError epkt) {
        int code = epkt.getErrorCode();
        
        for (ZrtpCodes.ZrtpErrorCodes zc: ZrtpCodes.ZrtpErrorCodes.values()) {
            if (zc.value == code) {
                sendInfo(ZrtpCodes.MessageSeverity.ZrtpError, EnumSet.of(zc));
                break;
            }
        }
        return zrtpErrorAck;
    }

    /**
     * Prepare the Error packet.
     *
     * This method prepares the Error packet. The input to this method is the
     * error code to be included into the message.
     */
    protected ZrtpPacketError prepareError(ZrtpCodes.ZrtpErrorCodes errMsg) {
        zrtpError.setErrorCode(errMsg.value);
        return zrtpError;
    }

    /**
     * Prepare a ClearAck packet.
     *
     * This method checks if the GoClear message is valid. If yes then switch
     * off SRTP processing, stop sending of RTP packets (pause transmit) and
     * inform the user about the fact. Only if user confirms the GoClear message
     * normal RTP processing is resumed.
     *
     * @return
     *     NULL if GoClear could not be authenticated, a ClearAck packet
     *     otherwise.
     */
    // ZrtpPacketClearAck prepareClearAck(ZrtpPacketGoClear gpkt) {return null;}

    /**
     * Prepare a GoClearAck packet w/o HMAC
     *
     * Prepare a GoCLear packet without a HMAC but with a short error message.
     * This type of GoClear is used if something went wrong during the ZRTP
     * negotiation phase.
     *
     * @return
     *     A goClear packet without HMAC
     */
    // ZrtpPacketGoClear prepareGoClear(ZrtpCodes.ZrtpErrorCodes[] errMsg) {return null;}

    /**
     * Compare the hvi values.
     * 
     * Compare a received Commit packet with our Commit packet and returns which
     * Commit packt is "more important". See chapter 5.2 to get further
     * information how to compare Commit packets.
     * 
     * @param commit
     *            Pointer to the peer's commit packet we just received.
     * @return <0 if our Commit packet is "less important" >0 if ours is "more
     *         important" 0 shouldn't happen because we compare crypto hashes
     */
    protected int compareCommit(ZrtpPacketCommit commit) {
        return (ZrtpUtils.byteArrayCompare(hvi, commit.getHvi(),
                ZrtpConstants.SHA256_DIGEST_LENGTH));
    }

    /**
     * Verify the H2 hash image.
     *
     * Verifies the H2 hash contained in a received commit message.
     * This functions just verifies H2 but does not store it.
     *
     * @param commit
     *    Pointer to the peer's commit packet we just received.
     * @return
     *    true if H2 is ok and verified
     *    false if H2 could not be verified
     */
    protected boolean verifyH2(ZrtpPacketCommit commit) {

        byte[] tmpH3 = sha256.digest(commit.getH2());
        if (ZrtpUtils.byteArrayCompare(tmpH3, peerH3, ZrtpConstants.SHA256_DIGEST_LENGTH) != 0) {
            return false;
        }
        return true;
    }

    /**
     * Send information messages to the hosting environment.
     * 
     * The ZRTP implementation uses this method to send information messages to
     * the host. Along with the message ZRTP provides a severity indicator that
     * defines: Info, Warning, Error, Alert. Refer to the MessageSeverity enum
     * in the ZrtpCallback class.
     * 
     * @param severity
     *            This defines the message's severity
     * @param subCode
     *            The subcode identifying the reason.
     * @see ZrtpCodes#MessageSeverity
     */
    protected void sendInfo(ZrtpCodes.MessageSeverity severity,
            EnumSet<?> subCode) {
        callback.sendInfo(severity, subCode);
    }

    /**
     * ZRTP state engine calls this if the negotiation failed.
     *
     * ZRTP calls this method in case ZRTP negotiation failed. The parameters
     * show the severity as well as some explanatory text.
     *
     * @param severity
     *     This defines the message's severity
     * @param subCode
     *     The subcode identifying the reason.
     * @see ZrtpCodes#MessageSeverity
     */
    protected void zrtpNegotiationFailed(ZrtpCodes.MessageSeverity severity, EnumSet<?> subCode) {
        callback.zrtpNegotiationFailed(severity, subCode);
    }

    /**
     * ZRTP state engine calls this method if the other side does not support ZRTP.
     *
     * If the other side does not answer the ZRTP <em>Hello</em> packets then
     * ZRTP calls this method,
     *
     */
    protected void zrtpNotSuppOther() {
        callback.zrtpNotSuppOther();
    }

    /**
     * Signal SRTP secrets are ready.
     *
     * This method calls a callback method to inform the host that the SRTP
     * secrets are ready.
     *
     * @param part
     *    Defines for which part (sender or receiver) to switch on security
     * @return
     *    Returns false if something went wrong during initialization of SRTP
     *    context. Propagate error back to state engine.
     */
    protected boolean srtpSecretsReady(ZrtpCallback.EnableSecurity part) {
        ZrtpSrtpSecrets sec = new ZrtpSrtpSecrets();
        
        sec.keyInitiator = srtpKeyI;
        sec.initKeyLen = (cipher == ZrtpConstants.SupportedSymCiphers.AES1) ? 128 :256;
        sec.saltInitiator = srtpSaltI;
        sec.initSaltLen = 112;
        sec.keyResponder = srtpKeyR;
        sec.respKeyLen = (cipher == ZrtpConstants.SupportedSymCiphers.AES1) ? 128 :256;
        sec.saltResponder = srtpSaltR;
        sec.respSaltLen = 112;
        sec.srtpAuthTagLen = (authLength == ZrtpConstants.SupportedAuthLengths.HS32)? 32 : 80;
        sec.setRole(myRole);
        
        return callback.srtpSecretsReady(sec, part);
    }

    /**
     * Switch off SRTP secrets.
     *
     * This method calls a callback method to inform the host that the SRTP
     * secrets shall be cleared.
     *
     * @param part
     *    Defines for which part (sender or receiver) to clear
     */
    protected void srtpSecretsOff(ZrtpCallback.EnableSecurity part) {
        callback.srtpSecretsOff(part);
    }

    /**
     * ZRTP state engine calls these methods to enter or leave its 
     * synchronization mutex.
     */
    protected void synchEnter() {
        // callback.synchEnter();
    }
    protected void synchLeave() {
        //callback.synchLeave();
    }

    // Private internal methods
    /**
     * Helper function to store ZRTP message data in a temporary buffer
     *
     * This functions first clears the temporary buffer, then stores
     * the packet's data to it. We use this to check the packet's HMAC
     * after we received the HMAC key in to following packet.
     *
     * @param data
     *    Pointer to the packet's ZRTP message
     */
    private void storeMsgTemp(ZrtpPacketBase pkt) {
        int length = pkt.getLength() * ZrtpPacketBase.ZRTP_WORD_SIZE;
        Arrays.fill(tempMsgBuffer, (byte) 0);
        System.arraycopy(pkt.getHeaderBase(), 0, tempMsgBuffer, 0, length);
        lengthOfMsgData = length;
    }

    /**
     * Check a ZRTP message HMAC of a previously stored message.
     * 
     * This function uses a HMAC key to compute a HMAC 
     * of a previous received and stored ZRTP message. It compares the
     * computed HMAC and the HMAC stored in the stored message and returns the
     * result.
     * 
     * @param key
     *            Pointer to the HMAC key.
     * @return Returns true if the computed HMAC and the stored HMAC match,
     *         false otherwise.
     */
    private boolean checkMsgHmac(byte[] keyIn) {
        //compute HMAC, but exlude the stored HMAC :-)
        int len = lengthOfMsgData - (2 * ZrtpPacketBase.ZRTP_WORD_SIZE); // :-)
        SecretKey key = new SecretKeySpec(keyIn, "HMAC");
        try {
            hmacSha256.init(key);
        } catch (GeneralSecurityException e) {
            sendInfo(ZrtpCodes.MessageSeverity.Severe, EnumSet
                    .of(ZrtpCodes.SevereCodes.SevereSecurityException));
            return false;
        }
        hmacSha256.update(tempMsgBuffer, 0, len);
        byte data[] = hmacSha256.doFinal();
        byte[] storedMac = ZrtpUtils.readRegion(tempMsgBuffer, len,
                2 * ZrtpPacketBase.ZRTP_WORD_SIZE);
        return (ZrtpUtils.byteArrayCompare(data, storedMac,
                2 * ZrtpPacketBase.ZRTP_WORD_SIZE) == 0);
    }

    /**
     * Set the client ID for ZRTP Hello message.
     * 
     * The user of ZRTP must set its id to identify itself in the ZRTP HELLO
     * message. The maximum length is 16 characters. Shorter id string are
     * allowed, they will be filled with blanks. A longer id is truncated to 16
     * characters.
     * 
     * The identifier is set in the Hello packet of ZRTP. Thus only after
     * setting the identifier ZRTP can compute the HMAC and the final helloHash.
     * 
     * @param id
     *            The client's id
     */
    private void setClientId(String id) {
        String tmp = "                ";
        if (id.length() < 4 * ZrtpPacketBase.ZRTP_WORD_SIZE) {
            zrtpHello.setClientId(tmp);
        }
        zrtpHello.setClientId(id);
        int len = zrtpHello.getLength() * ZrtpPacketBase.ZRTP_WORD_SIZE;

        // Hello packet is ready now, compute its HMAC
        // (excluding the HMAC field (2*ZTP_WORD_SIZE)) and store in Hello
        byte data[] = computeHmac(H2, zrtpHello.getHeaderBase(), len
                - (2 * ZrtpPacketBase.ZRTP_WORD_SIZE));
        zrtpHello.setHMAC(data);

        // calculate hash over the final Hello packet including the computed and
        // stored HMAC, refer to chap 9.1 how to use this hash in SIP/SDP.
        //
        // getHeaderBase() returns the full packetBuffer array. The length of
        // this array includes the CRC which are not part of the helloHash. 
        // Thus compute digest only for the real message length.
        sha256.update(zrtpHello.getHeaderBase(), 0, len);
        helloHash = sha256.digest();
    }

    /**
     * Helper function to compute a ZRTP message HMAC
     * 
     * This function gets a HMAC key and uses it to compute a HMAC with this key
     * and the stored data of a previous received ZRTP message. It compares the
     * computed HMAC and the HMAC stored in the received message and returns the
     * result.
     * 
     * @param key
     *            Pointer to the HMAC key.
     * @return Returns true if the computed HMAC and the stored HMAC match,
     *         false otherwise.
     */
    private byte[] computeMsgHmac(byte[] keyIn, ZrtpPacketBase pkt) {

        // compute HMAC, but exclude the stored HMAC in length computation:-)
        int len = (pkt.getLength() - 2) * ZrtpPacketBase.ZRTP_WORD_SIZE;
        return computeHmac(keyIn, pkt.getHeaderBase(), len);
    }

    /**
     * Compute a HMAC over some data
     * 
     * @param keyIn
     *            The key to use for the HMAC
     * @param toSign
     *            The data to sign
     * @param len
     *            the length of the data to sign
     * @return the HMAC data
     */
    private byte[] computeHmac(byte[] keyIn, byte[] toSign, int len) {
        SecretKey key = new SecretKeySpec(keyIn, "HMAC");
        try {
            hmacSha256.init(key);
        } catch (GeneralSecurityException e) {
            sendInfo(ZrtpCodes.MessageSeverity.Severe, EnumSet
                    .of(ZrtpCodes.SevereCodes.SevereSecurityException));
            return null;
        }
        hmacSha256.update(toSign, 0, len);
        return hmacSha256.doFinal();
    }

    /**
     * Compute my hvi value according to ZRTP specification.
     */
    private void computeHvi(ZrtpPacketDHPart dh, ZrtpPacketHello hello) {
        sha256.update(dh.getHeaderBase(), 0, dh.getLength()
                * ZrtpPacketBase.ZRTP_WORD_SIZE);
        sha256.update(hello.getHeaderBase(), 0, hello.getLength()
                * ZrtpPacketBase.ZRTP_WORD_SIZE);
        hvi = sha256.digest();
    }

    private void computeSharedSecretSet(ZidRecord zidRec) {
        /*
         * Compute the Initiator's and Reponder's retained shared secret Ids.
         */
        byte[] randBuf = new byte[ZidRecord.RS_LENGTH];

        Random ran = new Random();

        if (!zidRec.isRs1Valid()) {
            ran.nextBytes(randBuf);
            rs1IDi = computeHmac(randBuf, ZrtpConstants.initiator,
                    ZrtpConstants.initiator.length);
            rs1IDr = computeHmac(randBuf, ZrtpConstants.responder,
                    ZrtpConstants.responder.length);
        } else {
            rs1IDi = computeHmac(zidRec.getRs1(), ZrtpConstants.initiator,
                    ZrtpConstants.initiator.length);
            rs1IDr = computeHmac(zidRec.getRs1(), ZrtpConstants.responder,
                    ZrtpConstants.responder.length);
        }

        if (!zidRec.isRs2Valid()) {
            ran.nextBytes(randBuf);
            rs2IDi = computeHmac(randBuf, ZrtpConstants.initiator,
                    ZrtpConstants.initiator.length);
            rs2IDr = computeHmac(randBuf, ZrtpConstants.responder,
                    ZrtpConstants.responder.length);
        } else {
            rs2IDi = computeHmac(zidRec.getRs2(), ZrtpConstants.initiator,
                    ZrtpConstants.initiator.length);
            rs2IDr = computeHmac(zidRec.getRs2(), ZrtpConstants.responder,
                    ZrtpConstants.responder.length);
        }

        /*
         * For the time being we don't support these types of shared secrect.
         * Could be easily done: somebody sets some data into our ZRtp object,
         * check it here and use it. Otherwise use the random data.
         */
        ran.nextBytes(randBuf);
        s3IDi = computeHmac(randBuf, ZrtpConstants.initiator,
                ZrtpConstants.initiator.length);
        s3IDr = computeHmac(randBuf, ZrtpConstants.responder,
                ZrtpConstants.responder.length);

        ran.nextBytes(randBuf);
        pbxSecretIDi = computeHmac(randBuf, ZrtpConstants.initiator,
                ZrtpConstants.initiator.length);
        pbxSecretIDr = computeHmac(randBuf, ZrtpConstants.responder,
                ZrtpConstants.responder.length);
    }

    void computeSRTPKeys() {

        // Inititiator key and salt
        srtpKeyI = computeHmac(s0, ZrtpConstants.iniMasterKey,
                ZrtpConstants.iniMasterKey.length);
        srtpSaltI = computeHmac(s0, ZrtpConstants.iniMasterSalt,
                ZrtpConstants.iniMasterSalt.length);

        // Responder key and salt
        srtpKeyR = computeHmac(s0, ZrtpConstants.respMasterKey,
                ZrtpConstants.respMasterKey.length);
        srtpSaltR = computeHmac(s0, ZrtpConstants.respMasterSalt,
                ZrtpConstants.respMasterSalt.length);

        // The HMAC keys
        hmacKeyI = computeHmac(s0, ZrtpConstants.iniHmacKey,
                ZrtpConstants.iniHmacKey.length);
        hmacKeyR = computeHmac(s0, ZrtpConstants.respHmacKey,
                ZrtpConstants.respHmacKey.length);

        // The keys for Confirm messages
        zrtpKeyI = computeHmac(s0, ZrtpConstants.iniZrtpKey,
                ZrtpConstants.iniZrtpKey.length);
        zrtpKeyR = computeHmac(s0, ZrtpConstants.respZrtpKey,
                ZrtpConstants.respZrtpKey.length);

        // Compute the new Retained Secret
        newRs1 = computeHmac(s0, ZrtpConstants.retainedSec,
                ZrtpConstants.retainedSec.length);

        // Compute the ZRTP Session Key
        zrtpSession = computeHmac(s0, ZrtpConstants.zrtpSessionKey,
                ZrtpConstants.zrtpSessionKey.length);

        // perform SAS generation according to chapter 5.5 and 8.
        // we don't need a speciai sasValue filed. sasValue are the first
        // (leftmost) 32 bits (4 bytes) of sasHash
        sasHash = computeHmac(zrtpSession, ZrtpConstants.sasString,
                ZrtpConstants.sasString.length);

        // according to chapter 8 only the leftmost 20 bits of sasValue (aka
        // sasHash) are used to create the character SAS string of type SAS
        // base 32 (5 bits per character)
        byte[] sasBytes = new byte[4];
        sasBytes[0] = sasHash[0];
        sasBytes[1] = sasHash[1];
        sasBytes[2] = (byte) (sasHash[2] & 0xf0);
        sasBytes[3] = 0;
        SAS = Base32.binary2ascii(sasBytes, 20);
    }

    void generateS0Initiator(ZrtpPacketDHPart dhPart, ZidRecord zidRec) {
        byte[][] setD = new byte[4][];
        int rsFound = 0;

        setD[0] = setD[1] = setD[2] = setD[3] = null;

        /*
         * Select the real secrets into setD
         */
        int matchingSecrets = 0;
        if (ZrtpUtils.byteArrayCompare(rs1IDr, dhPart.getRs1Id(), 8) == 0) {
            setD[matchingSecrets++] = zidRec.getRs1();
            rsFound = 0x1;
        }
        if (ZrtpUtils.byteArrayCompare(rs2IDr, dhPart.getRs2Id(), 8) == 0) {
            setD[matchingSecrets++] = zidRec.getRs2();
            rsFound |= 0x2;
        }
        /***********************************************************************
         * Not yet supported:
         * if (ZrtpUtils.byteArrayCompare(s3IDr, dhPart.getS3Id(), 8) == 0) { 
         *      setD[matchingSecrets++] = ; 
         * } 
         * if (ZrtpUtils.byteArrayCompare(pbxSecretIDr, dhPart.getPbxSecretId(), 8) == 0) {
         *      setD[matchingSecrets++] =
         * } 
         ********************************************************************* */
        // Check if some retained secrets found
        if (((rsFound & 0x1) == 0x1) && ((rsFound & 0x2) == 0x2)) {
            sendInfo(ZrtpCodes.MessageSeverity.Info, EnumSet
                    .of(ZrtpCodes.InfoCodes.InfoBothRSMatch));
        } else {
            zidRec.resetSasVerified();

            if (rsFound == 0) {
                sendInfo(ZrtpCodes.MessageSeverity.Warning, EnumSet
                        .of(ZrtpCodes.WarningCodes.WarningNoRSMatch));
            }
            if (((rsFound & 0x1) == 0x1) && !((rsFound & 0x2) == 0x2)) {
                sendInfo(ZrtpCodes.MessageSeverity.Warning, EnumSet
                        .of(ZrtpCodes.WarningCodes.WarningFirstRSMatch));
            }
            if (!((rsFound & 0x1) == 0x1) && ((rsFound & 0x2) == 0x2)) {
                sendInfo(ZrtpCodes.MessageSeverity.Warning, EnumSet
                        .of(ZrtpCodes.WarningCodes.WarningSecondRSMatch));
            }
        }
        /*
         * Ready to generate s0 here. The formular to compute S0 (Refer to ZRTP
         * specification 5.4.4):
         * 
         * s0 = hash( counter | DHResult | "ZRTP-HMAC-KDF" | ZIDi | ZIDr | \
         * total_hash | len(s1) | s1 | len(s2) | s2 | len(s3) | s3 | len(s4) | \
         * s4)
         * 
         * Note: in this function we are Initiator, thus ZIDi is our zid (zid),
         * ZIDr is the peer's zid (peerZid).
         */

        // Very first element is a fixed counter, big endian
        byte[] counter = ZrtpUtils.int32ToArray(1);
        sha256.update(counter, 0, 4);

        // Next is the DH result itself
        sha256.update(DHss);

        // Next the fixed string "ZRTP-HMAC-KDF"
        sha256.update(ZrtpConstants.KDFString);

        // Next is Initiator's id (ZIDi), in this case as Initiator
        // it is zid
        sha256.update(zid);

        // Next is Responder's id (ZIDr), in this case our peer's id
        sha256.update(peerZid);

        // Next ist total hash (messageHash) itself
        sha256.update(messageHash);

        /*
         * For each matching shared secret hash the length of the shared secret
         * as 32 bit big-endian number followd by the shared secret itself. The
         * length of a shared seceret is currently fixed to
         * SHA256_DIGEST_LENGTH. If a shared secret is not used _only_ its
         * length is hased as zero length.
         */
        // prepare 32 bit big-endian number
        byte[] secretHashLen = ZrtpUtils
                .int32ToArray(ZrtpConstants.SHA256_DIGEST_LENGTH);
        byte[] nullinger = new byte[4];
        Arrays.fill(nullinger, (byte) 0);

        for (int i = 0; i < 4; i++) {
            if (setD[i] != null) { // a matching secret, set length, then
                                    // secret
                sha256.update(secretHashLen);
                sha256.update(setD[i]);
            } else { // no machting secret, set length 0, skip secret
                sha256.update(nullinger);
            }
        }
        s0 = sha256.digest();
        // ZrtpUtils.hexdump("S0 I", s0, ZrtpConstants.SHA256_DIGEST_LENGTH);

        Arrays.fill(DHss, (byte) 0);
        DHss = null;

        computeSRTPKeys();
    }

    void generateS0Responder(ZrtpPacketDHPart dhPart, ZidRecord zidRec) {
        byte[][] setD = new byte[4][];
        int rsFound = 0;

        setD[0] = setD[1] = setD[2] = setD[3] = null;

        /*
         * Select the real secrets into setD
         */
        int matchingSecrets = 0;
        if (ZrtpUtils.byteArrayCompare(rs1IDi, dhPart.getRs1Id(), 8) == 0) {
            setD[matchingSecrets++] = zidRec.getRs1();
            rsFound = 0x1;
        }
        if (ZrtpUtils.byteArrayCompare(rs2IDi, dhPart.getRs2Id(), 8) == 0) {
            setD[matchingSecrets++] = zidRec.getRs2();
            rsFound |= 0x2;
        }
        /***********************************************************************
         * Not yet supported 
         * if (ZrtpUtils.byteArrayCompare(s3IDi, dhPart.getS3Id(), 8) == 0) {
         *      setD[matchingSecrets++] =
         * }
         * if (ZrtpUtils.byteArrayCompare(pbxSecretIDi, dhPart.getPbxSecretId(), 8) == 0) {
         *      setD[matchingSecrets++] =
         * }
         **********************************************************************/

        // Check if some retained secrets found
        if (((rsFound & 0x1) == 0x1) && ((rsFound & 0x2) == 0x2)) {
            sendInfo(ZrtpCodes.MessageSeverity.Info, EnumSet
                    .of(ZrtpCodes.InfoCodes.InfoBothRSMatch));
        } else {
            zidRec.resetSasVerified();

            if (rsFound == 0) {
                sendInfo(ZrtpCodes.MessageSeverity.Warning, EnumSet
                        .of(ZrtpCodes.WarningCodes.WarningNoRSMatch));
            }
            if (((rsFound & 0x1) == 0x1) && !((rsFound & 0x2) == 0x2)) {
                sendInfo(ZrtpCodes.MessageSeverity.Warning, EnumSet
                        .of(ZrtpCodes.WarningCodes.WarningFirstRSMatch));
            }
            if (!((rsFound & 0x1) == 0x1) && ((rsFound & 0x2) == 0x2)) {
                sendInfo(ZrtpCodes.MessageSeverity.Warning, EnumSet
                        .of(ZrtpCodes.WarningCodes.WarningSecondRSMatch));
            }
        }
        /*
         * ready to generate s0 here. The formular to compute S0 (Refer to ZRTP
         * specification 5.4.4):
         * 
         * s0 = hash( counter | DHResult | "ZRTP-HMAC-KDF" | ZIDi | ZIDr | \
         * total_hash | len(s1) | s1 | len(s2) | s2 | len(s3) | s3 | len(s4) | \
         * s4 )
         * 
         * Note: in this function we are Responder, thus ZIDi is the peer's zid
         * (peerZid), ZIDr is our zid.
         */

        // Very first element is a fixed counter, big endian
        byte[] counter = ZrtpUtils.int32ToArray(1);
        sha256.update(counter, 0, 4);

        // Next is the DH result itself
        sha256.update(DHss);

        // Next the fixed string "ZRTP-HMAC-KDF"
        sha256.update(ZrtpConstants.KDFString);

        // Next is Initiator's id (ZIDi), in this case as Responder
        // it is peerZid
        sha256.update(peerZid);

        // Next is Responder's id (ZIDr), in this case our own zid
        sha256.update(zid);

        // Next ist total hash (messageHash) itself
        sha256.update(messageHash);

        /*
         * For each matching shared secret hash the length of the shared secret
         * as 32 bit big-endian number followd by the shared secret itself. The
         * length of a shared seceret is currently fixed to
         * SHA256_DIGEST_LENGTH. If a shared secret is not used _only_ its
         * length is hased as zero length.
         */
        // prepare 32 bit big-endian number
        byte[] secretHashLen = ZrtpUtils
                .int32ToArray(ZrtpConstants.SHA256_DIGEST_LENGTH);
        byte[] nullinger = new byte[4];
        Arrays.fill(nullinger, (byte) 0);

        for (int i = 0; i < 4; i++) {
            if (setD[i] != null) { // a matching secret, set length, then
                                    // secret
                sha256.update(secretHashLen);
                sha256.update(setD[i]);
            } else { // no machting secret, set length 0, skip secret
                sha256.update(nullinger);
            }
        }
        s0 = sha256.digest();
        // ZrtpUtils.hexdump("S0 R", s0, ZrtpConstants.SHA256_DIGEST_LENGTH);

        Arrays.fill(DHss, (byte) 0);
        DHss = null;

        computeSRTPKeys();
    }

    private boolean checkPubKey(BigInteger pvr,
            ZrtpConstants.SupportedPubKeys dhtype) {
        if (pvr.equals(BigInteger.ONE)) {
            return false;
        }
        if (dhtype == ZrtpConstants.SupportedPubKeys.DH3K) {
            return !pvr.equals(ZrtpConstants.P3072MinusOne);
        }
        return false;
    }

    public static void main(String argv[]) {
        byte[] data= {1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,27,28,29,30,31,32};
        ZRtp zrtp = null;
        try {
            zrtp = new ZRtp(data, null, "GNU ZRTP4J 1.0.0", null);
        } catch (GeneralSecurityException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        }
        ZrtpUtils.hexdump("Hello packet", zrtp.zrtpHello.getHeaderBase(), zrtp.zrtpHello.getHeaderBase().length);
        System.err.println("ZRtp done");
    }

}

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

import java.util.EnumSet;


/**
 * This interface class defines the callback functions required by GNU ZRTP.
 * 
 * This interface class defines the callback interface that the specific part of
 * a GNU ZRTP must implement. The generic part of GNU ZRTP uses these mehtods to
 * communicate with the specific part, for example to send data via the RTP/SRTP
 * stack, to set timers and cancel timer and so on.
 * 
 * The generiy part of GNU ZRTP needs only a few callback methods to be
 * implemented by the specific part.
 * 
 * @author Werner Dittmann <Werner.Dittmann@t-online.de>
 * 
 */

public interface ZrtpCallback {

    /**
     * This enum defines which role a ZRTP peer has.
     *
     * According to the ZRTP specification the role determines which keys to
     * use to encrypt or decrypt SRTP data.
     *
     * <ul>
     * <li> The Initiator encrypts SRTP data using the <em>keyInitiator</em> and the
     *      <em>saltInitiator</em> data, the Responder uses these data to decrypt.
     * </li>
     * <li> The Responder encrypts SRTP data using the <em>keyResponder</em> and the
     *      <em>saltResponder</em> data, the Initiator uses these data to decrypt.
     * </li>
     * </ul>
     */
    public static enum  Role {
        Responder,
        Initiator
    }

    public static enum EnableSecurity {
        ForReceiver,
        ForSender
    }

    /**
     * Send a ZRTP packet via RTP.
     *
     * ZRTP calls this method to send a ZRTP packet via the RTP session.
     *
     * @param data
     *    Points to ZRTP packet to send.
     * @return
     *    false if sending failed, true if packet was send
     */
    public boolean sendDataZRTP(byte[] data);

    /**
     * Activate timer.
     *
     * @param time
     *    The time in ms for the timer
     * @return
     *    zero if activation failed, one if timer was activated
     */
    public int activateTimer(int time);

    /**
     * Cancel the active timer.
     *
     * @return
     *    zero if cancel action failed, one if timer was canceled
     */
    public int cancelTimer();

    /**
     * Send information messages to the hosting environment.
     *
     * The ZRTP implementation uses this method to send information
     * messages to the host. Along with the message ZRTP provides a
     * severity indicator that defines: Info, Warning, Error,
     * Alert. Refer to the <code>MessageSeverity</code> enum above.
     *
     * @param severity
     *     This defines the message's severity
     * @param subCode
     *     The subcode identifying the reason.
     * @see gnu.java.zrtp.ZrtpCodes#MessageSeverity
     */
    public void sendInfo(ZrtpCodes.MessageSeverity severity, EnumSet<?> subCode);

    /**
     * SRTP crypto data ready for the sender or receiver.
     *
     * The ZRTP implementation calls this method right after all SRTP
     * secrets are computed and ready to be used. The parameter points
     * to a structure that contains pointers to the SRTP secrets and a
     * <code>enum Role</code>. The called method (the implementation
     * of this abstract method) must either copy the pointers to the SRTP
     * data or the SRTP data itself to a save place. The SrtpSecret_t
     * structure is destroyed after the callback method returns to the
     * ZRTP implementation.
     *
     * The SRTP data themselfs are ontained in the ZRtp object and are
     * valid as long as the ZRtp object is active. TheZRtp's
     * destructor clears the secrets. Thus the called method needs to
     * save the pointers only, ZRtp takes care of the data.
     *
     * The implementing class may enable SRTP processing in this
     * method or delay it to srtpSecertsOn().
     *
     * @param secrets A pointer to a SrtpSecret_t structure that
     *     contains all necessary data.
     *
     * @param part for which part (Sender or Receiver) this data is
     *     valid.
     * @return
     *      true if secrets could be set and crypto contexts created.
     *
     */
    public boolean srtpSecretsReady(ZrtpSrtpSecrets secrets, EnableSecurity part);

    /**
     * Switch off the security for the defined part.
     *
     * @param part Defines for which part (sender or receiver) to
     *    switch on security
     */
    public void srtpSecretsOff(EnableSecurity part);

    /**
     * Switch on the security.
     *
     * ZRTP calls this method after it has computed the SAS and check
     * if it is verified or not. In addition ZRTP provides information
     * about the cipher algorithm and key length for the SRTP session.
     *
     * This method must enable SRTP processing if it was not enabled
     * during sertSecretsReady().
     *
     * @param c The name of the used cipher algorithm and mode, or
     *    NULL
     *
     * @param s The SAS string
     *
     * @param verified if <code>verified</code> is true then SAS was
     *    verified by both parties during a previous call.
     */
    public void srtpSecretsOn(String c, String s, boolean verified);

    /**
     * This method handles GoClear requests.
     *
     * According to the ZRTP specification the user must be informed about
     * a GoClear request because the ZRTP implementation switches off security
     * if it could authenticate the GoClear packet.
     *
     * <b>Note:</b> GoClear is not yet implemented in GNU ZRTP.
     *
     */
    public void handleGoClear();

    /**
     * Handle ZRTP negotiation failed.
     *
     * ZRTP calls this method in case ZRTP negotiation failed. The
     * parameters show the severity as well as the reason.
     *
     * @param severity
     *     This defines the message's severity
     * @param subCode
     *     The subcode identifying the reason.
     * @see gnu.java.zrtp.ZrtpCodes#MessageSeverity
     */
    public void zrtpNegotiationFailed(ZrtpCodes.MessageSeverity severity, EnumSet<?> subCode);

    /**
     * ZRTP calls this method if the other side does not support ZRTP.
     *
     * If the other side does not answer the ZRTP <em>Hello</em> packets then
     * ZRTP calls this method,
     *
     */
    public void zrtpNotSuppOther();

    /**
     * Inform about a PBX enrollment request.
     *
     * Please refer to chapter 8.3 ff to get more details about PBX
     * enrollment and SAS relay.
     *
     * <b>Note:</b> PBX enrollement is not yet fully supported by GNU
     * ZRTP.
     *
     * @param info Give some information to the user about the PBX
     *    requesting an enrollment.
     */
    public void zrtpAskEnrollment(ZrtpCodes.InfoEnrollment info);

    /**
     * Inform about PBX enrollment result.
     *
     * Informs the use about the acceptance or denial of an PBX enrollment
     * request.
     *
     * @param info Give some information to the user about the result
     *    of an enrollment.
     */
    public void zrtpInformEnrollment(ZrtpCodes.InfoEnrollment info);

    /**
     * Request a SAS signature.
     *
     * After ZRTP was able to compute the Short Authentication String
     * (SAS) it calls this method. The client may now use an
     * approriate method to sign the SAS. The client may use
     * ZrtpQueue#setSignatureData() to store the signature data an
     * enable signature transmission to the other peer. Refer to
     * chapter 8.2 of ZRTP specification.
     *
     * <b>Note:</b> SAS signing is not yet fully supported by GNU
     * ZRTP.
     *
     * @param sas
     *    The SAS string to sign.
     *
     */
    public void signSAS(String sas);

    /**
     * ZRTPQueue calls this method to request a SAS signature check.
     *
     * After ZRTP received a SAS signature in one of the Confirm packets it
     * call this method. The client may use <code>getSignatureLength()</code>
     * and <code>getSignatureData()</code>of ZrtpQueue to get the signature
     * data and perform the signature check. Refer to chapter 8.2 of ZRTP 
     * specification.
     *
     * If the signature check fails the client may return false to ZRTP. In
     * this case ZRTP signals an error to the other peer and terminates
     * the ZRTP handshake.
     *
     * <b>Note:</b> SAS signing is not yet fully supported by GNU
     * ZRTP.
     *
     * @param sas
     *    The SAS string that was signed by the other peer.
     * @return
     *    true if the signature was ok, false otherwise.
     *
     */
    public boolean checkSASSignature(String sas);

}

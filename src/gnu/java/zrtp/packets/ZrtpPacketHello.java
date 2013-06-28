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

package gnu.java.zrtp.packets;

import gnu.java.zrtp.ZrtpConstants;
import gnu.java.zrtp.ZrtpConfigure;
import gnu.java.zrtp.ZrtpConstants.SupportedPubKeys;
import gnu.java.zrtp.utils.ZrtpUtils;

import java.io.UnsupportedEncodingException;
import java.util.ArrayList;
import java.util.Arrays;

/**
 * Implement the Hello packet.
 *
 * The ZRTP message Hello. The implementation sends this
 * to start the ZRTP negotiation sequence. The Hello message
 * offers crypto methods and parameters to the other party. The
 * other party selects methods and parameters it can support
 * and uses the Commit message to commit these.

 * @author Werner Dittmann <Werner.Dittmann@t-online.de>
 *
 */

public class ZrtpPacketHello extends ZrtpPacketBase {
    
    // private boolean passive;
    // number of the algorithms
    private int nHash, nCipher, nPubkey, nSas, nAuth;
    
    // offsets in bytes into hello packet where algo names are stored
    private int oHash, oCipher, oPubkey, oSas, oAuth, oHmac;

    private byte helloFlags = 0;
    
//    private static final byte HELLO_PASSIVE = 0x10;
    private static final byte HELLO_MITM_FLAG = 0x20;
    private static final byte SAS_SIGN_FLAG   = 0x40;
    /*
     * The length of the Hello specific ZRTP packet part in words
     */
    private static final int ZRTP_HELLO_FIX_LENGTH = 17;
    
    /*
     * Now the Hello packet specific offsets into the packet buffer. They
     * all start after ZRTP_HEADER_LENGTH and a given in bytes, not ZRTP
     * words.
     */
    private static final int VERSION_OFFSET = ZRTP_HEADER_LENGTH * ZRTP_WORD_SIZE;   // [ZRTP_WORD_SIZE]
    private static final int CLIENT_ID_OFFSET = VERSION_OFFSET + ZRTP_WORD_SIZE;     // [4*ZRTP_WORD_SIZE]
    private static final int HASH_H3_OFFSET = CLIENT_ID_OFFSET + CLIENT_ID_SIZE;     // [8*ZRTP_WORD_SIZE]
    private static final int ZID_OFFSET = HASH_H3_OFFSET + HASH_IMAGE_SIZE;          // [3*ZRTP_WORD_SIZE]
    private static final int FLAG_LENGTH_OFFSET = ZID_OFFSET + ZID_SIZE;             // [ZRTP_WORD_SIZE]
    private static final int VARIABLE_OFFSET = FLAG_LENGTH_OFFSET + ZRTP_WORD_SIZE;

    /*
     * The length of the Hello packet in bytes. The length is variable.
     */
    private int helloLength = 
            (ZRTP_HEADER_LENGTH + ZRTP_HELLO_FIX_LENGTH) * ZRTP_WORD_SIZE + CRC_SIZE;

    private int computedLength;
    
    public ZrtpPacketHello() {
        super(null);                        // will set packet buffer explicitly
    }
    
    public void configureHello(ZrtpConfigure config) {
        
        nHash = config.getNumConfiguredHashes();
        nCipher = config.getNumConfiguredSymCiphers();
        nPubkey = config.getNumConfiguredPubKeys();
        nSas = config.getNumConfiguredSasTypes();
        nAuth = config.getNumConfiguredAuthLengths();

        // length is fixed length plus HMAC size (2*ZRTP_WORD_SIZE)
        helloLength += (2 * ZRTP_WORD_SIZE);
        helloLength += nHash * ZRTP_WORD_SIZE;
        helloLength += nCipher * ZRTP_WORD_SIZE;
        helloLength += nPubkey * ZRTP_WORD_SIZE;
        helloLength += nSas * ZRTP_WORD_SIZE;
        helloLength += nAuth * ZRTP_WORD_SIZE;
        
        packetBuffer = new byte[helloLength];
        Arrays.fill(packetBuffer, (byte)0);

        oHash = VARIABLE_OFFSET;
        oCipher = oHash + (nHash * ZRTP_WORD_SIZE);
        oAuth = oCipher + (nCipher * ZRTP_WORD_SIZE);
        oPubkey = oAuth + (nAuth * ZRTP_WORD_SIZE);
        oSas = oPubkey + (nPubkey * ZRTP_WORD_SIZE);
        oHmac = oSas + (nSas * ZRTP_WORD_SIZE);         // offset to HMAC

        setZrtpId();

        // minus 1: CRC size does not count in packet length field 
        setLength((helloLength / ZRTP_WORD_SIZE) - 1);
        setMessageType(ZrtpConstants.HelloMsg);

        packetBuffer[FLAG_LENGTH_OFFSET] = helloFlags;  // Passive flag if required
        
        packetBuffer[FLAG_LENGTH_OFFSET+1] = (byte)(nHash);
        int index = 0;
        for (ZrtpConstants.SupportedHashes sh: config.hashes()) {
            setHashType(index++, sh.name);
        }

        packetBuffer[FLAG_LENGTH_OFFSET+2] = (byte)(nCipher << 4);
        index = 0;
        for (ZrtpConstants.SupportedSymCiphers sh: config.symCiphers()) {
            setCipherType(index++, sh.name);
        }

        packetBuffer[FLAG_LENGTH_OFFSET+2] |= (byte)(nAuth);
        index = 0;
        for (ZrtpConstants.SupportedAuthLengths sh: config.authLengths()) {
            setAuthLen(index++, sh.name);
        }

        packetBuffer[FLAG_LENGTH_OFFSET+3] = (byte)(nPubkey << 4);
        index = 0;
        for (ZrtpConstants.SupportedPubKeys sh: config.publicKeyAlgos()) {
            setPubKeyType(index++, sh.name);
        }

        packetBuffer[FLAG_LENGTH_OFFSET+3] |= (byte)(nSas);
        index = 0;
        for (ZrtpConstants.SupportedSASTypes sh: config.sasTypes()) {
            setSasType(index++, sh.name);
        }
    }

    public ZrtpPacketHello(final byte[] data) {
        super(data);
        
        helloFlags = packetBuffer[FLAG_LENGTH_OFFSET];  // check for passive flag (0x10)

        int temp = packetBuffer[FLAG_LENGTH_OFFSET+1];  // contains hash counter on low 3 bits
        nHash = temp & 0x7;
        
        temp = packetBuffer[FLAG_LENGTH_OFFSET+2];      // contains cipher cnt on high 3 bits, auth cnt on low        
        nCipher = (temp & 0x70) >> 4;
        nAuth = temp & 0x7;
        temp = packetBuffer[FLAG_LENGTH_OFFSET+3];      // contains key agreement cnt on high 4 bits, sas cnt on low        
        nPubkey = (temp & 0x70) >> 4;
        nSas = temp & 0x7;

        oHash = VARIABLE_OFFSET;
        oCipher = oHash + (nHash * ZRTP_WORD_SIZE);
        oAuth = oCipher + (nCipher * ZRTP_WORD_SIZE);
        oPubkey = oAuth + (nAuth * ZRTP_WORD_SIZE);
        oSas = oPubkey + (nPubkey * ZRTP_WORD_SIZE);
        oHmac = oSas + (nSas * ZRTP_WORD_SIZE);         // offset to HMAC
        
        // +2 : the MAC at the end of the packet
        computedLength = nHash + nCipher + nAuth + nPubkey + nSas + ZRTP_HEADER_LENGTH + ZRTP_HELLO_FIX_LENGTH + 2;

    }

    public final void setClientId(final String text) {
        byte[] data = null;
        try {
            data = text.getBytes("UTF-8");
        } catch (UnsupportedEncodingException e) {
            data = ZrtpConstants.clientId.getBytes();
        }
        int length = (data.length > 4*ZRTP_WORD_SIZE)? (4*ZRTP_WORD_SIZE) : data.length;
        System.arraycopy(data, 0, packetBuffer, CLIENT_ID_OFFSET, length);
    }
    
    public final void setH3(final byte[] data)          { 
        System.arraycopy(data, 0, packetBuffer, HASH_H3_OFFSET, HASH_IMAGE_SIZE);
    }
    
    public final byte[] getH3() {
        return ZrtpUtils.readRegion(packetBuffer, HASH_H3_OFFSET, ZrtpPacketBase.HASH_IMAGE_SIZE);
    }

    public final void setZid(final byte[] data)         { 
        System.arraycopy(data, 0, packetBuffer, ZID_OFFSET, 3*ZRTP_WORD_SIZE);
    }

    public final byte[] getZid() {
        return ZrtpUtils.readRegion(packetBuffer, ZID_OFFSET, 3*ZRTP_WORD_SIZE);
    }

    public final void setVersion(final byte[] data) {
        System.arraycopy(data, 0, packetBuffer, VERSION_OFFSET, ZRTP_WORD_SIZE);
    }

    public final byte[] getVersion() {
        return ZrtpUtils.readRegion(packetBuffer, VERSION_OFFSET, ZRTP_WORD_SIZE);
    }

    public final int getVersionInt() {
        String version = new String(getVersion());
        int intVersion = 0;
        
        char c = version.charAt(0);
        if (Character.isDigit(c)) 
            intVersion = Character.digit(c, 10) * 10;
        c = version.charAt(2);
        if (Character.isDigit(c)) 
            intVersion += Character.digit(c, 10);
        return intVersion;
    }

    public final void setHashType(final int n, final byte[] data) {
        System.arraycopy(data, 0, packetBuffer, oHash+(n*ZRTP_WORD_SIZE), ZRTP_WORD_SIZE);
    }
    
    public final void setCipherType(final int n, final byte[] data) {
        System.arraycopy(data, 0, packetBuffer, oCipher+(n*ZRTP_WORD_SIZE), ZRTP_WORD_SIZE);
    }

    public final void setAuthLen(final int n, final byte[] data) {
        System.arraycopy(data, 0, packetBuffer, oAuth+(n*ZRTP_WORD_SIZE), ZRTP_WORD_SIZE);
    }

    public final void setPubKeyType(final int n, final byte[] data) {
        System.arraycopy(data, 0, packetBuffer, oPubkey+(n*ZRTP_WORD_SIZE), ZRTP_WORD_SIZE);
    }
    
    public final void setSasType(final int n, final byte[] data) {
        System.arraycopy(data, 0, packetBuffer, oSas+(n*ZRTP_WORD_SIZE), ZRTP_WORD_SIZE);
    }
    
    public final void setHMAC(final byte[] data) {
        System.arraycopy(data, 0, packetBuffer, oHmac, 2*ZRTP_WORD_SIZE);
    }

    public final void setMitmMode() {
        packetBuffer[FLAG_LENGTH_OFFSET] |= HELLO_MITM_FLAG; 
    }

    public final boolean isMitmMode() {
        return ((helloFlags & HELLO_MITM_FLAG) == HELLO_MITM_FLAG); 
    }

    public final void setSasSign() {
        packetBuffer[FLAG_LENGTH_OFFSET] |= SAS_SIGN_FLAG; 
    }

    public final boolean isSasSign() {
        return ((helloFlags & SAS_SIGN_FLAG) == SAS_SIGN_FLAG); 
    }

    public final boolean isLengthOk() {
        return computedLength == getLength();
    }

    /**
     * Check if version data matches.
     * 
     * @param data The data to compare against.
     * @return true if data matches the packet version data, false other wise.
     */
    public final boolean isSameVersion(final byte[] data) {
        for (int i = 0; i < ZRTP_WORD_SIZE; i++) {
            if (packetBuffer[VERSION_OFFSET+i] != data[i]) {
                return false;
            }
        }
        return true;
    }
    
    /**
     * Find matching algorithms in Hello packet.
     * 
     * The next functions look up and return a prefered algorithm. These
     * functions work as follows:
     * - If the Hello packet does not contain an algorithm (number of algorithms is
     *   zero) then return our prefered algorithm. This prefered algorithm must be
     *   one of the mandatory algorithms specified in chapter 6.1.x.
     * - If the functions find a match return the found algorithm.
     * - If the functions do not find a match return a prefered, mandatory
     *   algorithm.
     * This guarantees that we always return a supported alogrithm.
     *
     * The mandatory algorithms are: (internal enums are our prefered algoritms)
     * Hash:                S256 (SHA 256)             (internal enum Sha256)
     * Symmetric Cipher:    AES1 (AES 128)             (internal enum Aes128)
     * SRTP Authentication: HS32 and HS80 (32/80 bits) (internal enum AuthLen32)
     * Key Agreement:       DH3k (3072 Diffie-Helman)  (internal enum Dh3072)
     *
     * Find macthing Hash type.
     * 
     * @return found matching hash or default SHA 256.
     */
    public final ZrtpConstants.SupportedHashes findBestHash(ZrtpConfigure config) {
        if (nHash == 0)
            return ZrtpConstants.SupportedHashes.S256;

        boolean mandatoryFound = false;
        
        int numAlgosOffered = nHash;
        ArrayList<ZrtpConstants.SupportedHashes> algosOffered = 
                        new ArrayList<ZrtpConstants.SupportedHashes>(numAlgosOffered+1);

        int numAlgosConf = config.getNumConfiguredHashes();
        ArrayList<ZrtpConstants.SupportedHashes> algosConf = 
                        new ArrayList<ZrtpConstants.SupportedHashes>(numAlgosConf+1);

        // Build a list of configured hashes, appending a mandatory algo if 
        // necessary
        for (ZrtpConstants.SupportedHashes sh: config.hashes()) {
            if (sh == ZrtpConstants.SupportedHashes.S256) {
                mandatoryFound = true;
            }
            algosConf.add(sh);
        }
        if (!mandatoryFound) {
            algosConf.add(ZrtpConstants.SupportedHashes.S256);
        }

        // Build a list of offered hashes, appending a mandatory algo if 
        // necessary
        mandatoryFound = false;
        for (int ii = 0; ii < nHash; ii++) {
            int o = oHash + (ii * ZRTP_WORD_SIZE);
            for (ZrtpConstants.SupportedHashes sh : ZrtpConstants.SupportedHashes
                    .values()) {
                byte[] s = sh.name;
                if (s[0] == packetBuffer[o] && s[1] == packetBuffer[o + 1]
                        && s[2] == packetBuffer[o + 2]
                        && s[3] == packetBuffer[o + 3]) {
                    algosOffered.add(sh);
                    if (sh == ZrtpConstants.SupportedHashes.S256) {
                        mandatoryFound = true;
                    }
                }
            }
        }
        if (!mandatoryFound) {
            algosOffered.add(ZrtpConstants.SupportedHashes.S256);
        }
        for (ZrtpConstants.SupportedHashes sho: algosOffered) {
            for (ZrtpConstants.SupportedHashes shc: algosConf) {
                if(sho == shc) {
                    return shc;
                }
            }
        }
        return ZrtpConstants.SupportedHashes.S256;
    }

    public final ZrtpConstants.SupportedSymCiphers findBestCipher(ZrtpConfigure config, ZrtpConstants.SupportedPubKeys pk) {
        if (nCipher == 0 || pk == ZrtpConstants.SupportedPubKeys.DH2K)
            return ZrtpConstants.SupportedSymCiphers.AES1;

        boolean mandatoryFound = false;
        
        int numAlgosOffered = nCipher;
        ArrayList<ZrtpConstants.SupportedSymCiphers> algosOffered = 
            new ArrayList<ZrtpConstants.SupportedSymCiphers>(numAlgosOffered+1);

        int numAlgosConf = config.getNumConfiguredSymCiphers();
        ArrayList<ZrtpConstants.SupportedSymCiphers> algosConf = 
            new ArrayList<ZrtpConstants.SupportedSymCiphers>(numAlgosConf+1);

        // Build a list of configured ciphers, appending a mandatory algo if 
        // necessary
        for (ZrtpConstants.SupportedSymCiphers sh: config.symCiphers()) {
            if (sh == ZrtpConstants.SupportedSymCiphers.AES1) {
                mandatoryFound = true;
            }
            algosConf.add(sh);
        }
        if (!mandatoryFound) {
            algosConf.add(ZrtpConstants.SupportedSymCiphers.AES1);
        }

        // Build a list of offered ciphers, appending a mandatory algo if 
        // necessary
        mandatoryFound = false;
        for (int ii = 0; ii < nCipher; ii++) {
            int o = oCipher + (ii * ZRTP_WORD_SIZE);
            for (ZrtpConstants.SupportedSymCiphers sh : ZrtpConstants.SupportedSymCiphers
                    .values()) {
                byte[] s = sh.name;
                if (s[0] == packetBuffer[o] && s[1] == packetBuffer[o + 1]
                        && s[2] == packetBuffer[o + 2]
                        && s[3] == packetBuffer[o + 3]) {
                    algosOffered.add(sh);
                    if (sh == ZrtpConstants.SupportedSymCiphers.AES1) {
                        mandatoryFound = true;
                    }
                }
            }
        }
        if (!mandatoryFound) {
            algosOffered.add(ZrtpConstants.SupportedSymCiphers.AES1);
        }
        
        for (ZrtpConstants.SupportedSymCiphers sho: algosOffered) {
            for (ZrtpConstants.SupportedSymCiphers shc: algosConf) {
                if(sho == shc) {
                    return shc;
                }
            }
        }
        return ZrtpConstants.SupportedSymCiphers.AES1;
    }
    
    private ZrtpConstants.SupportedHashes selectedHash;
    private ZrtpConstants.SupportedSymCiphers selectedCipher;

    public ZrtpConstants.SupportedHashes getSelectedHash() {
        return selectedHash;
    }

    public ZrtpConstants.SupportedSymCiphers getSelectedCipher() {
        return selectedCipher;
    }
    
    public final ZrtpConstants.SupportedPubKeys findBestPubkey(ZrtpConfigure config) {
        if (nPubkey == 0) {
            selectedHash = ZrtpConstants.SupportedHashes.S256;
            return ZrtpConstants.SupportedPubKeys.DH3K;
        }

        // Build list of own pubkey algorithm names, must follow the order
        // defined in RFC 6189, chapter 4.1.2.
        final ZrtpConstants.SupportedPubKeys orderedAlgos[] = {
            ZrtpConstants.SupportedPubKeys.DH2K, 
            ZrtpConstants.SupportedPubKeys.EC25, 
            ZrtpConstants.SupportedPubKeys.DH3K,
            ZrtpConstants.SupportedPubKeys.EC38 };

        int numAlgosConf = config.getNumConfiguredPubKeys();
        ArrayList<ZrtpConstants.SupportedPubKeys> algosPeerIntersect = 
                        new ArrayList<ZrtpConstants.SupportedPubKeys>(numAlgosConf+1);

        ArrayList<ZrtpConstants.SupportedPubKeys> algosOwnIntersect = 
                        new ArrayList<ZrtpConstants.SupportedPubKeys>(numAlgosConf+1);

        // Build our own intersection list ordered according to our sequence
        // The list must include real public key algorithms only, so skip
        // mult-stream mode, preshared and alike.
        for (ZrtpConstants.SupportedPubKeys sh: config.publicKeyAlgos()) {
            if (sh == ZrtpConstants.SupportedPubKeys.MULT) {
                continue;
            }
            byte[] s = sh.name;
            for (int i = 0; i < nPubkey; i++) {
                int o = oPubkey + (i * ZRTP_WORD_SIZE);
                if (s[0] == packetBuffer[o] && s[1] == packetBuffer[o + 1] && s[2] == packetBuffer[o + 2] &&
                                s[3] == packetBuffer[o + 3]) {
                    algosOwnIntersect.add(sh);
                }
            }
        }

        // Build list of intersectiong algos in peer's order. As input use own intersection list, just
        // order the algorithms as sent by peer.
        for (int i = 0; i < nPubkey; i++) {
            int o = oPubkey + (i * ZRTP_WORD_SIZE);
            for (ZrtpConstants.SupportedPubKeys sh : algosOwnIntersect) {
                byte[] s = sh.name;
                if (s[0] == packetBuffer[o] && s[1] == packetBuffer[o + 1] && s[2] == packetBuffer[o + 2] &&
                                s[3] == packetBuffer[o + 3]) {
                    algosPeerIntersect.add(sh);
                    break;
                }
            }
        }
        if (algosPeerIntersect.size() == 0) {   // If we don't find a common algorithm use the mandatory algorithms
            selectedHash = ZrtpConstants.SupportedHashes.S256;
            return ZrtpConstants.SupportedPubKeys.DH3K;
        }
        
        ZrtpConstants.SupportedPubKeys useAlgo;
        if (algosPeerIntersect.size() > 1 && algosPeerIntersect.get(0) != algosOwnIntersect.get(0)) {
            
            // Get own and peer's algorithm which are first on the repective lists
            ZrtpConstants.SupportedPubKeys ownTopAlgo = algosOwnIntersect.get(0);
            ZrtpConstants.SupportedPubKeys peerTopAlgo = algosPeerIntersect.get(0);

            int own = 0, peer = 0;
            
            // Now check which algorithm is first on the list of ordered algorithms, lookup own first
            for (ZrtpConstants.SupportedPubKeys sh : orderedAlgos) {
                if (sh == ownTopAlgo)
                    break;
                own++;
            }
            for (ZrtpConstants.SupportedPubKeys sh : orderedAlgos) {
                if (sh == peerTopAlgo)
                    break;
                peer++;
            }
            if (own < peer)             // our algorithm is faster
                useAlgo = algosOwnIntersect.get(0);
            else
                useAlgo = algosPeerIntersect.get(0);
        }
        else {
            useAlgo = algosPeerIntersect.get(0);
        }
        
        // select a corresponding strong hash if necessary.
        if (useAlgo == ZrtpConstants.SupportedPubKeys.EC38) {
            selectedHash = getStrongHashOffered();
            selectedCipher = getStrongCipherOffered();
        }
        else {
            selectedHash = findBestHash(config);
        }
        return useAlgo;        
    }

    private final ZrtpConstants.SupportedHashes getStrongHashOffered() {
        byte[] s = ZrtpConstants.SupportedHashes.S384.name;
        for (int i = 0; i < nHash; i++) {
            int o = oHash + (i * ZRTP_WORD_SIZE);
            if (s[0] == packetBuffer[o] && s[1] == packetBuffer[o + 1] && s[2] == packetBuffer[o + 2] &&
                            s[3] == packetBuffer[o + 3]) {
                return ZrtpConstants.SupportedHashes.S384;                    
            }
        }
        return null;
    }

    private final ZrtpConstants.SupportedSymCiphers getStrongCipherOffered() {

        byte[] aes3 = ZrtpConstants.SupportedSymCiphers.AES3.name;
        byte[] two3 = ZrtpConstants.SupportedSymCiphers.TWO3.name;

        for (int i = 0; i < nCipher; i++) {
            int o = oCipher + (i * ZRTP_WORD_SIZE);
            if (aes3[0] == packetBuffer[o] && aes3[1] == packetBuffer[o + 1] && aes3[2] == packetBuffer[o + 2] &&
                            aes3[3] == packetBuffer[o + 3]) {
                return ZrtpConstants.SupportedSymCiphers.AES3;
            }
            if (two3[0] == packetBuffer[o] && two3[1] == packetBuffer[o + 1] && two3[2] == packetBuffer[o + 2] &&
                            two3[3] == packetBuffer[o + 3]) {
                return ZrtpConstants.SupportedSymCiphers.TWO3;
            }
        }
        return null;
    }

    public final ZrtpConstants.SupportedSASTypes findBestSASType(ZrtpConfigure config) {
        if (nSas == 0)
            return ZrtpConstants.SupportedSASTypes.B32;
        
        boolean mandatoryFound = false;
        
        int numAlgosOffered = nSas;
        ArrayList<ZrtpConstants.SupportedSASTypes> algosOffered = 
            new ArrayList<ZrtpConstants.SupportedSASTypes>(numAlgosOffered+1);

        int numAlgosConf = config.getNumConfiguredSasTypes();
        ArrayList<ZrtpConstants.SupportedSASTypes> algosConf = 
            new ArrayList<ZrtpConstants.SupportedSASTypes>(numAlgosConf+1);

        // Build a list of configured hashes, appending a mandatory algo if 
        // necessary
        for (ZrtpConstants.SupportedSASTypes sh: config.sasTypes()) {
            if (sh == ZrtpConstants.SupportedSASTypes.B32) {
                mandatoryFound = true;
            }
            algosConf.add(sh);
        }
        if (!mandatoryFound) {
            algosConf.add(ZrtpConstants.SupportedSASTypes.B32);
        }

        // Build a list of offered hashes, appending a mandatory algo if 
        // necessary
        mandatoryFound = false;
        for (int ii = 0; ii < nSas; ii++) {
            int o = oSas + (ii * ZRTP_WORD_SIZE);
            for (ZrtpConstants.SupportedSASTypes sh : ZrtpConstants.SupportedSASTypes
                    .values()) {
                byte[] s = sh.name;
                if (s[0] == packetBuffer[o] && s[1] == packetBuffer[o + 1]
                        && s[2] == packetBuffer[o + 2]
                        && s[3] == packetBuffer[o + 3]) {
                    algosOffered.add(sh);
                    if (sh == ZrtpConstants.SupportedSASTypes.B32) {
                        mandatoryFound = true;
                    }
                }
            }
        }
        if (!mandatoryFound) {
            algosOffered.add(ZrtpConstants.SupportedSASTypes.B32);
        }
        for (ZrtpConstants.SupportedSASTypes sho: algosOffered) {
            for (ZrtpConstants.SupportedSASTypes shc: algosConf) {
                if(sho == shc) {
                    return shc;
                }
            }
        }        
        return ZrtpConstants.SupportedSASTypes.B32;
    }

    public final ZrtpConstants.SupportedAuthLengths findBestAuthLen(ZrtpConfigure config) {
        if (nAuth == 0)
            return ZrtpConstants.SupportedAuthLengths.HS32;

        boolean mandatoryFound_1 = false;
        boolean mandatoryFound_2 = false;
        
        int numAlgosOffered = nAuth;
        ArrayList<ZrtpConstants.SupportedAuthLengths> algosOffered = 
            new ArrayList<ZrtpConstants.SupportedAuthLengths>(numAlgosOffered+1);

        int numAlgosConf = config.getNumConfiguredAuthLengths();
        ArrayList<ZrtpConstants.SupportedAuthLengths> algosConf = 
            new ArrayList<ZrtpConstants.SupportedAuthLengths>(numAlgosConf+1);

        // Build a list of configured hashes, appending a mandatory algo if 
        // necessary
        for (ZrtpConstants.SupportedAuthLengths sh: config.authLengths()) {
            if (sh == ZrtpConstants.SupportedAuthLengths.HS32) {
                mandatoryFound_1 = true;
            }
            if (sh == ZrtpConstants.SupportedAuthLengths.HS80) {
                mandatoryFound_2 = true;
            }
            algosConf.add(sh);
        }
        if (!mandatoryFound_1) {
            algosConf.add(ZrtpConstants.SupportedAuthLengths.HS32);
        }

        if (!mandatoryFound_2) {
            algosConf.add(ZrtpConstants.SupportedAuthLengths.HS80);
        }
        // Build a list of offered hashes, appending a mandatory algo if 
        // necessary
        mandatoryFound_1 = mandatoryFound_2 = false;
        for (int ii = 0; ii < nAuth; ii++) {
            int o = oAuth + (ii * ZRTP_WORD_SIZE);
            for (ZrtpConstants.SupportedAuthLengths sh : ZrtpConstants.SupportedAuthLengths
                    .values()) {
                byte[] s = sh.name;
                if (s[0] == packetBuffer[o] && s[1] == packetBuffer[o + 1]
                        && s[2] == packetBuffer[o + 2]
                        && s[3] == packetBuffer[o + 3]) {
                    algosOffered.add(sh);
                    if (sh == ZrtpConstants.SupportedAuthLengths.HS32) {
                        mandatoryFound_1 = true;
                    }
                    if (sh == ZrtpConstants.SupportedAuthLengths.HS80) {
                        mandatoryFound_2 = true;
                    }
                }
            }
        }
        if (!mandatoryFound_1) {
            algosOffered.add(ZrtpConstants.SupportedAuthLengths.HS32);
        }
        if (!mandatoryFound_2) {
            algosOffered.add(ZrtpConstants.SupportedAuthLengths.HS80);
        }
        for (ZrtpConstants.SupportedAuthLengths sho: algosOffered) {
            for (ZrtpConstants.SupportedAuthLengths shc: algosConf) {
                if(sho == shc) {
                    return shc;
                }
            }
        }        
        return ZrtpConstants.SupportedAuthLengths.HS32;
    }

    public final boolean checkMultiStream() {
        // Multi Stream mode is mandatory, thus if nothing is offered then it is
        // supported :-)
        if (nPubkey == 0)
            return true;

        byte[] s = ZrtpConstants.SupportedPubKeys.MULT.name;
        // Loop over offer pub key data
        for (int ii = 0; ii < nPubkey; ii++) {
            int o = oPubkey + (ii * ZRTP_WORD_SIZE);
            if (s[0] == packetBuffer[o] && s[1] == packetBuffer[o + 1]
                    && s[2] == packetBuffer[o + 2]
                    && s[3] == packetBuffer[o + 3]) {
                return true;
            }
        }
        return false;
    }
    
    public final int getNAuth() {
        return nAuth;
    }

    public final int getNCipher() {
        return nCipher;
    }

    public final int getNHash() {
        return nHash;
    }

    public final int getNPubkey() {
        return nPubkey;
    }

    public final int getNSas() {
        return nSas;
    }

/* ***
    public static void main(String[] args) {
        ZrtpPacketHello pkt = new ZrtpPacketHello();
        ZrtpConfigure config = new ZrtpConfigure();
        config.setStandardConfig();
//        config.addPubKeyAlgo(ZrtpConstants.SupportedPubKeys.DH2K);
//        config.addHashAlgo(ZrtpConstants.SupportedHashes.S384);
//        config.addHashAlgo(ZrtpConstants.SupportedHashes.S256);
        
        pkt.configureHello(config);
        
        System.err.println("Hello length: " + pkt.getLength());
        
        System.err.println("packetBuffer length in bytes: " + pkt.getHeaderBase().length);

        byte[] data= {1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,27,28,29,30,31,32};
        pkt.setZid(data);

        ZrtpUtils.hexdump("Hello packet", pkt.getHeaderBase(), pkt.getHeaderBase().length);
        ZrtpConfigure config_1 = new ZrtpConfigure();
        config_1.setStandardConfig();
//        config_1.addHashAlgo(ZrtpConstants.SupportedHashes.S384);
        System.err.println("best hash: " + pkt.findBestHash(config_1));
        System.err.println("best pubkey: " + pkt.findBestPubkey(config_1));
        System.err.println("best cipher: " + pkt.findBestCipher(config_1, ZrtpConstants.SupportedPubKeys.DH3K));
    }
*** */
}

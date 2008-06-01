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

package gnu.java.zrtp.zidfile;

import gnu.java.zrtp.utils.ZrtpUtils;

import java.util.Arrays;


/**
 * This class implements the ZID record.
 *
 * The ZID record holds data about a peer. According to ZRTP specification
 * we use a ZID to identify a peer. ZRTP uses the RS (Retained Secret) data
 * to construct shared secrets.
 * <p/>
 * NOTE: ZIDRecord has ZIDFile as friend. ZIDFile knows about the private
 *   data of ZIDRecord - please keep both classes synchronized.
 * 
 * @author Werner Dittmann <Werner.Dittmann@t-online.de>
 *
 */
public class ZidRecord {

    public static final int IDENTIFIER_LENGTH = 12;
    public static final int RS_LENGTH = 32;

    private static final int VERSION = 2;
    private static final int TIME_LENGTH = 8;
    /*
     * Offsets of the ZID record fields (byte offsets) in packet buffer     // length in bytes
     */
    private static final int VERSION_OFFSET = 0;                            // [1]
    private static final int FLAGS_OFFSET = VERSION_OFFSET + 1;             // [1]
    private static final int FILLER_OFFSET = FLAGS_OFFSET + 1;              // [2]
    private static final int IDENTIFIER_OFFSET = FILLER_OFFSET + 2;         // [12]
    private static final int RS1INTERVAL_OFFSET = IDENTIFIER_OFFSET + 12;   // [8]
    private static final int RS1DATA_OFFSET = RS1INTERVAL_OFFSET + 8;       // [32]
    private static final int RS2INTERVAL_OFFSET = RS1DATA_OFFSET + 32;      // [8]
    private static final int RS2DATA_OFFSET = RS2INTERVAL_OFFSET + 8;       // [32]
    private static final int MITMKEY_OFFSET = RS2DATA_OFFSET + 32;          // [32]
    
    /*
     * Bit masks for the flag byte.
     */    
    private static final int Valid            = 0x1;
    private static final int SASVerified      = 0x2;
    private static final int RS1Valid         = 0x4;
    private static final int RS2Valid         = 0x8;
    private static final int MITMKeyAvailable = 0x10;
    private static final int OwnZIDRecord     = 0x20;

    /*
     * The length of the ZID record is the summ of all length shown above
     */
    private static final int ZID_RECORD_LENGTH = 128;

    /*
     * The ZID record buffer
     */
    private byte[] buffer;
    
    /*
     * Record position in ZID file (in bytes)
     */
    private long position;
    
    public ZidRecord(byte[] zidData) {
        buffer = new byte[ZID_RECORD_LENGTH];
        Arrays.fill(buffer, (byte)0);
        buffer[VERSION_OFFSET] = VERSION;
        if (zidData != null) {
            System.arraycopy(zidData, 0, buffer, IDENTIFIER_OFFSET, IDENTIFIER_LENGTH);
        }
    }

    protected boolean isValid() {
        return ((buffer[FLAGS_OFFSET] & Valid) == Valid);
    }

    protected void setValid() {
        buffer[FLAGS_OFFSET] |= Valid;
    }

    protected byte[] getBuffer() {
        return buffer;
    }
    public void setRs1Valid()   { 
        buffer[FLAGS_OFFSET] |= RS1Valid; 
    }
    
    public void resetRs1Valid() {
        buffer[FLAGS_OFFSET] &= ~RS1Valid;
    }

    public boolean isRs1Valid() {
        return ((buffer[FLAGS_OFFSET] & RS1Valid) == RS1Valid);
    }

    public void setRs2Valid() {
        buffer[FLAGS_OFFSET] |= RS2Valid;
    }

    public void resetRs2Valid() {
        buffer[FLAGS_OFFSET] &= ~RS2Valid;
    }

    public boolean isRs2Valid() {
        return ((buffer[FLAGS_OFFSET] & RS2Valid) == RS2Valid);
    }

    public void setMITMKeyAvailable() {
        buffer[FLAGS_OFFSET] |= MITMKeyAvailable;
    }

    public void resetMITMKeyAvailable() {
        buffer[FLAGS_OFFSET] &= ~MITMKeyAvailable;
    }

    public boolean isMITMKeyAvailable() {
        return ((buffer[FLAGS_OFFSET] & MITMKeyAvailable) == MITMKeyAvailable);
    }

    public void setOwnZIDRecord() {
        buffer[FLAGS_OFFSET] = OwnZIDRecord;
    }

    public void resetOwnZIDRecord() {
        buffer[FLAGS_OFFSET] = 0;
    }

    public boolean isOwnZIDRecord() {
        return (buffer[FLAGS_OFFSET] == OwnZIDRecord);      // no other flag allowed if own ZID
    }

    public void setSasVerified() {
        buffer[FLAGS_OFFSET] |= SASVerified;
    }

    public void resetSasVerified() {
        buffer[FLAGS_OFFSET] &= ~SASVerified;
    }

    public boolean isSasVerified() {
        return ((buffer[FLAGS_OFFSET] & SASVerified) == SASVerified);
    }

    /**
     * Retrieve identifier from buffer into a byte array.
     * @param data byte array that receives the identifier.
     */
    public void getIdentifierInto(byte[] data) {
        System.arraycopy(buffer, IDENTIFIER_OFFSET, data, 0, IDENTIFIER_LENGTH);        
    }
    
    /**
     * Get identifier.
     * 
     */
    public byte[] getIdentifier() {
        return ZrtpUtils.readRegion(buffer, IDENTIFIER_OFFSET, IDENTIFIER_LENGTH);        
    }

    /**
     * Get RS1.
     * 
     */
    public byte[] getRs1() {
        return ZrtpUtils.readRegion(buffer, RS1DATA_OFFSET, RS_LENGTH);        
    }

    /**
     * Get RS2.
     * 
     */
    public byte[] getRs2() {
        return ZrtpUtils.readRegion(buffer, RS2DATA_OFFSET, RS_LENGTH);        
    }
    /**
     * Compare an identifier with identifier in this record.
     * 
     * @param data byte array that containing the identifier to compare with
     */
    public boolean isSameIdentifier(byte[] data) {
        for (int i = 0; i < IDENTIFIER_LENGTH; i++) {
            if (buffer[IDENTIFIER_OFFSET+i] != data[i])
                return false;
        }
        return true;
    }

    /**
     * Compare RS1 with RS1 in this record.
     * 
     * @param data byte array that containing the identifier to compare with
     */
    public boolean isSameRs1(byte[] data) {
        for (int i = 0; i < RS_LENGTH; i++) {
            if (buffer[RS1DATA_OFFSET+i] != data[i])
                return false;
        }
        return true;
    }

    /**
     * Compare RS2 with RS2 in this record.
     * 
     * @param data byte array that containing the identifier to compare with
     */
    public boolean isSameRs2(byte[] data) {
        for (int i = 0; i < RS_LENGTH; i++) {
            if (buffer[RS2DATA_OFFSET+i] != data[i])
                return false;
        }
        return true;
    }
    
    /**
     * Sets new RS1 data and associated expiration value.
     *
     * If the expiration value is >0 or -1 the method stores the new
     * RS1. Before it stores the new RS1 it shifts the exiting RS1
     * into RS2 (together with its expiration time). Then it computes
     * the expiration time of the and stores the result together with
     * the new RS1.
     *
     * If the expiration value is -1 then this RS will never expire. 
     * 
     * If the expiration value is 0 then the expiration value of a
     * stored RS1 is cleared and no new RS1 value is stored. Also RS2
     * is left unchanged.
     *
     * @param data
     *    Points to the new RS1 data.
     * @param expire
     *    The expiration interval in seconds. Default is -1.
     *
     */
    public void setNewRs1(byte[] data, int expire) {

        long validThru = 0;
        if (expire == -1) {
            validThru = -1;
        } else if (expire <= 0) {
            validThru = 0;
        } else {
            validThru = (System.currentTimeMillis() / 1000) + expire;
        }
        
        if (validThru != 0) {
            // shift old RS1 data into RS2 position
            System.arraycopy(buffer, RS1DATA_OFFSET, buffer, RS2DATA_OFFSET,
                    RS_LENGTH);
            System.arraycopy(buffer, RS1INTERVAL_OFFSET, buffer,
                    RS2INTERVAL_OFFSET, TIME_LENGTH);

            // now propagate flags as well
            if (isRs1Valid()) {
                setRs2Valid();
            }
            // set new RS1 data
            System.arraycopy(data, 0, buffer, RS1DATA_OFFSET, RS_LENGTH);
            setRs1Valid();
        }
        /*
         * The the bytes in host order (file is invalid for systems using other
         * byte orders)
         */
        buffer[RS1INTERVAL_OFFSET] = (byte) validThru;
        buffer[RS1INTERVAL_OFFSET + 1] = (byte) (validThru >> 8);
        buffer[RS1INTERVAL_OFFSET + 2] = (byte) (validThru >> 16);
        buffer[RS1INTERVAL_OFFSET + 3] = (byte) (validThru >> 24);
        buffer[RS1INTERVAL_OFFSET + 4] = (byte) (validThru >> 32);
        buffer[RS1INTERVAL_OFFSET + 5] = (byte) (validThru >> 40);
        buffer[RS1INTERVAL_OFFSET + 6] = (byte) (validThru >> 48);
        buffer[RS1INTERVAL_OFFSET + 7] = (byte) (validThru >> 56);
    }

    /**
     * Check if RS1 is still valid
     *
     * Returns true if RS1 is still valid, false otherwise.
     *
     * @return
     *    Returns true is RS1 is not expired (valid), false otherwise. 
     */
    public boolean isRs1NotExpired() {
        long current = (System.currentTimeMillis() / 1000);
        long validThru;

        validThru = ((buffer[RS1INTERVAL_OFFSET] & 0xff)
                | ((buffer[RS1INTERVAL_OFFSET + 1] & 0xff) << 8)
                | ((buffer[RS1INTERVAL_OFFSET + 2] & 0xff) << 16)
                | ((buffer[RS1INTERVAL_OFFSET + 3] & 0xff) << 24)
                | ((buffer[RS1INTERVAL_OFFSET + 4] & 0xff) << 32)
                | ((buffer[RS1INTERVAL_OFFSET + 5] & 0xff) << 40)
                | ((buffer[RS1INTERVAL_OFFSET + 6] & 0xff) << 48) | ((buffer[RS1INTERVAL_OFFSET + 7] & 0xff) << 56));

        if (validThru == -1)
            return true;
        if (validThru == 0)
            return false;
        return (current <= validThru) ? true : false;
    }

    /**
     * Check if RS2 is still valid
     *
     * Returns true if RS2 is still valid, false otherwise.
     *
     * @return
     *    Returns true is RS2 is not expired (valid), false otherwise. 
     */
    public boolean isRs2NotExpired() {
        long current = (System.currentTimeMillis() / 1000);
        long validThru;

        validThru = ((buffer[RS2INTERVAL_OFFSET] & 0xff)
                | ((buffer[RS2INTERVAL_OFFSET + 1] & 0xff) << 8)
                | ((buffer[RS2INTERVAL_OFFSET + 2] & 0xff) << 16)
                | ((buffer[RS2INTERVAL_OFFSET + 3] & 0xff) << 24)
                | ((buffer[RS2INTERVAL_OFFSET + 4] & 0xff) << 32)
                | ((buffer[RS2INTERVAL_OFFSET + 5] & 0xff) << 40)
                | ((buffer[RS2INTERVAL_OFFSET + 6] & 0xff) << 48) | ((buffer[RS2INTERVAL_OFFSET + 7] & 0xff) << 56));

        if (validThru == -1)
            return true;
        if (validThru == 0)
            return false;
        return (current <= validThru) ? true : false;
    }
    /**
     * @return the position
     */
    public long getPosition() {
        return position;
    }

    /**
     * @param position the position to set
     */
    public void setPosition(long position) {
        this.position = position;
    }

    void setMiTMData(byte[] data) {
        System.arraycopy(data, 0, buffer, MITMKEY_OFFSET, RS_LENGTH);
        setMITMKeyAvailable();
    }

    public static void main(String argv[]) {
        byte[] data = {1,2,3,4,5,6,7,8,9,10,11,12};
        byte[] dataLong = {1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,27,28,29,30,31,32};
        
        ZidRecord rec = new ZidRecord(data);
        rec.setNewRs1(dataLong, 10);
        rec.setMiTMData(dataLong);
        System.err.println("is rs 1 valid: " + rec.isRs1NotExpired());
        dataLong[0] += 1;
        rec.setNewRs1(dataLong, 16);
        System.err.println("is rs 2 valid: " + rec.isRs2NotExpired());
        ZrtpUtils.hexdump("ZID record", rec.getBuffer(), rec.getBuffer().length);
    }
}

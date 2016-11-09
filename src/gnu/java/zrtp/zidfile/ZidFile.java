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


import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.EOFException;
import java.io.RandomAccessFile;
import java.io.File;

import java.util.Random;


/**
 * @author Werner Dittmann <Werner.Dittmann@t-online.de>
 *
 */

public class ZidFile {
    
    /*
     * Copied from ZidRecord, keep in synch
     */
    private static final int IDENTIFIER_LENGTH = 12;
    private static final int ZID_RECORD_LENGTH = 128;

    /*
     * The ZID file instance (singleton)
     */
    private static ZidFile instance = null;

    private RandomAccessFile zidFile;
    private byte[] associatedZid = null;
    
    private ZidFile() {
        associatedZid = new byte[IDENTIFIER_LENGTH];
    }
    
    /**
     * Get the an instance of ZIDFile.
     *
     * This method just creates an instance an store a pointer to it
     * in a static variable. The ZIDFile is a singleton, thus only
     * <em>one</em> ZID file can be open at one time.
     *
     * @return
     *    A pointer to the global ZIDFile singleton instance.
     */
    public synchronized static ZidFile getInstance() {
        if (instance == null) {
            instance = new ZidFile();
        }
        return instance;
    }
    
    private void createZIDFile(String name) {
        try {
            zidFile = new RandomAccessFile(name, "rw");
        } catch (FileNotFoundException e) {
            zidFile = null;
            return;
        }
        // New file, generate an associated random ZID and save
        // it as first record
        if (zidFile != null) {
            Random ran = new Random();
            ran.nextBytes(associatedZid);
            ZidRecord rec = new ZidRecord();
            rec.setIdentifier(associatedZid);
            rec.setOwnZIDRecord();
            try {
                zidFile.seek(0L);
                zidFile.write(rec.getBuffer());
            } catch (IOException e) {
                try {
                    zidFile.close();
                } catch (IOException e1) {
                    zidFile = null;
                    return;
                }
                zidFile = null;
                return;
            }
        }
    }
    
    
    /**
     * Open the named ZID file and return a ZID file class.
     * 
     * This static function either opens an existing ZID file or creates a new
     * ZID file with the given name. The ZIDFile is a singleton, thus only
     * <em>one</em> ZID file can be open at one time.
     * 
     * To open another ZID file you must close the active ZID file first.
     * 
     * @param name
     *            The name of the ZID file to open or create
     * @return 1 if file could be opened/created, 0 if the ZID instance already
     *         has an open file, -1 if open/creation of file failed.
     */
    public synchronized int open(String name) {

        // check for an already active ZID file
        if (zidFile != null) {
            return 0;
        }
        File f = new File(name);
        if (f.exists()) {
            try {
                zidFile = new RandomAccessFile(f, "rw");
            } catch (FileNotFoundException e) {
                zidFile = null;
                return -1;
            }
        }
        else {
            createZIDFile(name);
        }

        if (zidFile != null) {
            ZidRecord rec = new ZidRecord();

            try {
                zidFile.seek(0L);
                zidFile.readFully(rec.getBuffer());
            } catch (IOException e) {
                try {
                    zidFile.close();
                } catch (IOException e1) {
                    zidFile = null;
                    return -1;
                }
                zidFile = null;
                return -1;
            }
            
            if (!rec.isOwnZIDRecord()) {
                try {
                    zidFile.close();
                } catch (IOException e) {
                    zidFile = null;
                    return -1;
                }
                zidFile = null;
                return -1;
            }
            rec.getIdentifierInto(associatedZid);
        }
        return ((zidFile == null) ? -1 : 1);
    }

    /**
     * Check if ZIDFile has an active (open) file.
     *
     * @return
     *    True if ZIDFile has an active file, false otherwise
     */
    public synchronized boolean isOpen() { 
        return (zidFile != null); 
    }

     /**
         * Close the ZID file. Closes the ZID file, and prepares to open a new
         * ZID file.
         */
    public synchronized void close() {
        if (zidFile != null) {
            try {
                zidFile.close();
            } catch (IOException e1) {
                zidFile = null;
                return;
            }
            zidFile = null;
        }
    }

    /**
     * Get a ZID record from the active ZID file.
     * 
     * The method get the identifier data from the ZID record parameter, locates
     * the record in the ZID file and fills in the RS1, RS2, and other data.
     * 
     * If no matching record exists in the ZID file the method creates it and
     * fills it with default values.
     * 
     * @param zid
     *            contains the identifier data. The method
     *            returns the record.
     * @return The existing or created ZID record or null in case of I/O
     *         problems.
     */
    public synchronized ZidRecord getRecord(byte[] zid) {
        long pos = 0L;
        ZidRecord rec = new ZidRecord();
        boolean numRead = false;

        // set read pointer behind first record, then read record
        // the very first record is the "own" zid record.
        try {
            zidFile.seek(ZID_RECORD_LENGTH);
        } catch (IOException e2) {
            return null;
        }
        do {
            try {
                pos = zidFile.getFilePointer();
                zidFile.readFully(rec.getBuffer());
                numRead = true;
            } catch (EOFException e) {
                numRead = false;
            } catch (IOException e) {
                try {
                    zidFile.close();
                } catch (IOException e1) {
                    zidFile = null;
                    return null;
                }
            }
            if (!numRead) {
                break;
            }

            // skip own ZID record and invalid records
            if (rec.isOwnZIDRecord() || !rec.isValid()) {
                continue;
            }

        } while (numRead && !rec.isSameIdentifier(zid));

        // If we reached end of file, then no record with matching ZID
        // found. We need to create a new ZID record.
        if (!numRead) {
            rec = new ZidRecord();
            rec.setIdentifier(zid);
            rec.setValid();
            try {
                pos = zidFile.getFilePointer();
                zidFile.write(rec.getBuffer());
            } catch (IOException e) {
                return null;
            }
        }
        // remember position of record in file for save operation
        rec.setPosition(pos);
        return rec;
    }

    /**
     * Save a ZID record into the active ZID file.
     *
     * This method saves the content of a ZID record into the ZID file. Before
     * you can save the ZID record you must have performed a getRecord()
     * first.
     *
     * @param zidRecord
     *    The ZID record to save.
     * @return
     *    1 on success
     */
    public synchronized int saveRecord(ZidRecord zidRecord) {
        try {
            zidFile.seek(zidRecord.getPosition());
            zidFile.write(zidRecord.getBuffer());
        } catch (IOException e) {
            return -1;
        }
        // fflush(zidFile);
        return 1;
    }

    /**
     * Get the ZID associated with this ZID file.
     *
     * @return
     *    Pointer to the ZID
     */
    public synchronized byte[] getZid() { 
        return associatedZid;
    }

//    public static void main(String argv[]) {
//
//        byte[] myId = new byte[IDENTIFIER_LENGTH];
//
//        File f = new File("/tmp/tst.zid");
//        f.delete();
//
//        ZidFile zid = ZidFile.getInstance();
//        zid.open("/tmp/tst.zid");
//        ZrtpUtils.hexdump("My ZID: ", zid.getZid(), IDENTIFIER_LENGTH);
//        System.arraycopy(zid.getZid(), 0, myId, 0, IDENTIFIER_LENGTH);
//        zid.close();
//
//        zid.open("/tmp/tst.zid");
//        if (!Arrays.equals(zid.getZid(), myId)) {
//            System.err.println("Ids do not match, wrong own ZID in testfile");
//        }
//        ZrtpUtils.hexdump("My ZID 1: ", zid.getZid(), IDENTIFIER_LENGTH);
//
//        // Create a new ZID record for peer ZID "123456789012"
//        byte[] peer1 = "123456789012".getBytes();
//        ZidRecord zr3 = new ZidRecord(peer1);
//
//        zid.getRecord(zr3);
//        if (!zr3.isValid()) {
//            System.err
//                    .println("New ZID record '123456789012' not set to valid");
//            System.exit(1);
//        }
//        zid.saveRecord(zr3);
//
//        // Create a new ZID record for peer ZID "210987654321"
//        byte[] peer2 = "210987654321".getBytes();
//        ZidRecord zr4 = new ZidRecord(peer2);
//
//        zid.getRecord(zr4);
//        if (!zr4.isValid()) {
//            System.err
//                    .println("New ZID record '210987654321' not set to valid");
//            System.exit(1);
//        }
//        zid.saveRecord(zr4);
//
//        // now set a first RS1 with default expiration interval, check
//        // if set correctly, valid flag and expiration interval
//        byte[] rs1 = "11122233344455566677788899900012".getBytes();
//        zr3.setNewRs1(rs1, -1);
//        if (!zr3.isSameRs1(rs1)) {
//            System.err.println("RS1 was not set (111...012)");
//            System.exit(1);
//        }
//        if (!zr3.isRs1Valid()) {
//            System.err.println("RS1 was not set to valid state (111...012)");
//            System.exit(1);
//        }
//        if (!zr3.isRs1NotExpired()) {
//            System.err.println("RS1 expired (111...012)");
//            System.exit(1);
//        }
//        if (zr3.isRs2Valid()) {
//            System.err.println("RS2 was set to valid state (111...012)");
//            System.exit(1);
//        }
//        zid.saveRecord(zr3);
//
//        byte[] rs2 = "00099988877766655544433322211121".getBytes();
//        zr3.setNewRs1(rs2, -1);
//        if (!zr3.isSameRs1(rs2)) {
//            System.err.println("RS1 was not set (000...121)");
//            System.exit(1);
//        }
//        if (!zr3.isRs1Valid()) {
//            System.err.println("RS1 was not set to valid state (000...121)");
//            System.exit(1);
//        }
//        if (!zr3.isRs1NotExpired()) {
//            System.err.println("RS1 expired (000...121)");
//            System.exit(1);
//        }
//        if (!zr3.isSameRs2(rs1)) {
//            System.err.println("RS2 was not set (111...012)");
//            System.exit(1);
//        }
//        if (!zr3.isRs2Valid()) {
//            System.err.println("RS2 was not set to valid state (111...121)");
//            System.exit(1);
//        }
//        if (!zr3.isRs2NotExpired()) {
//            System.err.println("RS2 expired (111...121)");
//            System.exit(1);
//        }
//        zid.saveRecord(zr3);
//
//        zid.close();
//
//        // Reopen, check if first record is still valid, RSx vaild and
//        // not expired. Then manipulate 2nd record.
//        zid.open("/tmp/tst.zid");
//        ZidRecord zr3a = new ZidRecord(peer1);
//        zid.getRecord(zr3a);
//        if (!zr3a.isSameRs1(rs2)) {
//            System.err.println("Re-read RS1 was not set (000...121)");
//            System.exit(1);
//        }
//        if (!zr3a.isRs1Valid()) {
//            System.err.println("Re-read RS1 was not set to valid state (000...121)");
//            System.exit(1);
//        }
//        if (!zr3a.isRs1NotExpired()) {
//            System.err.println("Re-read RS1 expired (000...121)");
//            System.exit(1);
//        }
//        if (!zr3a.isSameRs2(rs1)) {
//            System.err.println("Re-read RS2 was not set (111...012)");
//            System.exit(1);
//        }
//        if (!zr3a.isRs2Valid()) {
//            System.err.println("Re-read RS2 was not set to valid state (111...121)");
//            System.exit(1);
//        }
//        if (!zr3a.isRs2NotExpired()) {
//            System.err.println("Re-read RS2 expired (111...121)");
//            System.exit(1);
//        }
//        
//        ZidRecord zr5 = new ZidRecord(peer2);
//        zid.getRecord(zr5);
//
//        byte[] rs3 = "aaa22233344455566677788899900012".getBytes();
//        zr5.setNewRs1(rs3, 5);
//        if (!zr5.isSameRs1(rs3)) {
//            System.err.println("RS1 (2) was not set (aaa...012)");
//            System.exit(1);
//        }
//        if (!zr5.isRs1Valid()) {
//            System.err.println("RS1 (2) was not set to valid state (aaa...012)");
//            System.exit(1);
//        }
//        if (!zr5.isRs1Valid()) {
//            System.err.println("RS1 (2) was not set to valid state (aaa...012)");
//            System.exit(1);
//        }
//        if (!zr5.isRs1NotExpired()) {
//            System.err.println("RS1 (2) expired (aaa...012)");
//            System.exit(1);
//        }
//        
//        try {
//            Thread.sleep(6000);
//        } catch (InterruptedException e) {
//            // TODO Auto-generated catch block
//            e.printStackTrace();
//        }
//        if (zr5.isRs1NotExpired()) {
//            System.err.println("RS1 (2) is not expired after defined interval (aaa...012)");
//            System.exit(1);
//        }
//        
//        byte[] rs4 = "bbb99988877766655544433322211121".getBytes();
//        zr5.setNewRs1(rs4, 256);
//        zid.saveRecord(zr5);
//        zid.close();
//        System.err.println("All done");
//    }
}

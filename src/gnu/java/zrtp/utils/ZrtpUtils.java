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

package gnu.java.zrtp.utils;

/**
 * Some helpful functions, all public static
 * 
 * @author Werner Dittmann <Werner.Dittmann@t-online.de>
 * 
 *
 */
public class ZrtpUtils {

    /**
     * Convert a 32 bit integer into a byte array, network order.
     * 
     * @param data the 32 bit integer to send over the network
     * @return the byte array conating the converted integer
     */
    public static byte[] int32ToArray(int data) {
        byte[] output = new byte[4];
        output[0]  = (byte) (data >> 24);
        output[1]  = (byte) (data >> 16);
        output[2] = (byte) (data >> 8);
        output[3] = (byte) data;
        return output;
    }

    /**
     * Convert a 32 bit integer into a byte array, network order.
     * 
     * This method places the converted four bytes into the buffer starting
     * at the given offset.
     * 
     * @param data the 32 bit integer to send over the network
     * @param buffer the byte array that receives the converted integer
     * @param offset the offset into the buffer
     */
    public static void int32ToArrayInPlace(int data, byte[] buffer, int offset) {
        buffer[offset]  = (byte) (data >> 24);
        buffer[offset+1]  = (byte) (data >> 16);
        buffer[offset+2] = (byte) (data >> 8);
        buffer[offset+3] = (byte) data;
    }

    /**
     * Convert a 16 bit integer into a byte array, network order.
     * 
     * @param data the 16 bit integer to send over the network
     * @return the byte array conating the converted short integer
     */
    public static byte[] short16ToArray(int data) {
        byte[] output = new byte[2];
        output[0] = (byte) (data >> 8);
        output[1] = (byte) data;
        return output;
    }

    /**
     * Convert a 16 bit integer into a byte array, network order.
     * 
     * @param data the 16 bit integer to send over the network
     */
    public static void short16ToArrayInPlace(int data, byte[] buffer, int offset) {
        buffer[offset] = (byte) (data >> 8);
        buffer[offset+1] = (byte) data;
    }
    /**
     * Extract two bytes from a buffer and convert into a short integer.
     * 
     * The method reads 2 bytes from the buffer starting at the specified
     * offset and converts it into a short integer. The buffer contains the
     * bytes in network order. 
     * 
     * @param buffer The buffer containing the bytes in network order.
     * @param offset Offset into buffer.
     */
    public static short readShort(byte[] buffer, int offset)
    {
        return (short) (((buffer[offset + 0] & 0xff) << 8) |
                         (buffer[offset + 1] & 0xff));
    }

    /**
     * Extract four bytes from a buffer and convert into an integer.
     * 
     * The method reads 4 bytes from the buffer starting at the specified
     * offset and converts it into a integer. The buffer contains the
     * bytes in network order. 
     * 
     * @param buffer The buffer containing the bytes in network order.
     * @param offset Offset into buffer.
     */
    public static int readInt(byte[] buffer, int offset)
    {
        return ((buffer[offset + 0] << 24) |
               ((buffer[offset + 1] & 0xff) << 16) |
               ((buffer[offset + 2] & 0xff) <<  8) |
                (buffer[offset + 3] & 0xff));
    }
    
    /**
     * Read a byte region from specified offset with specified length
     *
     * @param buffer the buffer to copy from
     * @param offset start offset of the region to be read 
     * @param length length of the region to be read
     * @return byte array of [offset, offset + length)
     */
    public static byte[] readRegion(byte[] buffer, int offset, int length)
    {
        if (offset < 0 || length <= 0 
            || offset + length > buffer.length)
        {
            return null;
        }

        byte[] region = new byte[length];
        
        System.arraycopy(buffer, offset, region, 0, length);
        
        return region;
    }


    private static final char[] hex = "0123456789abcdef".toCharArray();

    /**
     * Dump a buffer in hex and readable format.
     * 
     * @param title Printed at the beginning of the dump
     * @param buf   Byte buffer to dump
     * @param len   Number of bytes to dump, should be less or equal 
     *              the buffer length
     */
    public static void hexdump(String title, byte[] buf, int len) {
        byte b;
        System.err.println(title);
        for(int i = 0 ; ; i += 16) {
            for(int j=0; j < 16; ++j) {
                if (i+j >= len) {
                    System.err.print("   ");
                }
                else {
                    b = buf[i+j];
                    System.err.print(" "+ hex[(b>>>4) &0xf] + hex[b&0xf] );
                }
            }
            System.err.print("  ");
            for(int j = 0; j < 16; ++j) {
                if (i+j >= len) break;
                b = buf[i+j];
                if ( (byte)(b+1) < 32+1) {
                    System.err.print( '.' );
                }
                else {
                    System.err.print( (char)b );
                }
            }
            System.err.println();
            if (i+16 >= len) {
                break;
            }
        }
    }

    public static char[] bytesToHexString(byte[] in, int length) {
        if (length > in.length)
            return null;
        
        char[] out = new char[length * 2];

        for (int i = 0; i < length; i++) {
            byte b = in[i];
            out[i*2] = hex[(b>>>4) &0xf];
            out[i*2+1] = hex[b&0xf];
        }
        return out;
    }

    public static int byteArrayCompare(byte[] arg1, byte[] arg2, int length) {
//        if (arg1.length > length || arg2.length > length) {
//            return 0;
//        }
//        hexdump("arg1", arg1, arg1.length);
//        hexdump("arg2", arg2, arg2.length);
        for (int i = 0; i < length; i++) {
            if ((arg1[i]&0xff) == (arg2[i]&0xff))
                continue;
            return ((arg1[i]&0xff) < (arg2[i]&0xff)) ? -1 : 1;
        }
        return 0;
    }
   
    public static void main(String argv[]) {
        byte[] a = new byte[256];
        for (int i = 0; i < a.length; i++) {
            a[i] = (byte)i;
        }
        hexdump("Test", a, a.length);
        a = int32ToArray(16909060); // shall result in 01 02 03 04
        System.err.println("int: " + 0x01020304);
        hexdump("int32to", a, a.length);

        String s = new String(bytesToHexString(a, a.length));
        System.err.println("Byte to hex: " + s);
        
        byte[] b = new byte[4];
        byte[] c = new byte[4];
        
        b[0] = 2; c[0] = 2; 
        b[1] = 3; c[1] = 3;
        b[2] = 4; c[2] = 5;
        b[3] = 5; c[3] = 1;       
        System.err.println("b compare c (expected -1): " + byteArrayCompare(b, c, 4));

        b[0] = 2; c[0] = 2; 
        b[1] = 4; c[1] = 3;
        b[2] = 4; c[2] = 5;
        b[3] = 5; c[3] = 1;
        System.err.println("b compare c (expected 1): " + byteArrayCompare(b, c, 4));

        // treat bytes as unsigned
        b[0] = (byte)150; c[0] = 2; 
        b[1] = 4; c[1] = 3;
        b[2] = 4; c[2] = 5;
        b[3] = 5; c[3] = 1;
        System.err.println("b compare c (expected 1): " + byteArrayCompare(b, c, 4));

        b[0] = 2; c[0] = 2; 
        b[1] = 3; c[1] = 3;
        b[2] = 4; c[2] = 4;
        b[3] = 5; c[3] = 5;       
        System.err.println("b compare c (expected 0): " + byteArrayCompare(b, c, 4));

        b[0] = 2; c[0] = 2; 
        b[1] = 3; c[1] = 3;
        b[2] = (byte)150; c[2] = (byte)150;
        b[3] = 5; c[3] = 5;       
        System.err.println("b compare c (expected 0): " + byteArrayCompare(b, c, 4));
    }
}
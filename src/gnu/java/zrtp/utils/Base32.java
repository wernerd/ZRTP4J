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

/**
 *
 * Copyright (c) 2002 Bryce "Zooko" Wilcox-O'Hearn Permission is hereby
 * granted, free of charge, to any person obtaining a copy of this software to
 * deal in this software without restriction, including without limitation the
 * rights to use, copy, modify, merge, publish, distribute, sublicense, and/or
 * sell copies of this software, and to permit persons to whom this software
 * is furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of this software.
 *
 * THIS SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THIS SOFTWARE OR THE USE OR OTHER
 * DEALINGS IN THIS SOFTWARE.
 *
 * Converted to Java by: Werner Dittmann <Werner.Dittmann@t-online.de>
 */

package gnu.java.zrtp.utils;

/**
 * @author Werner Dittmann <Werner.Dittmann@t-online.de>
 *
 */
public class Base32 {
//                                                 1         2         3
//                                       01234567890123456789012345678901
    private static final char[] chars = "ybndrfg8ejkmcpqxot1uwisza345h769".toCharArray();

    /*
     * revchars: index into this table with the ASCII value of the char.
     * The result is the value of that quintet.
     */
    private static int[] revchars = {
        255, 255, 255, 255, 255, 255, 255, 255,
        255, 255, 255, 255, 255, 255, 255, 255,
        255, 255, 255, 255, 255, 255, 255, 255,
        255, 255, 255, 255, 255, 255, 255, 255,
        255, 255, 255, 255, 255, 255, 255, 255,
        255, 255, 255, 255, 255, 255, 255, 255,
        255,  18, 255,  25,  26,  27,  30,  29,
        7,  31, 255, 255, 255, 255, 255, 255,
        255, 255, 255, 255, 255, 255, 255, 255,
        255, 255, 255, 255, 255, 255, 255, 255,
        255, 255, 255, 255, 255, 255, 255, 255,
        255, 255, 255, 255, 255, 255, 255, 255,
        255,  24,   1,  12,   3,   8,   5,   6,
        28,   21,   9,  10, 255,  11,   2,  16,
        13,   14,   4,  22,  17,  19, 255,  20,
        15,    0,  23, 255, 255, 255, 255, 255,
        255, 255, 255, 255, 255, 255, 255, 255,
        255, 255, 255, 255, 255, 255, 255, 255,
        255, 255, 255, 255, 255, 255, 255, 255,
        255, 255, 255, 255, 255, 255, 255, 255,
        255, 255, 255, 255, 255, 255, 255, 255,
        255, 255, 255, 255, 255, 255, 255, 255,
        255, 255, 255, 255, 255, 255, 255, 255,
        255, 255, 255, 255, 255, 255, 255, 255,
        255, 255, 255, 255, 255, 255, 255, 255,
        255, 255, 255, 255, 255, 255, 255, 255,
        255, 255, 255, 255, 255, 255, 255, 255,
        255, 255, 255, 255, 255, 255, 255, 255,
        255, 255, 255, 255, 255, 255, 255, 255,
        255, 255, 255, 255, 255, 255, 255, 255,
        255, 255, 255, 255, 255, 255, 255, 255,
        255, 255, 255, 255, 255, 255, 255, 255
    };


    public static int divceil(int a, int b) {
        int c;
        if (a > 0) {
            if (b > 0) c = a + b - 1;
            else c = a;
        } else {
            if (b > 0) c = a;
            else c = a + b + 1;
        }
        return c/b;
    }

    /**
     * Encode binary data into a Base32 string.
     *
     * The method returns a string that contains the base32 encoded
     * data.
     *
     * @param os The byte array containing the binary data. The length
     * must be at least (lengthInBits + 7) / 8 .
     * @param lengthInBits Defines how may bits of the binary data shall be 
     * encoded into a base32 string. 
     * @return
     *     The string containing the base32 encoded data.
     */

    public static String binary2ascii(byte[] os, int lengthInBits) {

        /* if lengthInBits is not a multiple of 8 then this is allocating
         * space for 0, 1, or 2 extra quintets that will be truncated at the
         * end of this function if they are not needed
         */
        int len = (lengthInBits + 7) / 8;
        char[] result = new char[divceil(len*8, 5)];
        for (int i = 0; i < result.length; i++) {
            result[i] = ' ';
        }
        /* index into the result buffer, initially pointing to the
         * "one-past-the-end" quintet
         */
        int resp = result.length;

        int x = 0;   // to hold up to 32 bits worth of the input

        // Now this is a real live Duff's device, modifyed for Java usage.  You gotta love it.
        int switcher = len % 5;
        do {
            switch (switcher) {

            case 0:
                x = os[--len] & 0xff;
                result[--resp] = chars[x % 32]; /* The least sig 5 bits go into the final quintet. */
                x /= 32;    /* ... now we have 3 bits worth in x... */
            case 4:
                x |= (os[--len]&0xff) << 3; /* ... now we have 11 bits worth in x... */
                result[--resp] = chars[x % 32];
                x /= 32; /* ... now we have 6 bits worth in x... */
                result[--resp] = chars[x % 32];
                x /= 32; /* ... now we have 1 bits worth in x... */
            case 3:
                x |= (os[--len] & 0xff) << 1; /* The 8 bits from the 2-indexed octet.
                                So now we have 9 bits worth in x... */
                result[--resp] = chars[x % 32];
                x /= 32; /* ... now we have 4 bits worth in x... */
            case 2:
                x |= (os[--len] & 0xff) << 4; /* The 8 bits from the 1-indexed octet.
                                So now we have 12 bits worth in x... */
                result[--resp] = chars[x%32];
                x /= 32; /* ... now we have 7 bits worth in x... */
                result[--resp] = chars[x%32];
                x /= 32; /* ... now we have 2 bits worth in x... */
            case 1:
                x |= (os[--len] & 0xff) << 2; /* The 8 bits from the 0-indexed octet.
                                So now we have 10 bits worth in x... */
                result[--resp] = chars[x%32];
                x /= 32; /* ... now we have 5 bits worth in x... */
                result[--resp] = chars[x];

            } /* switch (switcher) */
            switcher = 0;
        } while (len > 0);

        /* truncate any unused trailing zero quintets */
        String encoded = new String(result, 0, divceil(lengthInBits, 5));
        return encoded;
    }

    
    /**
     * Decode a Base32 string into binary data.
     *
     * The method returns a byte array that contains the binary data
     * that was decoded from the base32 string.
     *
     * @param cs The String containing the base32 data. The length
     * must be at least (lengthInBits + 5 - 1) / 5 characters .
     * @param lengthInBits Defines how may bits shall be decoded from the
     * String. 
     * @return
     *     The byte array containg the decoded data.
     */
    public static byte[] ascii2binary(String cs, int lengthInBits ) {
        
        int x = 0;    // to hold up to 32 bits worth of the input

        int size = divceil(lengthInBits, 5);  // minimum length of input String

        /* if lengthinbits is not a multiple of 5 then this is
         * allocating space for 0 or 1 extra octets that will be
         * truncated at the end of this function if they are
         * not needed
         */
        int len = divceil(size*5, 8);
        byte[] binaryResult = new byte[len];

        /* offset into the result buffer, initially pointing to
         * the "one-past-the-end" octet
         */
        int resp = binaryResult.length;

        /* index into the input buffer, initially pointing to the
         * "one-past-the-end" character
         */
        int csp = size;

        /* Now this is a real live Duff's device, modifyed for Java usage.  You gotta love it. */
        int switcher = csp % 8;
        
            do {
            switch (switcher) {
            case 0:
                x = revchars[cs.charAt(--csp)& 0xff]; /* 5 bits... */
            case 7:
                x |= revchars[cs.charAt(--csp)& 0xff] << 5; /* 10 bits... */
                binaryResult[--resp] = (byte)(x % 256);
                x /= 256; /* 2 bits... */
            case 6:
                x |= revchars[cs.charAt(--csp)& 0xff] << 2; /* 7 bits... */
            case 5:
                x |= revchars[cs.charAt(--csp)& 0xff] << 7; /* 12 bits... */
                binaryResult[--resp] = (byte)(x % 256);
                x /= 256; /* 4 bits... */
            case 4:
                x |= revchars[cs.charAt(--csp)& 0xff] << 4; /* 9 bits... */
                binaryResult[--resp] = (byte)(x % 256);
                x /= 256; /* 1 bit... */
            case 3:
                x |= revchars[cs.charAt(--csp)& 0xff] << 1; /* 6 bits... */
            case 2:
                x |= revchars[cs.charAt(--csp)& 0xff] << 6; /* 11 bits... */
                binaryResult[--resp] = (byte)(x % 256);
                x /= 256; /* 3 bits... */
            case 1:
                x |= revchars[cs.charAt(--csp)& 0xff] << 3; /* 8 bits... */
                binaryResult[--resp] = (byte)(x % 256);
            } /* switch ((csp - cs.buf) % 8) */
            switcher = 0;
        } while (csp > 0);

        /* truncate any unused trailing zero octets */
        int resultLength = divceil(lengthInBits, 8);
        if (resultLength < len) {
            byte[] shorterResult = new byte[resultLength];
            System.arraycopy(binaryResult, 0, shorterResult, 0, shorterResult.length);
            return shorterResult;
        }
        return binaryResult;
    }

//    public static void main(String[] args)
//    {
//        byte[] ones = {1, 1, 1, 1, 1};
//        byte[] onesMore = {1, 1, 1, 1, 1, 1, 1, 1, 1, 1};
//        byte[] eightOne = {(byte)0x81, (byte)0x81, (byte)0x81, (byte)0x81,
//                (byte)0x81, (byte)0x81, (byte)0x81, (byte)0x81};
//
//        String encoded = binary2ascii(ones, 40);
//        System.err.println("Endcoded zeroOne, 40bits (expected: 'yryonyeb'): " + encoded);
//        encoded = binary2ascii(ones, 15);
//        System.err.println("Endcoded zeroOne, 15bits (expected: 'yry'): " + encoded);
//        encoded = binary2ascii(onesMore, 80);
//        System.err.println("Endcoded zeroOne, 80bits (expected: 'yryonyebyryonyeb'): " + encoded);
//        byte[] decoded = ascii2binary(encoded, 80);
//        ZrtpUtils.hexdump("Decoded 80 bits zeroOne", decoded, decoded.length);
//        decoded = ascii2binary(encoded, 8);
//        ZrtpUtils.hexdump("Decoded 8 bits zeroOne", decoded, decoded.length);
//
//        encoded = binary2ascii(eightOne, 15);
//        System.err.println("Endcoded eightOne, 15bits (expected: 'ogy'): " + encoded);
//        encoded = binary2ascii(eightOne, 16);
//        System.err.println("Endcoded eightOne, 16bits (expected: 'ogyo'): " + encoded);
//        encoded = binary2ascii(eightOne, 20);
//        System.err.println("Endcoded eightOne, 20bits (expected: 'ogya'): " + encoded);
//        encoded = binary2ascii(eightOne, 64);
//        System.err.println("Endcoded eightOne, 64bits (expected: 'ogyadycbogyan'): " + encoded);
//
//        decoded = ascii2binary(encoded, 7);
//        ZrtpUtils.hexdump("Decoded 7 bits eightOne", decoded, decoded.length);
//        decoded = ascii2binary(encoded, 8);
//        ZrtpUtils.hexdump("Decoded 8 bits eightOne", decoded, decoded.length);
//        decoded = ascii2binary(encoded, 15);
//        ZrtpUtils.hexdump("Decoded 15 bits eightOne", decoded, decoded.length);
//        decoded = ascii2binary(encoded, 16);
//        ZrtpUtils.hexdump("Decoded 16 bits eightOne", decoded, decoded.length);
//        decoded = ascii2binary(encoded, 64);
//        ZrtpUtils.hexdump("Decoded 64 bits eightOne", decoded, decoded.length);
//    }
}


package gnu.java.zrtp.utils;

/**
 * Implements the base32 Emoji functions.
 *
 * Some technical details:
 * - add a new SAS algorithm to the ZRTP library that uses 32 Unicode code points
 *   instead of 32 ASCII characters.
 * - select 32 emojis that are easily distinguishable, known to everyone, not offending etc,
 *   using standard Unicode code points
 * - select colored emojis that look good on white and on black backgrounds (many
 *   emojis look good on white only)
 * - select emojis that are available on iOS, Android, Mac OS X (Windows?)
 *
 * I used the information on this Unicode page http://unicode.org/emoji/charts/full-emoji-list.html
 *
 * Created by werner on 30.12.15.
 */
public class EmojiBase32 {

    // I used the information on this Unicode page http://unicode.org/emoji/charts/full-emoji-list.html
    // The comments are:        Seq. Nr.   Name
    static int[] emojis = {
            0x0001f601,        // 0002     GRINNING FACE WITH SMILING EYES
            0x0001f63a,        // 0080     SMILING CAT FACE WITH OPEN MOUTH
            0x0001f465,        // 0270     BUSTS IN SILHOUETTE
            0x0001f332,        // 0611     EVERGREEN TREE
            0x0001f45f,        // 0516     ATHLETIC SHOE
            0x0000270b,        // 0394     RAISED HAND
            0x0001f44d,        // 0412     THUMBS UP SIGN
            0x0001f435,        // 0528     MONKEY FACE
            0x0001f434,        // 0540     HORSE FACE
            0x0001f40d,        // 0580     SNAKE
            0x0001f41f,        // 0586     FISH
            0x0001f338,        // 0601     CHERRY BLOSSOM
            0x0001f310,        // 0694     GLOBE WITH MERIDIANS
            0x0001f3e0,        // 0711     HOUSE BUILDING
            0x0001f31e,        // 0876     SUN WITH FACE
            0x0001f698,        // 0779     ONCOMING AUTOMOBILE
            0x0001f535,        // 1367     LARGE BLUE CIRCLE
            0x0001f6a2,        // 0804     SHIP
            0x0001f53a,        // 1358     UP-POINTING RED TRIANGLE
            0x0001f42a,        // 0554     DROMEDARY CAMEL
            0x0001f525,        // 0903     FIRE
            0x0001f388,        // 0911     BALLOON
            0x0001f426,        // 0575     BIRD
            0x0001f50d,        // 1052     LEFT-POINTING MAGNIFYING GLASS
            0x0001f4d7,        // 1065     GREEN BOOK
            0x0001f4a1,        // 1058     ELECTRIC LIGHT BULB
            0x0001f536,        // 1354     LARGE ORANGE DIAMOND
            0x0001f528,        // 1134     HAMMER
            0x0001f55B,        // 0837     CLOCK FACE TWELVE OCLOCK
            0x0001f31f,        // 0878     GLOWING STAR
            0x0000274e,        // 1232     NEGATIVE SQUARED CROSS MARK
            0x0001f6a9         // 1157     TRIANGULAR FLAG ON POST
    };

    /**
     * Encode binary data into a Base32 string.
     *
     * The method returns a string that contains the emoji base32 encoded
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
        int[] result = new int[Base32.divceil(len*8, 5)];
        for (int i = 0; i < result.length; i++) {
            result[i] = 0x20;                           // Unicode "blank"
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
                    result[--resp] = emojis[x % 32]; /* The least sig 5 bits go into the final quintet. */
                    x /= 32;    /* ... now we have 3 bits worth in x... */
                case 4:
                    x |= (os[--len]&0xff) << 3; /* ... now we have 11 bits worth in x... */
                    result[--resp] = emojis[x % 32];
                    x /= 32; /* ... now we have 6 bits worth in x... */
                    result[--resp] = emojis[x % 32];
                    x /= 32; /* ... now we have 1 bits worth in x... */
                case 3:
                    x |= (os[--len] & 0xff) << 1; /* The 8 bits from the 2-indexed octet.
                                So now we have 9 bits worth in x... */
                    result[--resp] = emojis[x % 32];
                    x /= 32; /* ... now we have 4 bits worth in x... */
                case 2:
                    x |= (os[--len] & 0xff) << 4; /* The 8 bits from the 1-indexed octet.
                                So now we have 12 bits worth in x... */
                    result[--resp] = emojis[x%32];
                    x /= 32; /* ... now we have 7 bits worth in x... */
                    result[--resp] = emojis[x%32];
                    x /= 32; /* ... now we have 2 bits worth in x... */
                case 1:
                    x |= (os[--len] & 0xff) << 2; /* The 8 bits from the 0-indexed octet.
                                So now we have 10 bits worth in x... */
                    result[--resp] = emojis[x%32];
                    x /= 32; /* ... now we have 5 bits worth in x... */
                    result[--resp] = emojis[x];

            } /* switch (switcher) */
            switcher = 0;
        } while (len > 0);

        /* truncate any unused trailing zero quintets */
        return new String(result, 0, Base32.divceil(lengthInBits, 5));
    }
}

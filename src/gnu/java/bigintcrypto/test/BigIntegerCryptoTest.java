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

package gnu.java.bigintcrypto.test;

/**
 * The test class for BigIntegerCrypto.
 * 
 * This class contains tests for BigIntegerCrypto. Mos tests were copied
 * from various sources, for example BouncyCastle.
 * 
 * Now they are in a Junit compliant framework.
 *
 * @author  Werner Dittmann
 */


import gnu.java.bigintcrypto.BigIntegerCrypto;

import java.security.SecureRandom;

import junit.framework.Test;
import junit.framework.TestCase;
import junit.framework.TestSuite;



public class BigIntegerCryptoTest
    extends TestCase
{
    private static BigIntegerCrypto VALUE1 = new BigIntegerCrypto("1234");
    private static BigIntegerCrypto VALUE2 = new BigIntegerCrypto("1234567890");
    private static BigIntegerCrypto VALUE3 = new BigIntegerCrypto("12345678901234567890123");
    
    
    protected static SecureRandom r = new SecureRandom();

    java.math.BigInteger[] intsToTest = {
        new java.math.BigInteger("0"),
        new java.math.BigInteger("1"),
        new java.math.BigInteger("2"),
        new java.math.BigInteger("8"),
        new java.math.BigInteger("9"),
        new java.math.BigInteger("10"),
        new java.math.BigInteger("11"),
        new java.math.BigInteger("12"),
        new java.math.BigInteger("21"),
        new java.math.BigInteger("1000000"),
        new java.math.BigInteger("123456789"),
        new java.math.BigInteger("10203040506070809"),
        new java.math.BigInteger("111111111111"),
        new java.math.BigInteger("222222222222"),
        new java.math.BigInteger(256, r),
        new java.math.BigInteger(256, r),
        new java.math.BigInteger(256, r),
        new java.math.BigInteger(256, r),
        new java.math.BigInteger(256, r)
    };
    
    BigIntegerCrypto[] myBigInts;

    java.math.BigInteger[] dividends = {
            new java.math.BigInteger(81, r),
            new java.math.BigInteger(100, r),
            new java.math.BigInteger(190, r),
            new java.math.BigInteger(200, r),
            new java.math.BigInteger(256, r)
    };
    
    java.math.BigInteger[] divisors = {
            new java.math.BigInteger(77, r),
            new java.math.BigInteger(111, r),
            new java.math.BigInteger(179, r),
            new java.math.BigInteger(193, r),
            new java.math.BigInteger(203, r)
    };
 
    BigIntegerCrypto[] myDividends;
    BigIntegerCrypto[] myDivisors;

    /**
     * Default constructor for test class BigIntegerTest
     */
    public BigIntegerCryptoTest()
    {
        //  This is here because it doesn't need to be 
        // re-run once per test:  BigIntegers are immutable.
        myBigInts = new BigIntegerCrypto[intsToTest.length];
        for (int x = 0; x < myBigInts.length; x++) {
            myBigInts[x] = new BigIntegerCrypto(intsToTest[x].toString());
        }
        
        myDividends = new BigIntegerCrypto[dividends.length];
        myDivisors = new BigIntegerCrypto[divisors.length];
        
        for (int i = 0; i < dividends.length; i++) {
            myDividends[i] = new BigIntegerCrypto(dividends[i].toString());
            myDivisors[i] = new BigIntegerCrypto(divisors[i].toString());
        }
    }

    /**
     * Sets up the test fixture.
     *
     * Called before every test case method.
     */
    protected void setUp()
    {
    }

    /**
     * Tears down the test fixture.
     *
     * Called after every test case method.
     */
    protected void tearDown()
    {
    }
    

    public String getName()
    {
        return "BigIntegerCrypto";
    }

    public void testClearBit()
    {
        BigIntegerCrypto value = VALUE1.clearBit(3);
        BigIntegerCrypto result = new BigIntegerCrypto("1234");
        
        if (!value.equals(result))
        {
            fail("clearBit - expected: " + result + " got: " + value);
        }
        
        value = VALUE2.clearBit(3);
        result = new BigIntegerCrypto("1234567890");
        
        if (!value.equals(result))
        {
            fail("clearBit - expected: " + result + " got: " + value);
        }
        
        value = VALUE3.clearBit(3);
        result = new BigIntegerCrypto("12345678901234567890115");
        
        if (!value.equals(result))
        {
            fail("clearBit - expected: " + result + " got: " + value);
        }
        
        value = VALUE2.clearBit(55);
        result = new BigIntegerCrypto("1234567890");
        
        if (!value.equals(result))
        {
            fail("clearBit - expected: " + result + " got: " + value);
        }
        
        value = VALUE3.clearBit(55);
        result = new BigIntegerCrypto("12345642872437548926155");
        
        if (!value.equals(result))
        {
            fail("clearBit - expected: " + result + " got: " + value);
        }
    }
    
    public void testFlipBit()
    {
        BigIntegerCrypto value = VALUE1.flipBit(3);
        BigIntegerCrypto result = new BigIntegerCrypto("1242");
        
        if (!value.equals(result))
        {
            fail("flipBit - expected: " + result + " got: " + value);
        }
        
        value = VALUE2.flipBit(3);
        result = new BigIntegerCrypto("1234567898");
        
        if (!value.equals(result))
        {
            fail("flipBit - expected: " + result + " got: " + value);
        }
        
        value = VALUE3.flipBit(3);
        result = new BigIntegerCrypto("12345678901234567890115");
        
        if (!value.equals(result))
        {
            fail("flipBit - expected: " + result + " got: " + value);
        }
        
        value = VALUE2.flipBit(55);
        result = new BigIntegerCrypto("36028798253531858");
        
        if (!value.equals(result))
        {
            fail("flipBit - expected: " + result + " got: " + value);
        }
        
        value = VALUE3.flipBit(55);
        result = new BigIntegerCrypto("12345642872437548926155");
        
        if (!value.equals(result))
        {
            fail("flipBit - expected: " + result + " got: " + value);
        }
    }
    
    public void testSetBit()
    {
        BigIntegerCrypto value = VALUE1.setBit(3);
        BigIntegerCrypto result = new BigIntegerCrypto("1242");
        
        if (!value.equals(result))
        {
            fail("setBit - expected: " + result + " got: " + value);
        }
        
        value = VALUE2.setBit(3);
        result = new BigIntegerCrypto("1234567898");
        
        if (!value.equals(result))
        {
            fail("setBit - expected: " + result + " got: " + value);
        }
        
        value = VALUE3.setBit(3);
        result = new BigIntegerCrypto("12345678901234567890123");
        
        if (!value.equals(result))
        {
            fail("setBit - expected: " + result + " got: " + value);
        }
        
        value = VALUE2.setBit(55);
        result = new BigIntegerCrypto("36028798253531858");
        
        if (!value.equals(result))
        {
            fail("setBit - expected: " + result + " got: " + value);
        }
        
        value = VALUE3.setBit(55);
        result = new BigIntegerCrypto("12345678901234567890123");
        
        if (!value.equals(result))
        {
            fail("setBit - expected: " + result + " got: " + value);
        }
    }
    
    public void testXor()
    {
        BigIntegerCrypto value = VALUE1.xor(VALUE2);
        BigIntegerCrypto result = new BigIntegerCrypto("1234568704");
        
        if (!value.equals(result))
        {
            fail("xor - expected: " + result + " got: " + value);
        }
        
        value = VALUE1.xor(VALUE3);
        result = new BigIntegerCrypto("12345678901234567888921");
        
        if (!value.equals(result))
        {
            fail("xor - expected: " + result + " got: " + value);
        }
        
        value = VALUE3.xor(VALUE1);
        result = new BigIntegerCrypto("12345678901234567888921");
        
        if (!value.equals(result))
        {
            fail("xor - expected: " + result + " got: " + value);
        }
        
        value = VALUE2.xor(new BigIntegerCrypto("-1"));
        result = new BigIntegerCrypto("-1234567891");
        
        if (!value.equals(result))
        {
            fail("xor - expected: " + result + " got: " + value);
        }
        
        value = VALUE3.xor(VALUE3);
        result = new BigIntegerCrypto("0");
        
        if (!value.equals(result))
        {
            fail("xor - expected: " + result + " got: " + value);
        }
    }
    
    public void testPerform()
    {
        BigIntegerCrypto n1, n2, r1;

    // test division where the difference in bit length of the dividend and divisor is 32 bits 
        n1 = new BigIntegerCrypto("54975581388");
        n2 = new BigIntegerCrypto("10");
        r1 = n1.divide(n2);
        if (!r1.toString(10).equals("5497558138"))
        {
                fail("BigIntegerCrypto: failed Divide Test");
        }

        // two's complement test
        byte[] zeroBytes = BigIntegerCrypto.ZERO.toByteArray();
        byte[] oneBytes = BigIntegerCrypto.ONE.toByteArray();
        byte[] minusOneBytes = BigIntegerCrypto.ONE.negate().toByteArray();
    
        BigIntegerCrypto zero = new BigIntegerCrypto(zeroBytes);
        if (!zero.equals(BigIntegerCrypto.ZERO))
        {
            fail("Failed constructing zero");
        }

        BigIntegerCrypto one = new BigIntegerCrypto(oneBytes);
        if (!one.equals(BigIntegerCrypto.ONE))
        {
            fail("Failed constructing one");
        }

        BigIntegerCrypto minusOne = new BigIntegerCrypto(minusOneBytes);
        if (!minusOne.equals(BigIntegerCrypto.ONE.negate()))
        {
            fail("Failed constructing minus one");
        }
    
        SecureRandom random = new SecureRandom();
        byte[] randomBytes = new byte[100];
        for (int i=0; i < 100; i++)
        {
            random.nextBytes(randomBytes);
            BigIntegerCrypto bcInt = new BigIntegerCrypto(randomBytes);
            BigIntegerCrypto bcInt2 = new BigIntegerCrypto(bcInt.toByteArray());
            if (!bcInt.equals(bcInt2))
            {
                fail("Failed constructing random value " + i);
            }
            
//            java.math.BigIntegerCrypto jdkInt = new java.math.BigIntegerCrypto(randomBytes);
//            byte[] bcBytes = bcInt.toByteArray();
//            byte[] jdkBytes = jdkInt.toByteArray();
//            if (!arrayEquals(bcBytes, jdkBytes))
//            {
//                fail(""Failed constructing random value " + i);
//            }
        }
    }
    
    
    public void testMultiply() {
        
     // The following tests copied from:
     // Copyright (C) 2004 David Gilbert <david.gilbert@object-refinery.com>

     // Mauve is free software; you can redistribute it and/or modify
     // it under the terms of the GNU General Public License as published by
     // the Free Software Foundation; either version 2, or (at your option)
     // any later version.

     // Mauve is distributed in the hope that it will be useful,
     // but WITHOUT ANY WARRANTY; without even the implied warranty of
     // MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
     // GNU General Public License for more details.

     // You should have received a copy of the GNU General Public License
     // along with Mauve; see the file COPYING.  If not, write to
     // the Free Software Foundation, 59 Temple Place - Suite 330,
     // Boston, MA 02111-1307, USA.  */

        // modifications to use JUnit by: Werner Dittmann
        
        // some really simple cases
        BigIntegerCrypto p1 = new BigIntegerCrypto("1");
        BigIntegerCrypto p2 = new BigIntegerCrypto("2");
        BigIntegerCrypto m1 = new BigIntegerCrypto("-1");
        BigIntegerCrypto m2 = new BigIntegerCrypto("-2");
     
        assertTrue(p1.multiply(p2).equals(p2));
        assertTrue(p1.multiply(m2).equals(m2));
        assertTrue(m1.multiply(p2).equals(m2));
        assertTrue(m1.multiply(m2).equals(p2));

        // some bigger numbers
        BigIntegerCrypto bp1 = new BigIntegerCrypto("12345678901234567890123456789012345678901234567890");
        BigIntegerCrypto bp2 = new BigIntegerCrypto("987654321098765432198765");
        BigIntegerCrypto bm1 = new BigIntegerCrypto("-12345678901234567890123456789012345678901234567890");
        BigIntegerCrypto bm2 = new BigIntegerCrypto("-987654321098765432198765");
        BigIntegerCrypto resultp = new BigIntegerCrypto("12193263113702179523715891618930089161893008916189178958987793067366655850");
        BigIntegerCrypto resultm = new BigIntegerCrypto("-12193263113702179523715891618930089161893008916189178958987793067366655850");
     
        assert(bp1.multiply(bp2).equals(resultp));
        assertTrue(bp1.multiply(bm2).equals(resultm));
        assertTrue(bm1.multiply(bp2).equals(resultm));
        assertTrue(bm1.multiply(bm2).equals(resultp));

        // check null argument
        boolean pass = false;
        try 
        {
          p1.multiply(null);
        }
        catch (NullPointerException e)
        {
          pass = true;
        }
        assertTrue(pass);
      }    
    
    
    /*
     * The next tests use the setup done in the constructor and compare
     * the results of BigIntegerCrypto to the standard BigInteger package.
     * 
     * These tests were copied from Zachary Kurmas (package/project not 
     * known to me) and modified to use the BigIntegerCrypto and the published
     * API, not the internal API.
     */
    public void testToString() {
        for (int x = 0; x < intsToTest.length; x++) {
            assertEquals("toString failed", intsToTest[x].toString(),
                    myBigInts[x].toString());
        }
    }

    public void testEquals() {
        for (int x = 0; x < intsToTest.length; x++) {
            for (int y = 0; y < intsToTest.length; y++) {
                boolean observed = myBigInts[x].equals(myBigInts[y]);
                boolean expected = intsToTest[x].equals(intsToTest[y]);

                assertEquals("Equals failed comparing " + intsToTest[x]
                        + " and " + intsToTest[y], expected, observed);
            } // end for y
        } // end for x
    } // end testEquals

    public void testLessThan() {
        for (int x = 0; x < intsToTest.length; x++) {
            for (int y = 0; y < intsToTest.length; y++) {
                boolean observed = myBigInts[x].compareTo(myBigInts[y]) < 0;
                boolean expected = intsToTest[x].compareTo(intsToTest[y]) < 0;

                assertEquals("lessThan failed comparing " + intsToTest[x]
                        + " and " + intsToTest[y], expected, observed);
            } // end for y
        } // end for x
    } // end test

    protected void tAdd_helper(int a, int b) {
        java.math.BigInteger expected = intsToTest[a].add(intsToTest[b]);
        BigIntegerCrypto observed = myBigInts[a].add(myBigInts[b]);
        assertEquals("Failure adding " + a + " and " + b, expected.toString(),
                observed.toString());
    }

    public void testAdd() {
        for (int x = 0; x < intsToTest.length; x++) {
            for (int y = 0; y < intsToTest.length; y++) {
                tAdd_helper(x, y);
            }
        }
    }

    protected void tMult_helper(int a, int b) {
        java.math.BigInteger expected = intsToTest[a].multiply(intsToTest[b]);
        BigIntegerCrypto observed = myBigInts[a].multiply(myBigInts[b]);
        assertEquals("Failure multiplying " + a + " and " + b, expected
                .toString(), observed.toString());
    }

    public void testMultiply1() {
        for (int x = 0; x < intsToTest.length; x++) {
            for (int y = 0; y < intsToTest.length; y++) {
                tMult_helper(x, y);
            }
        }
    }

    protected void tDiv_helper(int a, int b) {
        java.math.BigInteger expected = dividends[a].divide(divisors[b]);
        BigIntegerCrypto observed = myDividends[a].divide(myDivisors[b]);
        assertEquals("Failure dividing " + a + " and " + b, expected
                .toString(), observed.toString());
    }

    public void testDivision() {
        for (int x = 0; x < dividends.length; x++) {
            for (int y = 0; y < divisors.length; y++) {
                tDiv_helper(x, y);
            }
        }
    }
    
    protected void tDivRem_helper(int a, int b) {
        java.math.BigInteger expected[] = dividends[a]
                .divideAndRemainder(divisors[b]);
        BigIntegerCrypto observed[] = myDividends[a]
                .divideAndRemainder(myDivisors[b]);
        assertEquals("Failure dividing " + a + " and " + b, expected[0]
                .toString(), observed[0].toString());
        assertEquals("Failure dividing " + a + " and " + b, expected[1]
                .toString(), observed[1].toString());
    }

    public void testDivisionReminder() {
        for (int x = 0; x < dividends.length; x++) {
            for (int y = 0; y < divisors.length; y++) {
                tDivRem_helper(x, y);
            }
        }
    }

    /**
     * JUnit suite <p/>
     * 
     * @return a junit test suite
     */
    public static Test suite() {
        return new TestSuite(BigIntegerCryptoTest.class);
    }

    /**
     * Main method <p/>
     * 
     * @param args
     *            command line args
     */
    public static void main(String[] args) {
        junit.textui.TestRunner.run(suite());
    }
}


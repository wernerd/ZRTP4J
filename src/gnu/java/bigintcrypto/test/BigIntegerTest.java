package gnu.java.bigintcrypto.test;

import java.math.BigInteger;

import java.security.SecureRandom;


import junit.framework.Test;
import junit.framework.TestCase;
import junit.framework.TestSuite;

public class BigIntegerTest
    extends TestCase
{
    private static BigInteger VALUE1 = new BigInteger("1234");
    private static BigInteger VALUE2 = new BigInteger("1234567890");
    private static BigInteger VALUE3 = new BigInteger("12345678901234567890123");
    
    public String getName()
    {
        return "BigInteger";
    }

    public void testClearBit()
    {
        BigInteger value = VALUE1.clearBit(3);
        BigInteger result = new BigInteger("1234");
        
        if (!value.equals(result))
        {
            fail("clearBit - expected: " + result + " got: " + value);
        }
        
        value = VALUE2.clearBit(3);
        result = new BigInteger("1234567890");
        
        if (!value.equals(result))
        {
            fail("clearBit - expected: " + result + " got: " + value);
        }
        
        value = VALUE3.clearBit(3);
        result = new BigInteger("12345678901234567890115");
        
        if (!value.equals(result))
        {
            fail("clearBit - expected: " + result + " got: " + value);
        }
        
        value = VALUE2.clearBit(55);
        result = new BigInteger("1234567890");
        
        if (!value.equals(result))
        {
            fail("clearBit - expected: " + result + " got: " + value);
        }
        
        value = VALUE3.clearBit(55);
        result = new BigInteger("12345642872437548926155");
        
        if (!value.equals(result))
        {
            fail("clearBit - expected: " + result + " got: " + value);
        }
    }
    
    public void testFlipBit()
    {
        BigInteger value = VALUE1.flipBit(3);
        BigInteger result = new BigInteger("1242");
        
        if (!value.equals(result))
        {
            fail("flipBit - expected: " + result + " got: " + value);
        }
        
        value = VALUE2.flipBit(3);
        result = new BigInteger("1234567898");
        
        if (!value.equals(result))
        {
            fail("flipBit - expected: " + result + " got: " + value);
        }
        
        value = VALUE3.flipBit(3);
        result = new BigInteger("12345678901234567890115");
        
        if (!value.equals(result))
        {
            fail("flipBit - expected: " + result + " got: " + value);
        }
        
        value = VALUE2.flipBit(55);
        result = new BigInteger("36028798253531858");
        
        if (!value.equals(result))
        {
            fail("flipBit - expected: " + result + " got: " + value);
        }
        
        value = VALUE3.flipBit(55);
        result = new BigInteger("12345642872437548926155");
        
        if (!value.equals(result))
        {
            fail("flipBit - expected: " + result + " got: " + value);
        }
    }
    
    public void testSetBit()
    {
        BigInteger value = VALUE1.setBit(3);
        BigInteger result = new BigInteger("1242");
        
        if (!value.equals(result))
        {
            fail("setBit - expected: " + result + " got: " + value);
        }
        
        value = VALUE2.setBit(3);
        result = new BigInteger("1234567898");
        
        if (!value.equals(result))
        {
            fail("setBit - expected: " + result + " got: " + value);
        }
        
        value = VALUE3.setBit(3);
        result = new BigInteger("12345678901234567890123");
        
        if (!value.equals(result))
        {
            fail("setBit - expected: " + result + " got: " + value);
        }
        
        value = VALUE2.setBit(55);
        result = new BigInteger("36028798253531858");
        
        if (!value.equals(result))
        {
            fail("setBit - expected: " + result + " got: " + value);
        }
        
        value = VALUE3.setBit(55);
        result = new BigInteger("12345678901234567890123");
        
        if (!value.equals(result))
        {
            fail("setBit - expected: " + result + " got: " + value);
        }
    }
    
    public void testXor()
    {
        BigInteger value = VALUE1.xor(VALUE2);
        BigInteger result = new BigInteger("1234568704");
        
        if (!value.equals(result))
        {
            fail("xor - expected: " + result + " got: " + value);
        }
        
        value = VALUE1.xor(VALUE3);
        result = new BigInteger("12345678901234567888921");
        
        if (!value.equals(result))
        {
            fail("xor - expected: " + result + " got: " + value);
        }
        
        value = VALUE3.xor(VALUE1);
        result = new BigInteger("12345678901234567888921");
        
        if (!value.equals(result))
        {
            fail("xor - expected: " + result + " got: " + value);
        }
        
        value = VALUE2.xor(new BigInteger("-1"));
        result = new BigInteger("-1234567891");
        
        if (!value.equals(result))
        {
            fail("xor - expected: " + result + " got: " + value);
        }
        
        value = VALUE3.xor(VALUE3);
        result = new BigInteger("0");
        
        if (!value.equals(result))
        {
            fail("xor - expected: " + result + " got: " + value);
        }
    }
    
    public void testPerform()
    {
        BigInteger n1, n2, r1;

    // test division where the difference in bit length of the dividend and divisor is 32 bits 
        n1 = new BigInteger("54975581388");
        n2 = new BigInteger("10");
        r1 = n1.divide(n2);
        if (!r1.toString(10).equals("5497558138"))
        {
                fail("BigInteger: failed Divide Test");
        }

        // two's complement test
        byte[] zeroBytes = BigInteger.ZERO.toByteArray();
        byte[] oneBytes = BigInteger.ONE.toByteArray();
        byte[] minusOneBytes = BigInteger.ONE.negate().toByteArray();
    
        BigInteger zero = new BigInteger(zeroBytes);
        if (!zero.equals(BigInteger.ZERO))
        {
            fail("Failed constructing zero");
        }

        BigInteger one = new BigInteger(oneBytes);
        if (!one.equals(BigInteger.ONE))
        {
            fail("Failed constructing one");
        }

        BigInteger minusOne = new BigInteger(minusOneBytes);
        if (!minusOne.equals(BigInteger.ONE.negate()))
        {
            fail("Failed constructing minus one");
        }
    
        SecureRandom random = new SecureRandom();
        byte[] randomBytes = new byte[100];
        for (int i=0; i < 100; i++)
        {
            random.nextBytes(randomBytes);
            BigInteger bcInt = new BigInteger(randomBytes);
            BigInteger bcInt2 = new BigInteger(bcInt.toByteArray());
            if (!bcInt.equals(bcInt2))
            {
                fail("Failed constructing random value " + i);
            }
            
//            java.math.BigInteger jdkInt = new java.math.BigInteger(randomBytes);
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

        // modified to use Junit by: Werner Dittmann
        
        // some really simple cases
        BigInteger p1 = new BigInteger("1");
        BigInteger p2 = new BigInteger("2");
        BigInteger m1 = new BigInteger("-1");
        BigInteger m2 = new BigInteger("-2");
     
        assertTrue(p1.multiply(p2).equals(p2));
        assertTrue(p1.multiply(m2).equals(m2));
        assertTrue(m1.multiply(p2).equals(m2));
        assertTrue(m1.multiply(m2).equals(p2));

        // some bigger numbers
        BigInteger bp1 = new BigInteger("12345678901234567890123456789012345678901234567890");
        BigInteger bp2 = new BigInteger("987654321098765432198765");
        BigInteger bm1 = new BigInteger("-12345678901234567890123456789012345678901234567890");
        BigInteger bm2 = new BigInteger("-987654321098765432198765");
        BigInteger resultp = new BigInteger("12193263113702179523715891618930089161893008916189178958987793067366655850");
        BigInteger resultm = new BigInteger("-12193263113702179523715891618930089161893008916189178958987793067366655850");
     
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
        

    /**
     * JUnit suite <p/>
     * 
     * @return a junit test suite
     */
    public static Test suite() {
        return new TestSuite(BigIntegerTest.class);
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


package gnu.java.bigintcrypto.test;

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
            
//            java.math.BigInteger jdkInt = new java.math.BigInteger(randomBytes);
//            byte[] bcBytes = bcInt.toByteArray();
//            byte[] jdkBytes = jdkInt.toByteArray();
//            if (!arrayEquals(bcBytes, jdkBytes))
//            {
//                fail(""Failed constructing random value " + i);
//            }
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


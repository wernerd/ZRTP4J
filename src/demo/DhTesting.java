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

package demo;

import gnu.java.zrtp.ZrtpConstants;
import gnu.java.zrtp.utils.ZrtpUtils;

import java.math.BigInteger;

import java.security.InvalidAlgorithmParameterException;
import java.security.NoSuchAlgorithmException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyFactory;
import java.security.NoSuchProviderException;
import java.security.spec.InvalidKeySpecException;

import javax.crypto.interfaces.DHPublicKey;
import javax.crypto.spec.DHPublicKeySpec;

import javax.crypto.KeyAgreement;

/**
 * @author Werner Dittmann <Werner.Dittmann@t-online.de>
 *
 */
public class DhTesting {

    private KeyPairGenerator dhKeyPairGen;
    private KeyPair myKeyPair = null;
    private KeyFactory DHkeyFactory = null;
    private byte[] pubKeyBytes = null;

    /**
     * Length off public key
     */
    private int pubKeyLen;
    
    static {
        try {
            Class c = Class
                    .forName("org.bouncycastle.jce.provider.BouncyCastleProvider");
            java.security.Security.addProvider((java.security.Provider) c
                    .newInstance());
        } catch (Throwable t) {
        }
    }

    public DhTesting() {
        /*
         * Get all required crypto algorithms here, used everywhere :-)
         */
        try {
            dhKeyPairGen = KeyPairGenerator.getInstance("DH", "BC");
            DHkeyFactory = KeyFactory.getInstance("DH", "BC");
        } catch (NoSuchProviderException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        } catch (NoSuchAlgorithmException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        }
        try {
            dhKeyPairGen.initialize(ZrtpConstants.specDh3k);
        } catch (InvalidAlgorithmParameterException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        }

        myKeyPair = dhKeyPairGen.generateKeyPair();
        DHPublicKey dhp = (DHPublicKey)myKeyPair.getPublic();
        pubKeyBytes = dhp.getY().toByteArray();
        pubKeyLen = pubKeyBytes.length;

        System.err.println("Public key length: " + pubKeyBytes.length);
        // ZrtpUtils.hexdump("Public key", pubKeyBytes, pubKeyBytes.length);
        // check for leading zero byte if public key resulted in negtive
        // value. BigInteger adds a leading zero to drop the negatice sign bit
        if (pubKeyLen > 384) {
            if (pubKeyBytes[0] == 0) {
                System.err.println("trim public key bytes");
                byte[] tmp = new byte[384];
                System.arraycopy(pubKeyBytes, 1, tmp, 0, 384);
                pubKeyBytes = tmp;
                // ZrtpUtils.hexdump("Public key timmed", pubKeyBytes, pubKeyBytes.length);
            } else {
                System.err
                        .println("Unexpected length of public key (expected 384): "
                                + pubKeyLen);
            }
        }
        BigInteger newPubKeyInteger = new BigInteger(1, pubKeyBytes);
        DHPublicKeySpec dhs =  new DHPublicKeySpec(newPubKeyInteger, 
                ZrtpConstants.specDh3k.getP(), ZrtpConstants.specDh3k.getG());

        DHPublicKey newDHPub = null;
        try {
            newDHPub = (DHPublicKey)DHkeyFactory.generatePublic(dhs);
        } catch (InvalidKeySpecException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        }
        byte[] newPubBytes = newDHPub.getY().toByteArray(); 
        System.err.println("New Public key length: " + newPubBytes.length);
        // ZrtpUtils.hexdump("Public key", newPubBytes, newPubBytes.length);

    }
    
    void tester() throws Exception {
        //
        // a side
        //
        KeyPair aKeyPair = dhKeyPairGen.generateKeyPair();

        KeyAgreement aKeyAgree = KeyAgreement.getInstance("DH", "BC");

        aKeyAgree.init(aKeyPair.getPrivate());

        //
        // b side
        //
        KeyPair bKeyPair = dhKeyPairGen.generateKeyPair();

        KeyAgreement bKeyAgree = KeyAgreement.getInstance("DH", "BC");

        bKeyAgree.init(bKeyPair.getPrivate());

        //
        // agreement
        //
        aKeyAgree.doPhase(bKeyPair.getPublic(), true);
        bKeyAgree.doPhase(aKeyPair.getPublic(), true);

        byte[] k1bytes = aKeyAgree.generateSecret();
        BigInteger k1 = new BigInteger(k1bytes);
        BigInteger k2 = new BigInteger(bKeyAgree.generateSecret());
        if (!k1.equals(k2)) {
            System.err.println("2-way test failed");
        }
        
        System.err.println("Secret length: " + k1bytes.length);
        ZrtpUtils.hexdump("Secret bytes", k1bytes, k1bytes.length);
       
    }
    public static void main(String[] args) {
        DhTesting dht = new DhTesting();
        try {
            dht.tester();
        } catch (Exception e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        }
    }
}

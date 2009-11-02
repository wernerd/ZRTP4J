/**
 * Copyright (C) 2006-2009 Werner Dittmann
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

package gnu.java.zrtp;

import java.util.ArrayList;
import java.util.Iterator;


public class ZrtpConfigure {

    public ZrtpConfigure() {
    }

    private class Data<T> implements Iterable<T> {
        private final static int maxNoOfAlgos = 7;

        final private ArrayList<T> algos = new ArrayList<T>(maxNoOfAlgos);

        T getAlgoAt(int index) {
            return algos.get(index);
        }

        int addAlgo(T algo) {
            if (algos.size() >= maxNoOfAlgos) {
                return 0;
            }
            if (algos.contains(algo)) {
                return maxNoOfAlgos - algos.size();
            }
            algos.add(algo);
            return maxNoOfAlgos - algos.size();
        }

        int removeAlgo(T algo) {
            algos.remove(algo);
            return maxNoOfAlgos - algos.size();
        }

        int getNumConfiguredAlgos() {
            return algos.size();
        }

        public Iterator<T> iterator() {
            return algos.iterator();
        }
        
        void clear() {
            algos.clear();
        }
    }

    private Data<ZrtpConstants.SupportedHashes> hashes = 
        new Data<ZrtpConstants.SupportedHashes>();
    
    private Data<ZrtpConstants.SupportedSymCiphers> symCiphers =
        new Data<ZrtpConstants.SupportedSymCiphers>();
    
    private Data<ZrtpConstants.SupportedPubKeys> publicKeyAlgos =
        new Data<ZrtpConstants.SupportedPubKeys>();
    
    private Data<ZrtpConstants.SupportedSASTypes> sasTypes =
        new Data<ZrtpConstants.SupportedSASTypes>();
    
    private Data<ZrtpConstants.SupportedAuthLengths> authLengths =
        new Data<ZrtpConstants.SupportedAuthLengths>();
    
    /**
     * Convenience function that sets a pre-defined standard configuration.
     *
     * The standard configuration consists of the following algorithms:
     * <ul>
     * <li> Hash: SHA256 </li>
     * <li> Symmetric Cipher: AES 128, AES 256 </li>
     * <li> Public Key Algorithm: DH2048, DH3027. Mult </li>
     * <li> SAS type: libase 32 </li>
     * <li> SRTP Authentication lengths: 32, 80 </li>
     *</ul>
     */
    public void setStandardConfig() {
        hashes.clear();
        hashes.addAlgo(ZrtpConstants.SupportedHashes.S256);

        symCiphers.clear();
        symCiphers.addAlgo(ZrtpConstants.SupportedSymCiphers.AES3);
        symCiphers.addAlgo(ZrtpConstants.SupportedSymCiphers.AES1);

        publicKeyAlgos.clear();
        publicKeyAlgos.addAlgo(ZrtpConstants.SupportedPubKeys.DH3K);
        publicKeyAlgos.addAlgo(ZrtpConstants.SupportedPubKeys.DH2K);
        publicKeyAlgos.addAlgo(ZrtpConstants.SupportedPubKeys.MULT);

        sasTypes.clear();
        sasTypes.addAlgo(ZrtpConstants.SupportedSASTypes.B32);

        authLengths.clear();
        authLengths.addAlgo(ZrtpConstants.SupportedAuthLengths.HS32);
        authLengths.addAlgo(ZrtpConstants.SupportedAuthLengths.HS80);
    }

    /**
     * Convenience function that sets the mandatory algorithms only.
     *
     * Mandatory algorithms are:
     * <ul>
     * <li> Hash: SHA256 </li>
     * <li> Symmetric Cipher: AES 128 </li>
     * <li> Public Key Algorithm: DH3027, Mult </li>
     * <li> SAS type: libase 32 </li>
     * <li> SRTP Authentication lengths: 32, 80 </li>
     *</ul>
     */
    public void setMandatoryOnly() {
        hashes.clear();
        hashes.addAlgo(ZrtpConstants.SupportedHashes.S256);

        symCiphers.clear();
        symCiphers.addAlgo(ZrtpConstants.SupportedSymCiphers.AES1);

        publicKeyAlgos.clear();
        publicKeyAlgos.addAlgo(ZrtpConstants.SupportedPubKeys.DH3K);
        publicKeyAlgos.addAlgo(ZrtpConstants.SupportedPubKeys.MULT);

        sasTypes.clear();
        sasTypes.addAlgo(ZrtpConstants.SupportedSASTypes.B32);

        authLengths.clear();
        authLengths.addAlgo(ZrtpConstants.SupportedAuthLengths.HS32);
        authLengths.addAlgo(ZrtpConstants.SupportedAuthLengths.HS80);
    }

    /**
     * Clears all configuration data.
     * 
     * This function clears all configuration data. If an application hands
     * over an empty set of configuration data ZRTP does not set any
     * algorithm identifiers in the Hello message. In this case the receiver
     * has to select algorithms from the mandatory set of algorithms.
     */
    public void clear() {
        hashes.clear();
        symCiphers.clear();
        publicKeyAlgos.clear();
        sasTypes.clear();
        authLengths.clear();        
    }
    
    /*
     * Hash configuration functions
     */
    /**
     * Add a hash algorithm to configuration data.
     * 
     * Adds the specified hash algorithm to the configuration data. If no free
     * configuration data slot is available the function does not add the
     * algorithm and return zero.
     * 
     * @param algo
     *            The identifier of the hash algorithm to add.
     * @return Number of free hash configuration data slots.
     */
    public int addHashAlgo(ZrtpConstants.SupportedHashes algo) {
        return hashes.addAlgo(algo);
    }

    /**
     * Remove a hash algorithm from configuration data.
     * 
     * Removes the specified algorithm from hash configuration data. If the
     * algorithm was not configured previously the function does not modify the
     * configuration data and return the number of free configuration data
     * slots.
     * 
     * If an application removes all algorithms then ZRTP does not include any
     * algorithm into the hello message and falls back to a predefined mandatory
     * algorithm. In this case SHA256.
     * 
     * @param algo
     *            The identifier of the hash algorithm to remove.
     * @return Number of free hash configuration slots.
     */
    public int removeHashAlgo(ZrtpConstants.SupportedHashes algo) {
        return hashes.removeAlgo(algo);
    }

    /**
     * Returns the number of configured hash algorithms.
     * 
     * @return The number of configured hash algorithms (used configuration data
     *         slots)
     */
    public int getNumConfiguredHashes() {
        return hashes.getNumConfiguredAlgos();
    }

    /**
     * Returns the identifier of the hash algorithm at the given index.
     * 
     * If the index does not point to a configured slot then the function
     * returns the value <code>EndSupportedHashes</code>.
     */
    public ZrtpConstants.SupportedHashes getHashAlgoAt(int index) {
        try {
            return hashes.getAlgoAt(index);
        } catch (IndexOutOfBoundsException e) {
            return null;
        }
    }

    /**
     * Returns Iterable for the hashes.
     * 
     * Use this in for-each loop such as
     * <code>for (ZrtpConstants.SupportedHashes sh: config.hashes()) {</code>
     * 
     * @return The hash Iterable.
     */
    public Iterable<ZrtpConstants.SupportedHashes> hashes() {
        return hashes;
    }

    /*
     * SymCipher configuration functions
     */
    /**
     * Add a symmetric cipher algorithm to configuration data.
     * 
     * Adds the specified cipher algorithm to the configuration data. If no free
     * configuration data slot is available the function does not add the
     * algorithm and return zero.
     * 
     * @param algo
     *            The identifier of the cipher algorithm to add.
     * @return Number of free cipher configuration data slots.
     */
    public int addSymCipherAlgo(ZrtpConstants.SupportedSymCiphers algo) {
        return symCiphers.addAlgo(algo);
    }

    /**
     * Remove a symmetric cipher algorithm from configuration data.
     * 
     * Removes the specified algorithm from cipher configuration data. If the
     * algorithm was not configured previously the function does not modify the
     * configuration data and return the number of free configuration data
     * slots.
     * 
     * If an application removes all algorithms then ZRTP does not include any
     * algorithm into the hello message and falls back to a predefined mandatory
     * algorithm. In this case AES 128.
     * 
     * @param algo
     *            The identifier of the cipher algorithm to remove.
     * @return Number of free cipher configuration slots.
     */
    public int removeSymCipherAlgo(ZrtpConstants.SupportedSymCiphers algo) {
        return symCiphers.removeAlgo(algo);
    }

    /**
     * Returns the number of configured symmetric cipher algorithms.
     * 
     * @return The number of configured cipher algorithms (used configuration
     *         data slots)
     */
    public int getNumConfiguredSymCiphers() {
        return symCiphers.getNumConfiguredAlgos();
    }

    /**
     * Returns the identifier of the symmetric cipher algorithm at the given
     * index.
     * 
     * If the index does not point to a configured slot then the function
     * returns the value <code>EndSupportedSymCiphers</code>.
     */
    public ZrtpConstants.SupportedSymCiphers getSymCipherAlgoAt(int index) {
        try {
            return symCiphers.getAlgoAt(index);
        } catch (IndexOutOfBoundsException e) {
            return null;
        }
    }

    /**
     * Returns Iterable for the symmetric ciphers.
     * 
     * Use this in for-each loop such as
     * <code>for (ZrtpConstants.SupportedHashes sh: config.symCiphers()) {</code>
     * 
     * @return The symCiphers Iterable.
     */
    public Iterable<ZrtpConstants.SupportedSymCiphers> symCiphers() {
        return symCiphers;
    }

    /*
     * Public key configuration functions
     */
    /**
     * Add a public key algorithm to configuration data.
     * 
     * Adds the specified public key algorithm to the configuration data. If no
     * free configuration data slot is available the function does not add the
     * algorithm and return zero.
     * 
     * If an application removes all algorithms then ZRTP does not include any
     * algorithm into the hello message and falls back to a predefined mandatory
     * algorithm. In this case DH 3072.
     * 
     * @param algo
     *            The identifier of the public key algorithm to add.
     * @return Number of free public key configuration data slots.
     */
    public int addPubKeyAlgo(ZrtpConstants.SupportedPubKeys algo) {
        return publicKeyAlgos.addAlgo(algo);
    }

    /**
     * Remove a public key algorithm from configuration data.
     * 
     * Removes the specified algorithm from public key configuration data. If
     * the algorithm was not configured previously the function does not modify
     * the configuration data and return the number of free configuration data
     * slots.
     * 
     * @param algo
     *            The identifier of the public key algorithm to remove.
     * @return Number of free public key configuration slots.
     */
    public int removePubKeyAlgo(ZrtpConstants.SupportedPubKeys algo) {
        return publicKeyAlgos.removeAlgo(algo);
    }

    /**
     * Returns the number of configured public key algorithms.
     * 
     * @return The number of configured public key algorithms (used
     *         configuration data slots)
     */
    public int getNumConfiguredPubKeys() {
        return publicKeyAlgos.getNumConfiguredAlgos();
    }

    /**
     * Returns the identifier of the public key algorithm at the given index.
     * 
     * If the index does not point to a configured slot then the function
     * returns the value <code>EndSupportedPubKeys</code>.
     */
    public ZrtpConstants.SupportedPubKeys getPubKeyAlgoAt(int index) {
        try {
            return publicKeyAlgos.getAlgoAt(index);
        } catch (IndexOutOfBoundsException e) {
            return null;
        }
    }

    /**
     * Returns Iterable for public key algorithms.
     * 
     * Use this in for-each loop such as
     * <code>for (ZrtpConstants.SupportedHashes sh: config.publicKeyAlgos()) {</code>
     * 
     * @return The publicKeyAlgos Iterable.
     */
    public Iterable<ZrtpConstants.SupportedPubKeys> publicKeyAlgos() {
        return publicKeyAlgos;
    }


    /*
     * SAS type configuration functions
     */
    /**
     * Add a SAS type algorithm to configuration data.
     * 
     * Adds the specified SAS type algorithm to the configuration data. If no
     * free configuration data slot is available the function does not add the
     * algorithm and return zero.
     * 
     * @param algo
     *            The identifier of the SAS type algorithm to add.
     * @return Number of free SAS type configuration data slots.
     */
    public int addSasTypeAlgo(ZrtpConstants.SupportedSASTypes algo) {
        return sasTypes.addAlgo(algo);
    }

    /**
     * Remove a SAS type algorithm from configuration data.
     * 
     * Removes the specified algorithm from SAS type configuration data. If the
     * algorithm was not configured previously the function does not modify the
     * configuration data and return the number of free configuration data
     * slots.
     * 
     * If an application removes all algorithms then ZRTP does not include any
     * algorithm into the hello message and falls back to a predefined mandatory
     * algorithm. In this case base 32.
     * 
     * @param algo
     *            The identifier of the SAS type algorithm to remove.
     * @return Number of free SAS type configuration slots.
     */
    public int removeSasTypeAlgo(ZrtpConstants.SupportedSASTypes algo) {
        return sasTypes.removeAlgo(algo);
    }

    /**
     * Returns the number of configured SAS type algorithms.
     * 
     * @return The number of configured SAS type algorithms (used configuration
     *         data slots)
     */
    public int getNumConfiguredSasTypes() {
        return sasTypes.getNumConfiguredAlgos();
    }

    /**
     * Returns the identifier of the SAS type algorithm at the given index.
     * 
     * If the index does not point to a configured slot then the function
     * returns the value <code>EndSupportedSASTypes</code>.
     */
    public ZrtpConstants.SupportedSASTypes getSasTypeAlgoAt(int index) {
        try {
            return sasTypes.getAlgoAt(index);
        } catch (IndexOutOfBoundsException e) {
            return null;
        }
    }

    /**
     * Returns Iterable for SAS algorithms.
     * 
     * Use this in for-each loop such as
     * <code>for (ZrtpConstants.SupportedHashes sh: config.sasTypes()) {</code>
     * 
     * @return The sasTypes Iterable.
     */
    public Iterable<ZrtpConstants.SupportedSASTypes> sasTypes() {
        return sasTypes;
    }

    /*
     * Authentication length configuration functions
     */
    /**
     * Add a SRTP authentication length to configuration data.
     * 
     * Adds the specified SRTP authentication length to the configuration data.
     * If no free configuration data slot is available the function does not add
     * the algorithm and return zero.
     * 
     * @param algo
     *            The identifier of the SRTP authentication length to add.
     * @return Number of free SRTP authentication length configuration data
     *         slots.
     */
    public int addAuthLength(ZrtpConstants.SupportedAuthLengths algo) {
        return authLengths.addAlgo(algo);
    }

    /**
     * Remove a SRTP authentication length from configuration data.
     * 
     * Removes the specified algorithm from SRTP authentication length
     * configuration data. If the algorithm was not configured previously the
     * function does not modify the configuration data and retursn the number of
     * free configuration data slots.
     * 
     * If an application removes all algorithms then ZRTP does not include any
     * algorithm into the hello message and falls back to a predefined mandatory
     * algorithm. In this case length 32.
     * 
     * @param algo
     *            The identifier of the SRTP authentication length to remove.
     * @return Number of free SRTP authentication length configuration slots.
     */
    public int removeAuthLength(ZrtpConstants.SupportedAuthLengths algo) {
        return authLengths.removeAlgo(algo);
    }

    /**
     * Returns the number of configured SRTP authentication lengths.
     * 
     * @return The number of configured SRTP authentication lengths (used
     *         configuration data slots)
     */
    public int getNumConfiguredAuthLengths() {
        return authLengths.getNumConfiguredAlgos();
    }

    /**
     * Returns the identifier of the SRTP authentication length at the given
     * index.
     * 
     * If the index does not point to a configured slot then the function
     * returns the value <code>EndSupportedAuthLength</code>.
     */
    public ZrtpConstants.SupportedAuthLengths getAuthLengthAt(int index) {
        try {
            return authLengths.getAlgoAt(index);
        } catch (IndexOutOfBoundsException e) {
            return null;
        }
    }

    /**
     * Returns Iterable for SRTP authentication lengths.
     * 
     * Use this in for-each loop such as
     * <code>for (ZrtpConstants.SupportedHashes sh: config.authLengths()) {</code>
     * 
     * @return The authLengths Iterable.
     */
    public Iterable<ZrtpConstants.SupportedAuthLengths> authLengths() {
        return authLengths;
    }

    
    /*
     * Some tests here
     */
/* ***
    public static void main(String argv[]) {
        ZrtpConfigure config = new ZrtpConfigure();

        config.addHashAlgo(ZrtpConstants.SupportedHashes.S256);

        System.out.println("hashes.size: " + config.getNumConfiguredHashes());

        for (ZrtpConstants.SupportedHashes sh : config.hashes()) {
            System.out.println("configured hash -- " + sh);
        }
        config.removeHashAlgo(ZrtpConstants.SupportedHashes.S256);
        System.out.println("hashes.size: " + config.getNumConfiguredHashes());
        System.out.println("configured hash: " + config.getHashAlgoAt(0));
        System.out.println("configured hash: " + config.getHashAlgoAt(1));
    }
*** */
}

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

    private class Data<T extends Enum<T>> implements Iterable<T> {
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

        int addAlgoAt(int index, T algo) {
            if (algos.size() >= maxNoOfAlgos) {
                return 0;
            }
            if (index >= maxNoOfAlgos) {
                return 0;
            }
            if (algos.contains(algo)) {
                return maxNoOfAlgos - algos.size();
            }
            algos.add(index, algo);
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
        
        boolean containsAlgo(T algo) {
            return algos.contains(algo);
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
    
    private boolean enableTrustedMitM = false;
    private boolean enableSasSignature = false;
    
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
        clear();
        hashes.addAlgo(ZrtpConstants.SupportedHashes.S256);

        symCiphers.addAlgo(ZrtpConstants.SupportedSymCiphers.AES3);
        symCiphers.addAlgo(ZrtpConstants.SupportedSymCiphers.AES1);

        publicKeyAlgos.addAlgo(ZrtpConstants.SupportedPubKeys.DH3K);
        publicKeyAlgos.addAlgo(ZrtpConstants.SupportedPubKeys.DH2K);
        publicKeyAlgos.addAlgo(ZrtpConstants.SupportedPubKeys.MULT);

        sasTypes.addAlgo(ZrtpConstants.SupportedSASTypes.B32);

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
        clear();
        hashes.addAlgo(ZrtpConstants.SupportedHashes.S256);

        symCiphers.addAlgo(ZrtpConstants.SupportedSymCiphers.AES1);

        publicKeyAlgos.addAlgo(ZrtpConstants.SupportedPubKeys.DH3K);
        publicKeyAlgos.addAlgo(ZrtpConstants.SupportedPubKeys.MULT);

        sasTypes.addAlgo(ZrtpConstants.SupportedSASTypes.B32);

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

    /**
     * Enables or disables trusted MitM processing.
     *
     * For further details of trusted MitM processing refer to ZRTP
     * specification, chapter 7.3
     * 
     * @param yesNo
     *    If set to true then trusted MitM processing is enabled.
     */
    public void setTrustedMitM(boolean yesNo) {
        enableTrustedMitM = yesNo;
    }
    
    /**
     * Check status of trusted MitM processing.
     * 
     * @return
     *    Returns true if trusted MitM processing is enabled.
     */
    public boolean isTrustedMitM() {
        return enableTrustedMitM;
    }
    
    /**
     * Enables or disables SAS signature processing.
     * 
     * For further details of trusted MitM processing refer to ZRTP
     * specification, chapter 7.2
     *
     * @param yesNo
     *    If set to true then certificate processing is enabled.
     */
    public void setSasSignature(boolean yesNo) {
        enableSasSignature = yesNo;
    }
    
    /**
     * Check status of SAS signature processing.
     * 
     * @return
     *    Returns true if certificate processing is enabled.
     */
    public boolean isSasSignature() {
        return enableSasSignature;
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
     * Add a hash algorithm to configuration data at defined poisition.
     * 
     * Adds the specified hash algorithm to the configuration data. 
     * 
     * @param algo
     *            The identifier of the hash algorithm to add.
     * @param index
     *            The index into the configuration data
     * @return Number of free hash configuration data slots.
     */
    public int addHashAlgoAt(int index, ZrtpConstants.SupportedHashes algo) {
        return hashes.addAlgoAt(index, algo);
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

    /**
     * Check if ZrtpConfigure contains a hash algorithm.
     * 
     * @return True if ZrtpConfigure contains the algorithm.
     */
    public boolean containsHashAlgo(ZrtpConstants.SupportedHashes hash) {
            return hashes.containsAlgo(hash);
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
     * Add a symmetric cipher algorithm to configuration data.
     * 
     * Adds the specified cipher algorithm to the configuration data. 
     * 
     * @param algo
     *            The identifier of the cipher algorithm to add.
     * @param index
     *            The index into the configuration data
     * @return Number of free cipher configuration data slots.
     */
    public int addSymCipherAlgoAt(int index, ZrtpConstants.SupportedSymCiphers algo) {
        return symCiphers.addAlgoAt(index, algo);
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

    /**
     * Check if ZrtpConfigure contains a cipher algorithm.
     * 
     * @return True if ZrtpConfigure contains the algorithm.
     */
    public boolean containsCipherAlgo(ZrtpConstants.SupportedSymCiphers cipher) {
            return symCiphers.containsAlgo(cipher);
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
     * @param algo
     *            The identifier of the public key algorithm to add.
     * @return Number of free public key configuration data slots.
     */
    public int addPubKeyAlgo(ZrtpConstants.SupportedPubKeys algo) {
        return publicKeyAlgos.addAlgo(algo);
    }

    /**
     * Add a public key algorithm to configuration data.
     * 
     * Adds the specified public key algorithm to the configuration data. 
     * 
     * @param algo
     *            The identifier of the public key algorithm to add.
     * @param index
     *            The index into the configuration data
     * @return Number of free public key configuration data slots.
     */
    public int addPubKeyAlgoAt(int index, ZrtpConstants.SupportedPubKeys algo) {
        return publicKeyAlgos.addAlgoAt(index, algo);
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

    /**
     * Check if ZrtpConfigure contains a Public key algorithm.
     * 
     * @return True if ZrtpConfigure contains the algorithm.
     */
    public boolean containsPubKeyAlgo(ZrtpConstants.SupportedPubKeys pubkey) {
            return publicKeyAlgos.containsAlgo(pubkey);
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
     * Add a SAS type algorithm to configuration data.
     * 
     * Adds the specified SAS type algorithm to the configuration data. 
     * 
     * @param algo
     *            The identifier of the SAS type algorithm to add.
     * @param index
     *            The index into the configuration data
      * @return Number of free SAS type configuration data slots.
     */
    public int addSasTypeAlgoAt(int index, ZrtpConstants.SupportedSASTypes algo) {
        return sasTypes.addAlgoAt(index, algo);
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

    /**
     * Check if ZrtpConfigure contains a SAS algorithm.
     * 
     * @return True if ZrtpConfigure contains the algorithm.
     */
    public boolean containsSasTypeAlgo(ZrtpConstants.SupportedSASTypes sas) {
            return sasTypes.containsAlgo(sas);
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
     * Add a SRTP authentication length to configuration data.
     * 
     * Adds the specified SRTP authentication length to the configuration data.
     * If no free configuration data slot is available the function does not add
     * the algorithm and return zero.
     * 
     * @param algo
     *            The identifier of the SRTP authentication length to add.
     * @param index
     *            The index into the configuration data
     * @return Number of free SRTP authentication length configuration data
     *         slots.
     */
    public int addAuthLengthAt(int index, ZrtpConstants.SupportedAuthLengths algo) {
        return authLengths.addAlgoAt(index, algo);
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

    /**
     * Check if ZrtpConfigure contains a Auth lengths.
     * 
     * @return True if ZrtpConfigure contains the algorithm.
     */
    public boolean containsAuthLength(ZrtpConstants.SupportedAuthLengths length) {
            return authLengths.containsAlgo(length);
    }
       
    /*
     * Generic configuration functions
     * 
     * TODO: Code workarounds because of javac bug
     * http://bugs.sun.com/bugdatabase/view_bug.do?bug_id=6548436
     * Normally a simple cast is OK (Eclipse compiler handles it correctly) but
     * because of the javac bug we need to do the more complex way according to
     * a comment at the bug description. 
     */
    /**
     * Add an algorithm to configuration data.
     * 
     * Adds an length to the configuration data. The function determines which
     * table to access based on the declaring class of the parameter.
     * 
     * If no free configuration data slot is available the function does not add
     * the algorithm and return zero.
     * 
     * @param algo
     *            The identifier of the algorithm to add.
     * @return Number of free SRTP authentication length configuration data
     *         slots.
     */
    public <T extends Enum<T>>int addAlgo(T algo) {
        Class<T> clazz = algo.getDeclaringClass();
        if (clazz.equals(ZrtpConstants.SupportedHashes.class)) {
        //    return hashes.addAlgo((ZrtpConstants.SupportedHashes)algo);
            return hashes.addAlgo(ZrtpConstants.SupportedHashes.class.cast(algo));
        }
        if (clazz.equals(ZrtpConstants.SupportedSymCiphers.class)) {
            return symCiphers.addAlgo(ZrtpConstants.SupportedSymCiphers.class.cast(algo));
        }
        if (clazz.equals(ZrtpConstants.SupportedPubKeys.class)) {
            return publicKeyAlgos.addAlgo(ZrtpConstants.SupportedPubKeys.class.cast(algo));
        }
        if (clazz.equals(ZrtpConstants.SupportedSASTypes.class)) {
            return sasTypes.addAlgo(ZrtpConstants.SupportedSASTypes.class.cast(algo));
        }
        if (clazz.equals(ZrtpConstants.SupportedAuthLengths.class)) {
            return authLengths.addAlgo(ZrtpConstants.SupportedAuthLengths.class.cast(algo));
        }
        return -1;
    }

    /**
     * Add an algorithm to configuration data.
     * 
     * Adds an length to the configuration data. The function determines which
     * table to access based on the declaring class of the parameter.
     * 
     * If no free configuration data slot is available the function does not add
     * the algorithm and return zero.
     * 
     * @param algo
     *            The identifier of the algorithm to add.
     * @param index
     *            The index into the configuration data
     * @return Number of free algorithm configuration data
     *         slots.
     */
    public <T extends Enum<T>>int addAlgoAt(int index, T algo) {
        Class<T> clazz = algo.getDeclaringClass();
        if (clazz.equals(ZrtpConstants.SupportedHashes.class)) {
            return hashes.addAlgoAt(index, ZrtpConstants.SupportedHashes.class.cast(algo));
        }
        if (clazz.equals(ZrtpConstants.SupportedSymCiphers.class)) {
            return symCiphers.addAlgoAt(index, ZrtpConstants.SupportedSymCiphers.class.cast(algo));
        }
        if (clazz.equals(ZrtpConstants.SupportedPubKeys.class)) {
            return publicKeyAlgos.addAlgoAt(index, ZrtpConstants.SupportedPubKeys.class.cast(algo));
        }
        if (clazz.equals(ZrtpConstants.SupportedSASTypes.class)) {
            return sasTypes.addAlgoAt(index, ZrtpConstants.SupportedSASTypes.class.cast(algo));
        }
        if (clazz.equals(ZrtpConstants.SupportedAuthLengths.class)) {
            return authLengths.addAlgoAt(index, ZrtpConstants.SupportedAuthLengths.class.cast(algo));
        }
        return -1;
    }

    /**
     * Remove an algorithm from configuration data.
     * 
     * Removes an length to the configuration data. The function determines which
     * table to access based on the declaring class of the parameter.
     * 
     * If the algorithm was not configured previously the
     * function does not modify the configuration data and returns the number of
     * free configuration data slots.
     * 
     * If an application removes all algorithms then ZRTP does not include any
     * algorithm into the hello message and falls back to a predefined mandatory
     * algorithm. In this case length 32.
     * 
     * @param algo
     *            The identifier of the algorithm to remove.
     * @return Number of free algorithm configuration slots.
     */
    public <T extends Enum<T>>int removeAlgo(T algo) {
        Class<T> clazz = algo.getDeclaringClass();
        if (clazz.equals(ZrtpConstants.SupportedHashes.class)) {
            return hashes.removeAlgo(ZrtpConstants.SupportedHashes.class.cast(algo));
        }
        if (clazz.equals(ZrtpConstants.SupportedSymCiphers.class)) {
            return symCiphers.removeAlgo(ZrtpConstants.SupportedSymCiphers.class.cast(algo));
        }
        if (clazz.equals(ZrtpConstants.SupportedPubKeys.class)) {
            return publicKeyAlgos.removeAlgo(ZrtpConstants.SupportedPubKeys.class.cast(algo));
        }
        if (clazz.equals(ZrtpConstants.SupportedSASTypes.class)) {
            return sasTypes.removeAlgo(ZrtpConstants.SupportedSASTypes.class.cast(algo));
        }
        if (clazz.equals(ZrtpConstants.SupportedAuthLengths.class)) {
            return authLengths.removeAlgo(ZrtpConstants.SupportedAuthLengths.class.cast(algo));
        }
        return -1;
    }

    /**
     * Returns the number of configured algoritms.
     * 
     * The function determines which table to access based on the declaring class
     * of the parameter.
     * 
     * @param algo
     *            The identifier of the algorithm. Used only to identify 
     *            configure data.
     */
    public <T extends Enum<T>> int getNumConfiguredAlgos(T algo) {
        Class<T> clazz = algo.getDeclaringClass();
        if (clazz.equals(ZrtpConstants.SupportedHashes.class)) {
            return hashes.getNumConfiguredAlgos();
        }
        if (clazz.equals(ZrtpConstants.SupportedSymCiphers.class)) {
            return symCiphers.getNumConfiguredAlgos();
        }
        if (clazz.equals(ZrtpConstants.SupportedPubKeys.class)) {
            return publicKeyAlgos.getNumConfiguredAlgos();
        }
        if (clazz.equals(ZrtpConstants.SupportedSASTypes.class)) {
            return sasTypes.getNumConfiguredAlgos();
        }
        if (clazz.equals(ZrtpConstants.SupportedAuthLengths.class)) {
            return authLengths.getNumConfiguredAlgos();
        }
        return -1;
    }

    /**
     * Returns the identifier an algorithm at the given index.
     * 
     * The function determines which table to access based on the declaring class
     * of the parameter.
     * 
     * @param index
     *            The index into the configuration data.
     * @param algo
     *            The identifier of the algorithm to get. Used only to identify 
     *            configure data.
     * @return 
     *        If the index does not point to a configured slot then the function
     *        returns null, otherwise the algorithm at that index.
     */
    // @SuppressWarnings("unchecked")
    public <T extends Enum<T>> T getAlgoAt(int index, T algo) {
        Class<T> clazz = algo.getDeclaringClass();
        if (clazz.equals(ZrtpConstants.SupportedHashes.class)) {
            try {
            	// return (T)hashes.getAlgoAt(index);
                return clazz.cast(hashes.getAlgoAt(index));
            } catch (IndexOutOfBoundsException e) {
                return null;
            }
        }
        if (clazz.equals(ZrtpConstants.SupportedSymCiphers.class)) {
            try {
                return clazz.cast(symCiphers.getAlgoAt(index));
            } catch (IndexOutOfBoundsException e) {
                return null;
            }
        }
        if (clazz.equals(ZrtpConstants.SupportedPubKeys.class)) {
            try {
                return clazz.cast(publicKeyAlgos.getAlgoAt(index));
            } catch (IndexOutOfBoundsException e) {
                return null;
            }
        }
        if (clazz.equals(ZrtpConstants.SupportedSASTypes.class)) {
            try {
                return clazz.cast(sasTypes.getAlgoAt(index));
            } catch (IndexOutOfBoundsException e) {
                return null;
            }
        }
        if (clazz.equals(ZrtpConstants.SupportedAuthLengths.class)) {
            try {
                return clazz.cast(authLengths.getAlgoAt(index));
            } catch (IndexOutOfBoundsException e) {
                return null;
            }
        }
        return null;
    }

    /**
     * Returns Iterable for SRTP authentication lengths.
     * 
     * Use this in for-each loop such as
     * <code>for (ZrtpConstants.SupportedHashes sh: config.authLengths()) {</code>
     * 
     * @param algo
     *            The identifier of the algorithm to get.
     * @return The authLengths Iterable.
     */
    @SuppressWarnings("unchecked")
    public <T extends Enum<T>>Iterable<T> algos(T algo) {
        Class<T> clazz = algo.getDeclaringClass();
        if (clazz.equals(ZrtpConstants.SupportedHashes.class)) {
            // return (Iterable<T>)hashes;
        	return (Iterable)hashes;
        }
        if (clazz.equals(ZrtpConstants.SupportedSymCiphers.class)) {
            return (Iterable)symCiphers;
        }
        if (clazz.equals(ZrtpConstants.SupportedPubKeys.class)) {
            return (Iterable)publicKeyAlgos;
        }
        if (clazz.equals(ZrtpConstants.SupportedSASTypes.class)) {
            return (Iterable)sasTypes;
        }
        if (clazz.equals(ZrtpConstants.SupportedAuthLengths.class)) {
            return (Iterable)authLengths;
        }
        return null;
    }

    /**
     * Check if ZrtpConfigure contains an algorithm.
     * 
     * @return True if ZrtpConfigure contains the algorithm.
     */
    public <T extends Enum<T>>boolean containsAuthLength(T algo) {
        Class<T> clazz = algo.getDeclaringClass();
        if (clazz.equals(ZrtpConstants.SupportedHashes.class)) {
            return hashes.containsAlgo(ZrtpConstants.SupportedHashes.class.cast(algo));
        }
        if (clazz.equals(ZrtpConstants.SupportedSymCiphers.class)) {
            return symCiphers.containsAlgo(ZrtpConstants.SupportedSymCiphers.class.cast(algo));
        }
        if (clazz.equals(ZrtpConstants.SupportedPubKeys.class)) {
            return publicKeyAlgos.containsAlgo(ZrtpConstants.SupportedPubKeys.class.cast(algo));
        }
        if (clazz.equals(ZrtpConstants.SupportedSASTypes.class)) {
            return sasTypes.containsAlgo(ZrtpConstants.SupportedSASTypes.class.cast(algo));
        }
        if (clazz.equals(ZrtpConstants.SupportedAuthLengths.class)) {
            return authLengths.containsAlgo(ZrtpConstants.SupportedAuthLengths.class.cast(algo));
        }
        return false;
    }
       
    /*
     * Some tests here
     */
    
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

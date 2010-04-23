package gnu.java.zrtp.utils;

import org.bouncycastle.crypto.prng.FortunaGenerator;
import org.bouncycastle.crypto.prng.RandomGenerator;

/**
 * A Fortuna PRNG utility class to maintain a Fortuna generator singleton.
 * 
 * If several threads of an application require random data then this class
 * helps to increase the quality of the random data. This class implements the
 * BouncyCastle RandomNumber interface and the FortunaGenerator specific
 * methods.
 * <p>
 * This class manages a Fortuna PRNG generator instance and maintains access.
 * Thus all threads of an application can contribute entropy data to the same
 * Fortuna PRNG instance. The quality of random data enhances if an application
 * is able to add more entropy data.
 * <p>
 * If a thread requires random data it should use the methods of this class to
 * get high quality random data.
 * <p>
 * ZrtpFortuna always creates a Fortuna generator instance and initializes the
 * seed with some random data. An application may set another initialized
 * Fortuna instance using the <code>setFortuna()</code> method after calling
 * <code>getInstance()</code>. An application may use this feature to use a
 * Fortuna instance that was initialized with a saved seed (
 * {@link org.bouncycastle.crypto.prng.FortunaGenerator})
 * 
 */
public class ZrtpFortuna implements RandomGenerator {

	static private ZrtpFortuna singleInstance = null;
	private FortunaGenerator fortuna = null;

	protected ZrtpFortuna() {
	}

	synchronized static public ZrtpFortuna getInstance() {
		if (singleInstance == null) {
			singleInstance = new ZrtpFortuna();
			singleInstance.initialize();
		}
		return singleInstance;
	}

	private void initialize() {
		byte[] someData = new byte[256];
		new java.util.Random().nextBytes(someData);
		fortuna = new FortunaGenerator(someData);
	}

	/**
	 * Get the Fortuna instance.
	 * 
	 * @return The Fortuna instance.
	 */
	public FortunaGenerator getFortuna() {
		return fortuna;
	}

	/**
	 * Set the Fortuna instance.
	 * 
	 * @param fortuna
	 *            The Fortuna instance to use.
	 */
	synchronized public void setFortuna(FortunaGenerator fortuna) {
		this.fortuna = fortuna;
	}

	/**
	 * Adds new random data (entropy) to a entropy pool.
	 * 
	 * This functions adds entropy data to the current pool. Fortuna uses 32
	 * pools to gather entropy. After the function added the entropy to the pool
	 * it increments the current pool number modulo 32.
	 * <p>
	 * Only if pool 0 (zero) got enough entropy (min. 64 bytes) then Fortuna
	 * uses the pools to perform a real re-seed. If an application uses this
	 * function to add entropy it shall take this behaviour into consideration.
	 * 
	 * @param entropy
	 *            with new entropy data. If the current pool is 0 then the
	 *            function adds the length of the buffer to the overall entropy
	 *            count that controls re-seed.
	 */
	synchronized public void addSeedMaterial(byte[] entropy) {
		fortuna.addSeedMaterial(entropy);
	}

	/**
	 * Adds new random data (entropy) to a entropy pool.
	 * 
	 * This functions adds entropy data to the current pool. Fortuna uses 32
	 * pools to gather entropy. After the function added the entropy to the pool
	 * it increments the current pool number modulo 32.
	 * <p>
	 * Only if pool 0 (zero) got enough entropy (min. 64 bytes) then Fortuna
	 * uses the pools to perform a real re-seed. If an application uses this
	 * function to add entropy it shall take this behaviour into consideration.
	 * 
	 * @param entropy
	 *            a long with new entropy data. If the current pool is 0 then
	 *            the function adds the length of a long to the overall entropy
	 *            count that controls re-seed.
	 */
	synchronized public void addSeedMaterial(long entropy) {
		fortuna.addSeedMaterial(entropy);
	}

	/**
	 * Adds new random data (entropy) to a entropy pool.
	 * 
	 * This functions adds entropy data to the current pool. Fortuna uses 32
	 * pools to gather entropy. After the function added the entropy to the pool
	 * it increments the current pool number modulo 32.
	 * <p>
	 * Only if pool 0 (zero) got enough entropy (min. 64 bytes) then Fortuna
	 * uses the pools to perform a real re-seed. If an application uses this
	 * function to add entropy it shall take this behaviour into consideration.
	 * 
	 * @param entropy
	 *            buffer with new entropy data.
	 * @param offset
	 *            offset into the buffer
	 * @param length
	 *            number of bytes to add to the current pool's entropy. If the
	 *            current pool is 0 then the function adds the length of the
	 *            entropy to the overall entropy count that controls re-seed.
	 */
	synchronized public void addSeedMaterial(byte[] entropy, int offset, int length) {
		fortuna.addSeedMaterial(entropy, offset, length);
	}

	/**
	 * Adds new random data (entropy) to the specified entropy pool.
	 * 
	 * This functions adds entropy data to the the specified pool. Fortuna
	 * uses32 pools to gather entropy.
	 * <p>
	 * Only if pool 0 (zero) got enough entropy (min. 64 bytes) then Fortuna
	 * uses the pools to perform a real re-seed. If an application uses this
	 * function to add entropy it shall take this behaviour into consideration.
	 * 
	 * @param poolNumber
	 *            specifies which pool receives the entropy data
	 * @param entropy
	 *            buffer with new entropy data.
	 * @param offset
	 *            offset into the buffer
	 * @param length
	 *            number of bytes to add to the specified pool's entropy. If the
	 *            specified pool is 0 then the function adds the length of the
	 *            entropy to the overall entropy count that controls re-seed.
	 */
	synchronized public void addSeedMaterial(int poolNumber, byte[] entropy,
			int offset, int length) {
		fortuna.addSeedMaterial(poolNumber, entropy, offset, length);
	}

	/**
	 * Get new random data.
	 * 
	 * This functions fills a byte buffer with new random data.
	 * 
	 * @param randomData
	 *            the buffer that receives the random data
	 */
	synchronized public void nextBytes(byte[] randomData) {
		fortuna.nextBytes(randomData);
	}

	/**
	 * Get new random data.
	 * 
	 * This functions returns new random data.
	 * 
	 * @param randomData
	 *            the buffer that receives the random data
	 * @param offset
	 *            offset into the buffer
	 * @param length
	 *            number of random bytes
	 */
	synchronized public void nextBytes(byte[] randomData, int offset, int length) {
		fortuna.nextBytes(randomData, offset, length);
	}
}

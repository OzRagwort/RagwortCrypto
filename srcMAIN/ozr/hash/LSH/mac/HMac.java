package ozr.hash.LSH.mac;

import java.util.Arrays;

import ozr.hash.LSH.Hash;
import ozr.hash.LSH.Mac;

/**
 * HMAC κ΅¬ν
 */
public class HMac extends Mac {

	private static final byte IPAD = 0x36;
	private static final byte OPAD = 0x5c;

	private int blocksize;
	private Hash digest;

	private byte[] i_key_pad;
	private byte[] o_key_pad;

	/**
	 * ??±?
	 * 
	 * @param md
	 *            MessageDigest κ°μ²΄
	 */
	public HMac(Hash md) {
		if (md == null) {
			throw new IllegalArgumentException("md should not be null");
		}

		digest = md.newInstance();
		blocksize = digest.getBlockSize();

		i_key_pad = new byte[blocksize];
		o_key_pad = new byte[blocksize];
	}

	/**
	 * ?΄λΆ? ?? μ΄κΈ°?
	 * 
	 * @param key
	 *            λΉλ??€
	 */
	public void init(byte[] key) {

		if (key == null) {
			throw new IllegalArgumentException("key should not be null");
		}

		if (key.length > blocksize) {
			digest.reset();
			key = digest.doFinal(key);
		}

		Arrays.fill(i_key_pad, IPAD);
		Arrays.fill(o_key_pad, OPAD);
		for (int i = 0; i < key.length; ++i) {
			i_key_pad[i] ^= (byte) (key[i]);
			o_key_pad[i] ^= (byte) (key[i]);
		}

		reset();
	}

	/**
	 * ?΄? ?¨?λ₯? μ΄κΈ°??κ³? i_key_pad λ₯? hash ?¨?? ?£?΄??€
	 */
	public void reset() {
		digest.reset();
		digest.update(i_key_pad);
	}

	/**
	 * MAC? κ³μ°?  λ©μμ§?λ₯? hash ?¨?? ?£??€
	 */
	public void update(byte[] msg) {
		if (msg == null) {
			return;
		}

		digest.update(msg);
	}

	/**
	 * H(i_key_pad || msg) λ₯? κ³μ°?κ³?, H(o_key_pad || H(i_key_pad || msg)) λ₯? κ³μ°??€.
	 */
	public byte[] doFinal() {
		byte[] result = digest.doFinal();
		digest.reset();
		digest.update(o_key_pad);
		result = digest.doFinal(result);

		reset();
		return result;
	}

	public static byte[] digest(Hash.Algorithm algorithm, byte[] key, byte[] msg) {
		Hash hash = Hash.getInstance(algorithm);
		HMac hmac = new HMac(hash);
		hmac.init(key);
		return hmac.doFinal(msg);
	}
}

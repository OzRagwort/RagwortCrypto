package ozr.hash.LSH.mac;

import java.util.Arrays;

import ozr.hash.LSH.Hash;
import ozr.hash.LSH.Mac;

/**
 * HMAC êµ¬í˜„
 */
public class HMac extends Mac {

	private static final byte IPAD = 0x36;
	private static final byte OPAD = 0x5c;

	private int blocksize;
	private Hash digest;

	private byte[] i_key_pad;
	private byte[] o_key_pad;

	/**
	 * ?ƒ?„±?ž
	 * 
	 * @param md
	 *            MessageDigest ê°ì²´
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
	 * ?‚´ë¶? ?ƒ?ƒœ ì´ˆê¸°?™”
	 * 
	 * @param key
	 *            ë¹„ë??‚¤
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
	 * ?•´?‹œ ?•¨?ˆ˜ë¥? ì´ˆê¸°?™”?•˜ê³? i_key_pad ë¥? hash ?•¨?ˆ˜?— ?„£?–´?‘”?‹¤
	 */
	public void reset() {
		digest.reset();
		digest.update(i_key_pad);
	}

	/**
	 * MAC?„ ê³„ì‚°?•  ë©”ì‹œì§?ë¥? hash ?•¨?ˆ˜?— ?„£?Š”?‹¤
	 */
	public void update(byte[] msg) {
		if (msg == null) {
			return;
		}

		digest.update(msg);
	}

	/**
	 * H(i_key_pad || msg) ë¥? ê³„ì‚°?•˜ê³?, H(o_key_pad || H(i_key_pad || msg)) ë¥? ê³„ì‚°?•œ?‹¤.
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

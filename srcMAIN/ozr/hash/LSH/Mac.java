package ozr.hash.LSH;

import ozr.hash.LSH.mac.HMac;

/**
 * MAC κ΅¬ν? ?? ?Έ?°??΄?€
 */
public abstract class Mac {

	/**
	 * μ΄κΈ°? ?¨?
	 * 
	 * @param key
	 *            λΉλ??€
	 */
	public abstract void init(byte[] key);

	/**
	 * ?λ‘μ΄ λ©μμ§?? ??? MAC κ³μ°? ?? κ°μ²΄ μ΄κΈ°?
	 */
	public abstract void reset();

	/**
	 * λ©μμ§? μΆκ?
	 * 
	 * @param msg
	 *            μΆκ??  λ©μμ§?
	 */
	public abstract void update(byte[] msg);

	/**
	 * ??¬κΉμ? μΆκ?? λ©μμ§?? ??? MAC κ³μ°
	 * 
	 * @return MAC κ°?
	 */
	public abstract byte[] doFinal();

	/**
	 * λ§μ?λ§? λ©μμ§?λ₯? ?¬?¨??¬ MAC κ³μ°
	 * 
	 * @param msg
	 *            λ§μ?λ§? λ©μμ§?
	 * @return MAC κ°?
	 */
	public byte[] doFinal(byte[] msg) {
		update(msg);
		return doFinal();
	}

	/**
	 * MAC κ³μ°? ?? κ°μ²΄ ??±
	 * 
	 * @param algorithm
	 *            MessageDigest ?κ³ λ¦¬μ¦?
	 * @return Mac κ°μ²΄
	 */
	public static Mac getInstance(Hash.Algorithm algorithm) {
		Hash md = Hash.getInstance(algorithm);
		return new HMac(md);
	}

}

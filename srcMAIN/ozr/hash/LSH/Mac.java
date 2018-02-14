package ozr.hash.LSH;

import ozr.hash.LSH.mac.HMac;

/**
 * MAC 구현?�� ?��?�� ?��?��?��?��?��
 */
public abstract class Mac {

	/**
	 * 초기?�� ?��?��
	 * 
	 * @param key
	 *            비�??��
	 */
	public abstract void init(byte[] key);

	/**
	 * ?��로운 메시�??�� ???�� MAC 계산?�� ?��?�� 객체 초기?��
	 */
	public abstract void reset();

	/**
	 * 메시�? 추�?
	 * 
	 * @param msg
	 *            추�??�� 메시�?
	 */
	public abstract void update(byte[] msg);

	/**
	 * ?��?��까�? 추�??�� 메시�??�� ???�� MAC 계산
	 * 
	 * @return MAC �?
	 */
	public abstract byte[] doFinal();

	/**
	 * 마�?�? 메시�?�? ?��?��?��?�� MAC 계산
	 * 
	 * @param msg
	 *            마�?�? 메시�?
	 * @return MAC �?
	 */
	public byte[] doFinal(byte[] msg) {
		update(msg);
		return doFinal();
	}

	/**
	 * MAC 계산?�� ?��?�� 객체 ?��?��
	 * 
	 * @param algorithm
	 *            MessageDigest ?��고리�?
	 * @return Mac 객체
	 */
	public static Mac getInstance(Hash.Algorithm algorithm) {
		Hash md = Hash.getInstance(algorithm);
		return new HMac(md);
	}

}

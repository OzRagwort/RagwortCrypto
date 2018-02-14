package ozr.encryption.sym.LEA;

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
	 * 마�?�? 메시�?�? ?��?��?��?�� MAC 계산
	 * 
	 * @param msg
	 *            마�?�? 메시�?
	 * @return MAC �?
	 */
	public abstract byte[] doFinal(byte[] msg);

	/**
	 * ?��?��까�? 추�??�� 메시�??�� ???�� MAC 계산
	 * 
	 * @return MAC �?
	 */
	public abstract byte[] doFinal();

}

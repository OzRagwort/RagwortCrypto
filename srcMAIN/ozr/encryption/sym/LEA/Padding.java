package ozr.encryption.sym.LEA;

/**
 * ?��?�� 구현?�� ?��?�� ?��?��?��?��?��
 */
public abstract class Padding {

	protected int blocksize;

	public Padding(int blocksize) {
		this.blocksize = blocksize;
	}

	/**
	 * ?��?�� 추�?
	 * 
	 * @param in
	 *            ?��?��?�� 추�??�� 메시�?, 길이�? 블록?��?��즈보?�� 같거?�� ?��?��?�� ?��
	 */
	public abstract byte[] pad(byte[] in);

	/**
	 * ?��?�� 추�?
	 * 
	 * @param in
	 *            ?��?��?�� 추�??�� 메시�?�? ?��?��?�� 배열, 배열 ?��체의 길이?�� 블록?��?�� 블록?��?��즈�? 같아?�� ?��
	 * @param inOff
	 *            메시�? 길이
	 */
	public abstract void pad(byte[] in, int inOff);

	/**
	 * ?��?�� ?���?
	 * 
	 * @param in
	 *            ?��?��?�� ?��거할 메시�?
	 * @return ?��?��?�� ?��거된 메시�?
	 */
	public abstract byte[] unpad(byte[] in);

	/**
	 * ?��?�� 길이 계산
	 * 
	 * @param in
	 *            ?��?��?�� ?��?��?�� 메시�?
	 * @return ?��?��?�� 길이
	 */
	public abstract int getPadCount(byte[] in);

}

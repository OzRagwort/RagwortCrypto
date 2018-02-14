package ozr.encryption.sym.LEA;

/**
 * 블록?��?�� ?��블록 ?��/복호?�� 구현?�� ?��?�� ?��?��?��?��?��
 */
public abstract class BlockCipher {

	public enum Mode {
		/** ?��?��?�� 모드 */
		ENCRYPT,
		/** 복호?�� 모드 */
		DECRYPT
	}

	/**
	 * 초기?�� ?��?��
	 * 
	 * @param mode
	 *            {@link BlockCipher.Mode}
	 * @param mk
	 *            ?��?��?�� ?��
	 */
	public abstract void init(Mode mode, byte[] mk);

	/**
	 * ?��로운 ?��?��?���? 처리?���? ?��?�� init?�� ?��?��?�� ?��?���? 복원
	 */
	public abstract void reset();

	/**
	 * ?��?��?�� ?��고리�? ?��름을 리턴
	 * 
	 * @return ?��고리�? ?���?
	 */
	public abstract String getAlgorithmName();

	/**
	 * ?��?��?�� ?��고리즘의 ?�� 블록 ?��기�?? 리턴
	 * 
	 * @return ?�� 블록 ?���?
	 */
	public abstract int getBlockSize();

	/**
	 * ?��블록 ?��?��?��
	 * 
	 * @param in
	 *            ?��?��
	 * @param inOff
	 *            ?��?�� ?��?�� ?���?
	 * @param out
	 *            출력
	 * @param outOff
	 *            출력 ?��?�� ?���?
	 * @return 처리?�� ?��?��?��?�� 길이
	 */
	public abstract int processBlock(byte[] in, int inOff, byte[] out, int outOff);
}

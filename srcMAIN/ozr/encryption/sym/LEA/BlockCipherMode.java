package ozr.encryption.sym.LEA;

/**
 * 블록?��?�� ?��?��모드 구현?�� ?��?�� ?��?��?��?��?��
 */
public abstract class BlockCipherMode {

	/**
	 * ?��?�� 객체�? 구현?���? ?��?�� ?��고리�? ?��름을 리턴
	 * 
	 * @return ?��고리�? ?��름을 "블록?��?��/?��?��모드" ?��?���? 리턴
	 */
	public abstract String getAlgorithmName();

	/**
	 * ?��?��?�� ???�� 출력 길이�? 계산
	 * 
	 * @param len
	 *            ?��?�� 길이
	 * @return len 만큼?�� ?��?��?�� 처리?���? ?��?�� ?��?��?�� 출력 길이
	 */
	public abstract int getOutputSize(int len);

	/**
	 * �?�? ?��?��?��?���? ?��?�� ?��?��?�� 출력?�� 길이 계산, 주로 블록?��기의 배수�? 계산?��
	 * 
	 * @param len
	 *            ?��?�� 길이
	 * @return len 만큼?�� ?��?��?�� 처리?���? ?��?�� ?��?��?�� 중간 출력 길이
	 */
	public abstract int getUpdateOutputSize(int len);

	/**
	 * IV�? ?��?���? ?���? ?��?�� ?��?��모드�? ?��?�� 초기?�� ?��?��
	 * 
	 * @param mode
	 *            {@link BlockCipher.Mode}
	 * @param mk
	 *            ?��?��?�� ?��
	 */
	public abstract void init(BlockCipher.Mode mode, byte[] mk);

	/**
	 * IV�? ?��?���? ?��?�� ?��?��모드�? ?��?�� 초기?�� ?��?��
	 * 
	 * @param mode
	 *            {@link BlockCipher.Mode}
	 * @param mk
	 *            ?��?��?�� ?��
	 * @param iv
	 *            초기?�� 벡터
	 */
	public abstract void init(BlockCipher.Mode mode, byte[] mk, byte[] iv);

	/**
	 * init?�� ?��료한 ?��?���? �?�?, ?�� 메시�?�? 처리?���? ?��?��
	 */
	public abstract void reset();

	/**
	 * PKCS7Padding ?��?�� ?���? ?��?��, 기본?��로는 ?��?��
	 * 
	 * @param padding
	 *            ?��?�� ?��고리�? 객체
	 */
	public abstract void setPadding(Padding padding);

	/**
	 * ?��?��?�� 모드�? ?��?�� ?��?��?��?�� ?��?��
	 * 
	 * @param msg
	 *            처리?�� 메시�? ?���?
	 * @return 처리?�� 메시�? ?���?
	 */
	public abstract byte[] update(byte[] msg);

	/**
	 * ?��/복호?�� 최종?���? ?��?��
	 * 
	 * @param msg
	 *            ?���?/?��?��문의 마�?�? �?�?
	 * @return ?��?���? ?��?? ?��문의 마�?�? �?�?
	 */
	public abstract byte[] doFinal(byte[] msg);

	/**
	 * ?��/복호?�� 최종?���? ?��?��
	 * 
	 * @return ?��?���? ?��?? ?��문의 마�?�? �?�?
	 */
	public abstract byte[] doFinal();

}

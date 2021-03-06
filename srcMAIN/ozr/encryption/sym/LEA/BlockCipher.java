package ozr.encryption.sym.LEA;

/**
 * λΈλ‘??Έ ?λΈλ‘ ?/λ³΅νΈ? κ΅¬ν? ?? ?Έ?°??΄?€
 */
public abstract class BlockCipher {

	public enum Mode {
		/** ??Έ? λͺ¨λ */
		ENCRYPT,
		/** λ³΅νΈ? λͺ¨λ */
		DECRYPT
	}

	/**
	 * μ΄κΈ°? ?¨?
	 * 
	 * @param mode
	 *            {@link BlockCipher.Mode}
	 * @param mk
	 *            ??Έ? ?€
	 */
	public abstract void init(Mode mode, byte[] mk);

	/**
	 * ?λ‘μ΄ ?°?΄?°λ₯? μ²λ¦¬?κΈ? ??΄ init? ??? ??λ‘? λ³΅μ
	 */
	public abstract void reset();

	/**
	 * ??Έ? ?κ³ λ¦¬μ¦? ?΄λ¦μ λ¦¬ν΄
	 * 
	 * @return ?κ³ λ¦¬μ¦? ?΄λ¦?
	 */
	public abstract String getAlgorithmName();

	/**
	 * ??Έ? ?κ³ λ¦¬μ¦μ ? λΈλ‘ ?¬κΈ°λ?? λ¦¬ν΄
	 * 
	 * @return ? λΈλ‘ ?¬κΈ?
	 */
	public abstract int getBlockSize();

	/**
	 * ?λΈλ‘ ??Έ?
	 * 
	 * @param in
	 *            ?? ₯
	 * @param inOff
	 *            ?? ₯ ?? ?μΉ?
	 * @param out
	 *            μΆλ ₯
	 * @param outOff
	 *            μΆλ ₯ ?? ?μΉ?
	 * @return μ²λ¦¬? ?°?΄?°? κΈΈμ΄
	 */
	public abstract int processBlock(byte[] in, int inOff, byte[] out, int outOff);
}

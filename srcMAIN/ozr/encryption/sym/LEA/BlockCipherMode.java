package ozr.encryption.sym.LEA;

/**
 * λΈλ‘??Έ ?΄?©λͺ¨λ κ΅¬ν? ?? ?Έ?°??΄?€
 */
public abstract class BlockCipherMode {

	/**
	 * ??¬ κ°μ²΄κ°? κ΅¬ν?κ³? ?? ?κ³ λ¦¬μ¦? ?΄λ¦μ λ¦¬ν΄
	 * 
	 * @return ?κ³ λ¦¬μ¦? ?΄λ¦μ "λΈλ‘??Έ/?΄?©λͺ¨λ" ??λ‘? λ¦¬ν΄
	 */
	public abstract String getAlgorithmName();

	/**
	 * ?? ₯? ??? μΆλ ₯ κΈΈμ΄λ₯? κ³μ°
	 * 
	 * @param len
	 *            ?? ₯ κΈΈμ΄
	 * @return len λ§νΌ? ?? ₯? μ²λ¦¬?κΈ? ??΄ ??? μΆλ ₯ κΈΈμ΄
	 */
	public abstract int getOutputSize(int len);

	/**
	 * λΆ?λΆ? ??°?΄?Έλ₯? ??΄ ??? μΆλ ₯? κΈΈμ΄ κ³μ°, μ£Όλ‘ λΈλ‘?¬κΈ°μ λ°°μλ‘? κ³μ°?¨
	 * 
	 * @param len
	 *            ?? ₯ κΈΈμ΄
	 * @return len λ§νΌ? ?? ₯? μ²λ¦¬?κΈ? ??΄ ??? μ€κ° μΆλ ₯ κΈΈμ΄
	 */
	public abstract int getUpdateOutputSize(int len);

	/**
	 * IVλ₯? ??λ‘? ?μ§? ?? ?΄?©λͺ¨λλ₯? ?? μ΄κΈ°? ?¨?
	 * 
	 * @param mode
	 *            {@link BlockCipher.Mode}
	 * @param mk
	 *            ??Έ? ?€
	 */
	public abstract void init(BlockCipher.Mode mode, byte[] mk);

	/**
	 * IVλ₯? ??λ‘? ?? ?΄?©λͺ¨λλ₯? ?? μ΄κΈ°? ?¨?
	 * 
	 * @param mode
	 *            {@link BlockCipher.Mode}
	 * @param mk
	 *            ??Έ? ?€
	 * @param iv
	 *            μ΄κΈ°? λ²‘ν°
	 */
	public abstract void init(BlockCipher.Mode mode, byte[] mk, byte[] iv);

	/**
	 * init? ?λ£ν ??λ‘? λ³?κ²?, ? λ©μμ§?λ₯? μ²λ¦¬?κΈ? ??¨
	 */
	public abstract void reset();

	/**
	 * PKCS7Padding ?¬?© ?¬λΆ? ?€? , κΈ°λ³Έ?Όλ‘λ ?¬?©
	 * 
	 * @param padding
	 *            ?¨?© ?κ³ λ¦¬μ¦? κ°μ²΄
	 */
	public abstract void setPadding(Padding padding);

	/**
	 * ?¨?Ό?Έ λͺ¨λλ₯? ?? ??°?΄?Έ ?¨?
	 * 
	 * @param msg
	 *            μ²λ¦¬?  λ©μμ§? ?ΌλΆ?
	 * @return μ²λ¦¬? λ©μμ§? ?ΌλΆ?
	 */
	public abstract byte[] update(byte[] msg);

	/**
	 * ?/λ³΅νΈ? μ΅μ’?¨κ³? ??
	 * 
	 * @param msg
	 *            ?λ¬?/??Έλ¬Έμ λ§μ?λ§? λΆ?λΆ?
	 * @return ??Έλ¬? ?Ή?? ?λ¬Έμ λ§μ?λ§? λΆ?λΆ?
	 */
	public abstract byte[] doFinal(byte[] msg);

	/**
	 * ?/λ³΅νΈ? μ΅μ’?¨κ³? ??
	 * 
	 * @return ??Έλ¬? ?Ή?? ?λ¬Έμ λ§μ?λ§? λΆ?λΆ?
	 */
	public abstract byte[] doFinal();

}

package ozr.encryption.sym.LEA;

/**
 * ë¸”ë¡?•”?˜¸ ?š´?š©ëª¨ë“œ êµ¬í˜„?„ ?œ„?•œ ?¸?„°?˜?´?Š¤
 */
public abstract class BlockCipherMode {

	/**
	 * ?˜„?¬ ê°ì²´ê°? êµ¬í˜„?•˜ê³? ?ˆ?Š” ?•Œê³ ë¦¬ì¦? ?´ë¦„ì„ ë¦¬í„´
	 * 
	 * @return ?•Œê³ ë¦¬ì¦? ?´ë¦„ì„ "ë¸”ë¡?•”?˜¸/?š´?š©ëª¨ë“œ" ?˜•?ƒœë¡? ë¦¬í„´
	 */
	public abstract String getAlgorithmName();

	/**
	 * ?…? ¥?— ???•œ ì¶œë ¥ ê¸¸ì´ë¥? ê³„ì‚°
	 * 
	 * @param len
	 *            ?…? ¥ ê¸¸ì´
	 * @return len ë§Œí¼?˜ ?…? ¥?„ ì²˜ë¦¬?•˜ê¸? ?œ„?•´ ?•„?š”?•œ ì¶œë ¥ ê¸¸ì´
	 */
	public abstract int getOutputSize(int len);

	/**
	 * ë¶?ë¶? ?—…?°?´?Š¸ë¥? ?œ„?•´ ?•„?š”?•œ ì¶œë ¥?˜ ê¸¸ì´ ê³„ì‚°, ì£¼ë¡œ ë¸”ë¡?¬ê¸°ì˜ ë°°ìˆ˜ë¡? ê³„ì‚°?¨
	 * 
	 * @param len
	 *            ?…? ¥ ê¸¸ì´
	 * @return len ë§Œí¼?˜ ?…? ¥?„ ì²˜ë¦¬?•˜ê¸? ?œ„?•´ ?•„?š”?•œ ì¤‘ê°„ ì¶œë ¥ ê¸¸ì´
	 */
	public abstract int getUpdateOutputSize(int len);

	/**
	 * IVë¥? ?•„?š”ë¡? ?•˜ì§? ?•Š?Š” ?š´?š©ëª¨ë“œë¥? ?œ„?•œ ì´ˆê¸°?™” ?•¨?ˆ˜
	 * 
	 * @param mode
	 *            {@link BlockCipher.Mode}
	 * @param mk
	 *            ?•”?˜¸?™” ?‚¤
	 */
	public abstract void init(BlockCipher.Mode mode, byte[] mk);

	/**
	 * IVë¥? ?•„?š”ë¡? ?•˜?Š” ?š´?š©ëª¨ë“œë¥? ?œ„?•œ ì´ˆê¸°?™” ?•¨?ˆ˜
	 * 
	 * @param mode
	 *            {@link BlockCipher.Mode}
	 * @param mk
	 *            ?•”?˜¸?™” ?‚¤
	 * @param iv
	 *            ì´ˆê¸°?™” ë²¡í„°
	 */
	public abstract void init(BlockCipher.Mode mode, byte[] mk, byte[] iv);

	/**
	 * init?„ ?™„ë£Œí•œ ?ƒ?ƒœë¡? ë³?ê²?, ?ƒˆ ë©”ì‹œì§?ë¥? ì²˜ë¦¬?•˜ê¸? ?œ„?•¨
	 */
	public abstract void reset();

	/**
	 * PKCS7Padding ?‚¬?š© ?—¬ë¶? ?„¤? •, ê¸°ë³¸?œ¼ë¡œëŠ” ?‚¬?š©
	 * 
	 * @param padding
	 *            ?Œ¨?”© ?•Œê³ ë¦¬ì¦? ê°ì²´
	 */
	public abstract void setPadding(Padding padding);

	/**
	 * ?˜¨?¼?¸ ëª¨ë“œë¥? ?œ„?•œ ?—…?°?´?Š¸ ?•¨?ˆ˜
	 * 
	 * @param msg
	 *            ì²˜ë¦¬?•  ë©”ì‹œì§? ?¼ë¶?
	 * @return ì²˜ë¦¬?œ ë©”ì‹œì§? ?¼ë¶?
	 */
	public abstract byte[] update(byte[] msg);

	/**
	 * ?•”/ë³µí˜¸?™” ìµœì¢…?‹¨ê³? ?ˆ˜?–‰
	 * 
	 * @param msg
	 *            ?‰ë¬?/?•”?˜¸ë¬¸ì˜ ë§ˆì?ë§? ë¶?ë¶?
	 * @return ?•”?˜¸ë¬? ?˜¹?? ?‰ë¬¸ì˜ ë§ˆì?ë§? ë¶?ë¶?
	 */
	public abstract byte[] doFinal(byte[] msg);

	/**
	 * ?•”/ë³µí˜¸?™” ìµœì¢…?‹¨ê³? ?ˆ˜?–‰
	 * 
	 * @return ?•”?˜¸ë¬? ?˜¹?? ?‰ë¬¸ì˜ ë§ˆì?ë§? ë¶?ë¶?
	 */
	public abstract byte[] doFinal();

}

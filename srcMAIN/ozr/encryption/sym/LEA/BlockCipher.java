package ozr.encryption.sym.LEA;

/**
 * ë¸”ë¡?•”?˜¸ ?•œë¸”ë¡ ?•”/ë³µí˜¸?™” êµ¬í˜„?„ ?œ„?•œ ?¸?„°?˜?´?Š¤
 */
public abstract class BlockCipher {

	public enum Mode {
		/** ?•”?˜¸?™” ëª¨ë“œ */
		ENCRYPT,
		/** ë³µí˜¸?™” ëª¨ë“œ */
		DECRYPT
	}

	/**
	 * ì´ˆê¸°?™” ?•¨?ˆ˜
	 * 
	 * @param mode
	 *            {@link BlockCipher.Mode}
	 * @param mk
	 *            ?•”?˜¸?™” ?‚¤
	 */
	public abstract void init(Mode mode, byte[] mk);

	/**
	 * ?ƒˆë¡œìš´ ?°?´?„°ë¥? ì²˜ë¦¬?•˜ê¸? ?œ„?•´ init?„ ?ˆ˜?–‰?•œ ?ƒ?ƒœë¡? ë³µì›
	 */
	public abstract void reset();

	/**
	 * ?•”?˜¸?™” ?•Œê³ ë¦¬ì¦? ?´ë¦„ì„ ë¦¬í„´
	 * 
	 * @return ?•Œê³ ë¦¬ì¦? ?´ë¦?
	 */
	public abstract String getAlgorithmName();

	/**
	 * ?•”?˜¸?™” ?•Œê³ ë¦¬ì¦˜ì˜ ?•œ ë¸”ë¡ ?¬ê¸°ë?? ë¦¬í„´
	 * 
	 * @return ?•œ ë¸”ë¡ ?¬ê¸?
	 */
	public abstract int getBlockSize();

	/**
	 * ?•œë¸”ë¡ ?•”?˜¸?™”
	 * 
	 * @param in
	 *            ?…? ¥
	 * @param inOff
	 *            ?…? ¥ ?‹œ?‘ ?œ„ì¹?
	 * @param out
	 *            ì¶œë ¥
	 * @param outOff
	 *            ì¶œë ¥ ?‹œ?‘ ?œ„ì¹?
	 * @return ì²˜ë¦¬?•œ ?°?´?„°?˜ ê¸¸ì´
	 */
	public abstract int processBlock(byte[] in, int inOff, byte[] out, int outOff);
}

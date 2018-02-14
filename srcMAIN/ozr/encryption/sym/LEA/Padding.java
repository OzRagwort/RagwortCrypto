package ozr.encryption.sym.LEA;

/**
 * ?Œ¨?”© êµ¬í˜„?„ ?œ„?•œ ?¸?„°?˜?´?Š¤
 */
public abstract class Padding {

	protected int blocksize;

	public Padding(int blocksize) {
		this.blocksize = blocksize;
	}

	/**
	 * ?Œ¨?”© ì¶”ê?
	 * 
	 * @param in
	 *            ?Œ¨?”©?„ ì¶”ê??•  ë©”ì‹œì§?, ê¸¸ì´ê°? ë¸”ë¡?‚¬?´ì¦ˆë³´?‹¤ ê°™ê±°?‚˜ ?‘?•„?•¼ ?•¨
	 */
	public abstract byte[] pad(byte[] in);

	/**
	 * ?Œ¨?”© ì¶”ê?
	 * 
	 * @param in
	 *            ?Œ¨?”©?„ ì¶”ê??•  ë©”ì‹œì§?ê°? ?¬?•¨?œ ë°°ì—´, ë°°ì—´ ? „ì²´ì˜ ê¸¸ì´?Š” ë¸”ë¡?•”?˜¸ ë¸”ë¡?‚¬?´ì¦ˆì? ê°™ì•„?•¼ ?•¨
	 * @param inOff
	 *            ë©”ì‹œì§? ê¸¸ì´
	 */
	public abstract void pad(byte[] in, int inOff);

	/**
	 * ?Œ¨?”© ? œê±?
	 * 
	 * @param in
	 *            ?Œ¨?”©?„ ? œê±°í•  ë©”ì‹œì§?
	 * @return ?Œ¨?”©?´ ? œê±°ëœ ë©”ì‹œì§?
	 */
	public abstract byte[] unpad(byte[] in);

	/**
	 * ?Œ¨?”© ê¸¸ì´ ê³„ì‚°
	 * 
	 * @param in
	 *            ?Œ¨?”©?´ ?¬?•¨?œ ë©”ì‹œì§?
	 * @return ?Œ¨?”©?˜ ê¸¸ì´
	 */
	public abstract int getPadCount(byte[] in);

}

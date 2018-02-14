package ozr.encryption.sym.LEA;

/**
 * MAC êµ¬í˜„?„ ?œ„?•œ ?¸?„°?˜?´?Š¤
 */
public abstract class Mac {

	/**
	 * ì´ˆê¸°?™” ?•¨?ˆ˜
	 * 
	 * @param key
	 *            ë¹„ë??‚¤
	 */
	public abstract void init(byte[] key);

	/**
	 * ?ƒˆë¡œìš´ ë©”ì‹œì§??— ???•œ MAC ê³„ì‚°?„ ?œ„?•œ ê°ì²´ ì´ˆê¸°?™”
	 */
	public abstract void reset();

	/**
	 * ë©”ì‹œì§? ì¶”ê?
	 * 
	 * @param msg
	 *            ì¶”ê??•  ë©”ì‹œì§?
	 */
	public abstract void update(byte[] msg);

	/**
	 * ë§ˆì?ë§? ë©”ì‹œì§?ë¥? ?¬?•¨?•˜?—¬ MAC ê³„ì‚°
	 * 
	 * @param msg
	 *            ë§ˆì?ë§? ë©”ì‹œì§?
	 * @return MAC ê°?
	 */
	public abstract byte[] doFinal(byte[] msg);

	/**
	 * ?˜„?¬ê¹Œì? ì¶”ê??œ ë©”ì‹œì§??— ???•œ MAC ê³„ì‚°
	 * 
	 * @return MAC ê°?
	 */
	public abstract byte[] doFinal();

}

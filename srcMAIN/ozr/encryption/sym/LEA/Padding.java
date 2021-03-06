package ozr.encryption.sym.LEA;

/**
 * ?¨?© κ΅¬ν? ?? ?Έ?°??΄?€
 */
public abstract class Padding {

	protected int blocksize;

	public Padding(int blocksize) {
		this.blocksize = blocksize;
	}

	/**
	 * ?¨?© μΆκ?
	 * 
	 * @param in
	 *            ?¨?©? μΆκ??  λ©μμ§?, κΈΈμ΄κ°? λΈλ‘?¬?΄μ¦λ³΄?€ κ°κ±°? ???Ό ?¨
	 */
	public abstract byte[] pad(byte[] in);

	/**
	 * ?¨?© μΆκ?
	 * 
	 * @param in
	 *            ?¨?©? μΆκ??  λ©μμ§?κ°? ?¬?¨? λ°°μ΄, λ°°μ΄ ? μ²΄μ κΈΈμ΄? λΈλ‘??Έ λΈλ‘?¬?΄μ¦μ? κ°μ?Ό ?¨
	 * @param inOff
	 *            λ©μμ§? κΈΈμ΄
	 */
	public abstract void pad(byte[] in, int inOff);

	/**
	 * ?¨?© ? κ±?
	 * 
	 * @param in
	 *            ?¨?©? ? κ±°ν  λ©μμ§?
	 * @return ?¨?©?΄ ? κ±°λ λ©μμ§?
	 */
	public abstract byte[] unpad(byte[] in);

	/**
	 * ?¨?© κΈΈμ΄ κ³μ°
	 * 
	 * @param in
	 *            ?¨?©?΄ ?¬?¨? λ©μμ§?
	 * @return ?¨?©? κΈΈμ΄
	 */
	public abstract int getPadCount(byte[] in);

}

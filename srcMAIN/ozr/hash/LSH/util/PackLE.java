package ozr.hash.LSH.util;

/**
 * λ°μ΄?Έ λ°°μ΄? λ¦¬ν? ??? ??? ? ?λ‘? λ³???κΈ? ?? ?κ΅?
 */
public class PackLE {

	/**
	 * λ°μ΄?Έ λ°°μ΄? unsigned integer λ‘? λ³??
	 * 
	 * @param in
	 *            λ³???  λ°μ΄?Έ λ°°μ΄
	 * @param offset
	 *            ?? ?€??
	 * @return
	 */
	public static int toU32(byte[] in, int offset) {

		int result = (in[offset] & 0xff);
		result |= (in[++offset] & 0xff) << 8;
		result |= (in[++offset] & 0xff) << 16;
		result |= (in[++offset] & 0xff) << 24;

		return result;
	}

	/**
	 * λ°μ΄?Έ λ°°μ΄? unsigned integer λ°°μ΄λ‘? λ³??
	 * 
	 * @param in
	 *            λ³???  λ°μ΄?Έ λ°°μ΄
	 * @param inOff
	 *            λ°μ΄?Έ λ°°μ΄? ?? ?€??
	 * @param out
	 *            unsigned integer λ°°μ΄
	 * @param outOff
	 *            unsigned integer λ°°μ΄? ?? ?€??
	 * @param length
	 *            λ³???  unsigned integer ? κΈΈμ΄
	 */
	public static void toU32(byte[] in, int inOff, int[] out, int outOff, int length) {

		for (int idx = outOff; idx < outOff + length; ++idx, ++inOff) {
			out[idx] = in[inOff] & 0xff;
			out[idx] |= (in[++inOff] & 0xff) << 8;
			out[idx] |= (in[++inOff] & 0xff) << 16;
			out[idx] |= (in[++inOff] & 0xff) << 24;
		}

	}

	/**
	 * λ°μ΄?Έ λ°°μ΄? unsigned long ?Όλ‘? λ³??
	 * 
	 * @param in
	 *            λ³???  λ°μ΄?Έ λ°°μ΄
	 * @param offset
	 *            ?? ?€??
	 * @return
	 */
	public static long toU64(byte[] in, int offset) {

		long result = (in[offset] & 0xff);
		result |= (long) (in[++offset] & 0xff) << 8;
		result |= (long) (in[++offset] & 0xff) << 16;
		result |= (long) (in[++offset] & 0xff) << 24;
		result |= (long) (in[++offset] & 0xff) << 32;
		result |= (long) (in[++offset] & 0xff) << 40;
		result |= (long) (in[++offset] & 0xff) << 48;
		result |= (long) (in[++offset] & 0xff) << 56;

		return result;
	}

	/**
	 * λ°μ΄?Έ λ°°μ΄? unsigned long λ°°μ΄λ‘? λ³??
	 * 
	 * @param in
	 *            λ³???  λ°μ΄?Έ λ°°μ΄
	 * @param inOff
	 *            λ°μ΄?Έ λ°°μ΄? ?? ?€??
	 * @param out
	 *            unsigned long λ°°μ΄
	 * @param outOff
	 *            unsigned long λ°°μ΄? ?? ?€??
	 * @param length
	 *            λ³???  unsigned long ? κΈΈμ΄
	 */
	public static void toU64(byte[] in, int inOff, long[] out, int outOff, int length) {

		for (int idx = outOff; idx < outOff + length; ++idx, ++inOff) {
			out[idx] = in[inOff] & 0xff;
			out[idx] |= (long) (in[++inOff] & 0xff) << 8;
			out[idx] |= (long) (in[++inOff] & 0xff) << 16;
			out[idx] |= (long) (in[++inOff] & 0xff) << 24;
			out[idx] |= (long) (in[++inOff] & 0xff) << 32;
			out[idx] |= (long) (in[++inOff] & 0xff) << 40;
			out[idx] |= (long) (in[++inOff] & 0xff) << 48;
			out[idx] |= (long) (in[++inOff] & 0xff) << 56;
		}

	}
}

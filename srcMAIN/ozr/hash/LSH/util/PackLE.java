package ozr.hash.LSH.util;

/**
 * ë°”ì´?Š¸ ë°°ì—´?„ ë¦¬í? ?—”?””?•ˆ ?˜•?‹?˜ ? •?ˆ˜ë¡? ë³??™˜?•˜ê¸? ?œ„?•œ ?„êµ?
 */
public class PackLE {

	/**
	 * ë°”ì´?Š¸ ë°°ì—´?„ unsigned integer ë¡? ë³??™˜
	 * 
	 * @param in
	 *            ë³??™˜?•  ë°”ì´?Š¸ ë°°ì—´
	 * @param offset
	 *            ?‹œ?‘ ?˜¤?”„?…‹
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
	 * ë°”ì´?Š¸ ë°°ì—´?„ unsigned integer ë°°ì—´ë¡? ë³??™˜
	 * 
	 * @param in
	 *            ë³??™˜?•  ë°”ì´?Š¸ ë°°ì—´
	 * @param inOff
	 *            ë°”ì´?Š¸ ë°°ì—´?˜ ?‹œ?‘ ?˜¤?”„?…‹
	 * @param out
	 *            unsigned integer ë°°ì—´
	 * @param outOff
	 *            unsigned integer ë°°ì—´?˜ ?‹œ?‘ ?˜¤?”„?…‹
	 * @param length
	 *            ë³??™˜?•  unsigned integer ?˜ ê¸¸ì´
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
	 * ë°”ì´?Š¸ ë°°ì—´?„ unsigned long ?œ¼ë¡? ë³??™˜
	 * 
	 * @param in
	 *            ë³??™˜?•  ë°”ì´?Š¸ ë°°ì—´
	 * @param offset
	 *            ?‹œ?‘ ?˜¤?”„?…‹
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
	 * ë°”ì´?Š¸ ë°°ì—´?„ unsigned long ë°°ì—´ë¡? ë³??™˜
	 * 
	 * @param in
	 *            ë³??™˜?•  ë°”ì´?Š¸ ë°°ì—´
	 * @param inOff
	 *            ë°”ì´?Š¸ ë°°ì—´?˜ ?‹œ?‘ ?˜¤?”„?…‹
	 * @param out
	 *            unsigned long ë°°ì—´
	 * @param outOff
	 *            unsigned long ë°°ì—´?˜ ?‹œ?‘ ?˜¤?”„?…‹
	 * @param length
	 *            ë³??™˜?•  unsigned long ?˜ ê¸¸ì´
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

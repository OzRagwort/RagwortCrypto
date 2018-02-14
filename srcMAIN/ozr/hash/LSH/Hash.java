package ozr.hash.LSH;

import ozr.hash.LSH.hash.LSH256;
import ozr.hash.LSH.hash.LSH512;

/**
 * LSH256, LSH512 ?˜ ?ƒ?œ„ ?´?˜?Š¤, ?•´?‹œ ?•¨?ˆ˜ êµ¬í˜„?„ ?œ„?•œ ê³µí†µ ?¸?„°?˜?´?Š¤ë¥? ?¬?•¨?•˜?Š” ?´?˜?Š¤?´?‹¤.
 */
public abstract class Hash {

	/**
	 * LSH ?•Œê³ ë¦¬ì¦? ëª…ì„¸
	 */
	public enum Algorithm {
		/**
		 * LSH-256-224 ?•Œê³ ë¦¬ì¦? ëª…ì„¸
		 */
		LSH256_224,

		/**
		 * LSH-256-256 ?•Œê³ ë¦¬ì¦? ëª…ì„¸
		 */
		LSH256_256,

		/**
		 * LSH-512-224 ?•Œê³ ë¦¬ì¦? ëª…ì„¸
		 */
		LSH512_224,

		/**
		 * LSH-512-256 ?•Œê³ ë¦¬ì¦? ëª…ì„¸
		 */
		LSH512_256,

		/**
		 * LSH-512-384 ?•Œê³ ë¦¬ì¦? ëª…ì„¸
		 */
		LSH512_384,

		/**
		 * LSH-512-512 ?•Œê³ ë¦¬ì¦? ëª…ì„¸
		 */
		LSH512_512
	};

	/**
	 * ê°™ì? ì¶œë ¥ê¸¸ì´ë¥? ê°?ì§??Š” ê°ì²´ë¥? ë§Œë“¤?–´ ë¦¬í„´?•œ?‹¤.
	 * 
	 * @return LSHDigest ê°ì²´
	 */
	public abstract Hash newInstance();

	/**
	 * ?‚´ë¶? ê³„ì‚°?— ?‚¬?š©?˜?Š” ë©”ì‹œì§? ë¸”ë¡ ë¹„íŠ¸ ê¸¸ì´ë¥? ë¦¬í„´?•œ?‹¤.
	 * 
	 * @return ë©”ì‹œì§? ë¸”ë¡ ë¹„íŠ¸ ê¸¸ì´
	 */
	public abstract int getBlockSize();

	/**
	 * ?•´?‹œ ì¶œë ¥ ê¸¸ì´ë¥? ë¦¬í„´?•œ?‹¤.
	 * 
	 * @return ?•´?‹œ ì¶œë ¥ ê¸¸ì´ (ë¹„íŠ¸ ?‹¨?œ„)
	 */
	public abstract int getOutlenbits();

	/**
	 * ?‚´ë¶? ?ƒ?ƒœë¥? ì´ˆê¸°?™”?•˜?—¬ ?ƒˆë¡œì? message digestë¥? ê³„ì‚°?•  ì¤?ë¹„ë?? ?•œ?‹¤.
	 */
	public abstract void reset();

	/**
	 * message digestë¥? ê³„ì‚°?•  ?°?´?„°ë¥? ì²˜ë¦¬?•œ?‹¤.
	 * 
	 * @param data
	 *            message digestë¥? ê³„ì‚°?•  ?°?´?„°
	 * @param offset
	 *            ?°?´?„° ë°°ì—´?˜ ?‹œ?‘ ?˜¤?”„?…‹
	 * @param lenbits
	 *            ?°?´?„°?˜ ê¸¸ì´ (ë¹„íŠ¸ ?‹¨?œ„)
	 */
	public abstract void update(byte[] data, int offset, int lenbits);

	/**
	 * message digestë¥? ê³„ì‚°?•œ?‹¤
	 * 
	 * @return ê³„ì‚°?œ message digest ê°?
	 */
	public abstract byte[] doFinal();

	/**
	 * message digestë¥? ê³„ì‚°?•  ?°?´?„°ë¥? ì²˜ë¦¬?•œ?‹¤.
	 * 
	 * @param data
	 *            message digestë¥? ê³„ì‚°?•  ?°?´?„°
	 */
	public void update(byte[] data) {
		if (data != null) {
			update(data, 0, data.length * 8);
		}
	}

	/**
	 * dataë¥? ì¶”ê??•˜?—¬ ìµœì¢… message digestë¥? ê³„ì‚°?•œ?‹¤.
	 * 
	 * @param data
	 *            message digestë¥? ê³„ì‚°?•  ?°?´?„°
	 * @param offset
	 *            ?°?´?„° ë°°ì—´?˜ ?‹œ?‘ ?˜¤?”„?…‹
	 * @param lenbits
	 *            ?°?´?„°?˜ ê¸¸ì´ (ë¹„íŠ¸ ?‹¨?œ„)
	 */
	public byte[] doFinal(byte[] data, int offset, int lenbits) {
		if (data != null && lenbits > 0) {
			update(data, offset, lenbits);
		}

		return doFinal();
	}

	/**
	 * dataë¥? ì¶”ê??•˜?—¬ ìµœì¢… message digestë¥? ê³„ì‚°?•œ?‹¤.
	 * 
	 * @param data
	 *            ìµœì¢… data
	 * @return ê³„ì‚°?œ message digest
	 */
	public byte[] doFinal(byte[] data) {
		if (data != null) {
			update(data);
		}

		return doFinal();
	}

	/**
	 * algorithm?— ?•´?‹¹?•˜?Š” ?•´?‹œ?•¨?ˆ˜ ê°ì²´ ë¦¬í„´
	 * 
	 * @param algorithm
	 *            ?•Œê³ ë¦¬ì¦?
	 * @return ?•´?‹œ?•¨?ˆ˜ ê°ì²´
	 */
	public static Hash getInstance(Algorithm algorithm) {

		Hash lsh = null;

		switch (algorithm) {

		case LSH256_224:
			lsh = new LSH256(224);
			break;

		case LSH256_256:
			lsh = new LSH256(256);
			break;

		case LSH512_224:
			lsh = new LSH512(224);
			break;

		case LSH512_256:
			lsh = new LSH512(256);
			break;

		case LSH512_384:
			lsh = new LSH512(384);
			break;

		case LSH512_512:
			lsh = new LSH512(512);
			break;

		default:
			throw new RuntimeException("Unsupported algorithm");
		}

		return lsh;
	}

	/**
	 * algorithm?„ ?´?š©?•˜?—¬ ?•´?‹œ ê³„ì‚°
	 * 
	 * @param algorithm
	 *            ?•Œê³ ë¦¬ì¦?
	 * @param data
	 *            ?•´?‹œê°’ì„ ê³„ì‚°?•  ?°?´?„°
	 * @return
	 */
	public static byte[] digest(Algorithm algorithm, byte[] data) {
		return digest(algorithm, data, 0, data == null ? 0 : data.length << 3);
	}

	/**
	 * algorithm?„ ?´?š©?•˜?—¬ ?•´?‹œ ê³„ì‚°
	 * 
	 * @param algorithm
	 *            ?•Œê³ ë¦¬ì¦?
	 * @param data
	 *            ?•´?‹œê°’ì„ ê³„ì‚°?•  ?°?´?„°
	 * @param offset
	 *            ?°?´?„° ?‹œ?‘ ?˜¤?”„?…‹
	 * @param lenbits
	 *            ?°?´?„° ê¸¸ì´, ë¹„íŠ¸ ?‹¨?œ„
	 * @return
	 */
	public static byte[] digest(Algorithm algorithm, byte[] data, int offset,
			int lenbits) {
		Hash lsh = Hash.getInstance(algorithm);
		lsh.update(data, offset, lenbits);
		return lsh.doFinal();
	}

	/**
	 * LSH-wordlenbits-hashlenbits ?•Œê³ ë¦¬ì¦˜ì„ ?´?š©?•˜?—¬ ?•´?‹œ ê³„ì‚°
	 * 
	 * @param wordlenbits
	 *            ?›Œ?“œ ê¸¸ì´, ë¹„íŠ¸ ?‹¨?œ„, 256 or 512
	 * @param hashlenbits
	 *            ì¶œë ¥ ê¸¸ì´, ë¹„íŠ¸ ?‹¨?œ„, 1 ~ wordlenbits
	 * @param data
	 *            ?•´?‹œë¥? ê³„ì‚°?•  ?°?´?„°
	 * @return ?•´?‹œê°?
	 */
	public static byte[] digest(int wordlenbits, int hashlenbits, byte[] data) {
		return digest(wordlenbits, hashlenbits, data, 0, data == null ? 0
				: data.length * 8);
	}

	/**
	 * 
	 * @param wordlenbits
	 *            ?›Œ?“œ ê¸¸ì´, ë¹„íŠ¸ ?‹¨?œ„, 256 or 512
	 * @param hashlenbits
	 *            ì¶œë ¥ ê¸¸ì´, ë¹„íŠ¸ ?‹¨?œ„, 1 ~ wordlenbits
	 * @param data
	 *            ?•´?‹œë¥? ê³„ì‚°?•  ?°?´?„°
	 * @param offset
	 *            ?°?´?„° ?‹œ?‘ ?˜¤?”„?…‹
	 * @param lenbits
	 *            ?°?´?„° ê¸¸ì´, ë¹„íŠ¸ ?‹¨?œ„
	 * @return ?•´?‹œê°?
	 */
	public static byte[] digest(int wordlenbits, int hashlenbits, byte[] data,
			int offset, int lenbits) {
		Hash lsh = null;
		if (wordlenbits == 256) {
			lsh = new LSH256(hashlenbits);
		} else if (wordlenbits == 512) {
			lsh = new LSH512(hashlenbits);
		} else {
			throw new RuntimeException("Unsupported wordlenbits");
		}

		lsh.update(data, offset, lenbits);
		return lsh.doFinal();
	}

}

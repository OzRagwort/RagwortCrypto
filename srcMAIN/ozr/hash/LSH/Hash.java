package ozr.hash.LSH;

import ozr.hash.LSH.hash.LSH256;
import ozr.hash.LSH.hash.LSH512;

/**
 * LSH256, LSH512 ? ?? ?΄??€, ?΄? ?¨? κ΅¬ν? ?? κ³΅ν΅ ?Έ?°??΄?€λ₯? ?¬?¨?? ?΄??€?΄?€.
 */
public abstract class Hash {

	/**
	 * LSH ?κ³ λ¦¬μ¦? λͺμΈ
	 */
	public enum Algorithm {
		/**
		 * LSH-256-224 ?κ³ λ¦¬μ¦? λͺμΈ
		 */
		LSH256_224,

		/**
		 * LSH-256-256 ?κ³ λ¦¬μ¦? λͺμΈ
		 */
		LSH256_256,

		/**
		 * LSH-512-224 ?κ³ λ¦¬μ¦? λͺμΈ
		 */
		LSH512_224,

		/**
		 * LSH-512-256 ?κ³ λ¦¬μ¦? λͺμΈ
		 */
		LSH512_256,

		/**
		 * LSH-512-384 ?κ³ λ¦¬μ¦? λͺμΈ
		 */
		LSH512_384,

		/**
		 * LSH-512-512 ?κ³ λ¦¬μ¦? λͺμΈ
		 */
		LSH512_512
	};

	/**
	 * κ°μ? μΆλ ₯κΈΈμ΄λ₯? κ°?μ§?? κ°μ²΄λ₯? λ§λ€?΄ λ¦¬ν΄??€.
	 * 
	 * @return LSHDigest κ°μ²΄
	 */
	public abstract Hash newInstance();

	/**
	 * ?΄λΆ? κ³μ°? ?¬?©?? λ©μμ§? λΈλ‘ λΉνΈ κΈΈμ΄λ₯? λ¦¬ν΄??€.
	 * 
	 * @return λ©μμ§? λΈλ‘ λΉνΈ κΈΈμ΄
	 */
	public abstract int getBlockSize();

	/**
	 * ?΄? μΆλ ₯ κΈΈμ΄λ₯? λ¦¬ν΄??€.
	 * 
	 * @return ?΄? μΆλ ₯ κΈΈμ΄ (λΉνΈ ?¨?)
	 */
	public abstract int getOutlenbits();

	/**
	 * ?΄λΆ? ??λ₯? μ΄κΈ°???¬ ?λ‘μ? message digestλ₯? κ³μ°?  μ€?λΉλ?? ??€.
	 */
	public abstract void reset();

	/**
	 * message digestλ₯? κ³μ°?  ?°?΄?°λ₯? μ²λ¦¬??€.
	 * 
	 * @param data
	 *            message digestλ₯? κ³μ°?  ?°?΄?°
	 * @param offset
	 *            ?°?΄?° λ°°μ΄? ?? ?€??
	 * @param lenbits
	 *            ?°?΄?°? κΈΈμ΄ (λΉνΈ ?¨?)
	 */
	public abstract void update(byte[] data, int offset, int lenbits);

	/**
	 * message digestλ₯? κ³μ°??€
	 * 
	 * @return κ³μ°? message digest κ°?
	 */
	public abstract byte[] doFinal();

	/**
	 * message digestλ₯? κ³μ°?  ?°?΄?°λ₯? μ²λ¦¬??€.
	 * 
	 * @param data
	 *            message digestλ₯? κ³μ°?  ?°?΄?°
	 */
	public void update(byte[] data) {
		if (data != null) {
			update(data, 0, data.length * 8);
		}
	}

	/**
	 * dataλ₯? μΆκ???¬ μ΅μ’ message digestλ₯? κ³μ°??€.
	 * 
	 * @param data
	 *            message digestλ₯? κ³μ°?  ?°?΄?°
	 * @param offset
	 *            ?°?΄?° λ°°μ΄? ?? ?€??
	 * @param lenbits
	 *            ?°?΄?°? κΈΈμ΄ (λΉνΈ ?¨?)
	 */
	public byte[] doFinal(byte[] data, int offset, int lenbits) {
		if (data != null && lenbits > 0) {
			update(data, offset, lenbits);
		}

		return doFinal();
	}

	/**
	 * dataλ₯? μΆκ???¬ μ΅μ’ message digestλ₯? κ³μ°??€.
	 * 
	 * @param data
	 *            μ΅μ’ data
	 * @return κ³μ°? message digest
	 */
	public byte[] doFinal(byte[] data) {
		if (data != null) {
			update(data);
		}

		return doFinal();
	}

	/**
	 * algorithm? ?΄?Ή?? ?΄??¨? κ°μ²΄ λ¦¬ν΄
	 * 
	 * @param algorithm
	 *            ?κ³ λ¦¬μ¦?
	 * @return ?΄??¨? κ°μ²΄
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
	 * algorithm? ?΄?©??¬ ?΄? κ³μ°
	 * 
	 * @param algorithm
	 *            ?κ³ λ¦¬μ¦?
	 * @param data
	 *            ?΄?κ°μ κ³μ°?  ?°?΄?°
	 * @return
	 */
	public static byte[] digest(Algorithm algorithm, byte[] data) {
		return digest(algorithm, data, 0, data == null ? 0 : data.length << 3);
	}

	/**
	 * algorithm? ?΄?©??¬ ?΄? κ³μ°
	 * 
	 * @param algorithm
	 *            ?κ³ λ¦¬μ¦?
	 * @param data
	 *            ?΄?κ°μ κ³μ°?  ?°?΄?°
	 * @param offset
	 *            ?°?΄?° ?? ?€??
	 * @param lenbits
	 *            ?°?΄?° κΈΈμ΄, λΉνΈ ?¨?
	 * @return
	 */
	public static byte[] digest(Algorithm algorithm, byte[] data, int offset,
			int lenbits) {
		Hash lsh = Hash.getInstance(algorithm);
		lsh.update(data, offset, lenbits);
		return lsh.doFinal();
	}

	/**
	 * LSH-wordlenbits-hashlenbits ?κ³ λ¦¬μ¦μ ?΄?©??¬ ?΄? κ³μ°
	 * 
	 * @param wordlenbits
	 *            ?? κΈΈμ΄, λΉνΈ ?¨?, 256 or 512
	 * @param hashlenbits
	 *            μΆλ ₯ κΈΈμ΄, λΉνΈ ?¨?, 1 ~ wordlenbits
	 * @param data
	 *            ?΄?λ₯? κ³μ°?  ?°?΄?°
	 * @return ?΄?κ°?
	 */
	public static byte[] digest(int wordlenbits, int hashlenbits, byte[] data) {
		return digest(wordlenbits, hashlenbits, data, 0, data == null ? 0
				: data.length * 8);
	}

	/**
	 * 
	 * @param wordlenbits
	 *            ?? κΈΈμ΄, λΉνΈ ?¨?, 256 or 512
	 * @param hashlenbits
	 *            μΆλ ₯ κΈΈμ΄, λΉνΈ ?¨?, 1 ~ wordlenbits
	 * @param data
	 *            ?΄?λ₯? κ³μ°?  ?°?΄?°
	 * @param offset
	 *            ?°?΄?° ?? ?€??
	 * @param lenbits
	 *            ?°?΄?° κΈΈμ΄, λΉνΈ ?¨?
	 * @return ?΄?κ°?
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

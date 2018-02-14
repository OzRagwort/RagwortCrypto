package ozr.hash.LSH;

import ozr.hash.LSH.hash.LSH256;
import ozr.hash.LSH.hash.LSH512;

/**
 * LSH256, LSH512 ?�� ?��?�� ?��?��?��, ?��?�� ?��?�� 구현?�� ?��?�� 공통 ?��?��?��?��?���? ?��?��?��?�� ?��?��?��?��?��.
 */
public abstract class Hash {

	/**
	 * LSH ?��고리�? 명세
	 */
	public enum Algorithm {
		/**
		 * LSH-256-224 ?��고리�? 명세
		 */
		LSH256_224,

		/**
		 * LSH-256-256 ?��고리�? 명세
		 */
		LSH256_256,

		/**
		 * LSH-512-224 ?��고리�? 명세
		 */
		LSH512_224,

		/**
		 * LSH-512-256 ?��고리�? 명세
		 */
		LSH512_256,

		/**
		 * LSH-512-384 ?��고리�? 명세
		 */
		LSH512_384,

		/**
		 * LSH-512-512 ?��고리�? 명세
		 */
		LSH512_512
	};

	/**
	 * 같�? 출력길이�? �?�??�� 객체�? 만들?�� 리턴?��?��.
	 * 
	 * @return LSHDigest 객체
	 */
	public abstract Hash newInstance();

	/**
	 * ?���? 계산?�� ?��?��?��?�� 메시�? 블록 비트 길이�? 리턴?��?��.
	 * 
	 * @return 메시�? 블록 비트 길이
	 */
	public abstract int getBlockSize();

	/**
	 * ?��?�� 출력 길이�? 리턴?��?��.
	 * 
	 * @return ?��?�� 출력 길이 (비트 ?��?��)
	 */
	public abstract int getOutlenbits();

	/**
	 * ?���? ?��?���? 초기?��?��?�� ?��로�? message digest�? 계산?�� �?비�?? ?��?��.
	 */
	public abstract void reset();

	/**
	 * message digest�? 계산?�� ?��?��?���? 처리?��?��.
	 * 
	 * @param data
	 *            message digest�? 계산?�� ?��?��?��
	 * @param offset
	 *            ?��?��?�� 배열?�� ?��?�� ?��?��?��
	 * @param lenbits
	 *            ?��?��?��?�� 길이 (비트 ?��?��)
	 */
	public abstract void update(byte[] data, int offset, int lenbits);

	/**
	 * message digest�? 계산?��?��
	 * 
	 * @return 계산?�� message digest �?
	 */
	public abstract byte[] doFinal();

	/**
	 * message digest�? 계산?�� ?��?��?���? 처리?��?��.
	 * 
	 * @param data
	 *            message digest�? 계산?�� ?��?��?��
	 */
	public void update(byte[] data) {
		if (data != null) {
			update(data, 0, data.length * 8);
		}
	}

	/**
	 * data�? 추�??��?�� 최종 message digest�? 계산?��?��.
	 * 
	 * @param data
	 *            message digest�? 계산?�� ?��?��?��
	 * @param offset
	 *            ?��?��?�� 배열?�� ?��?�� ?��?��?��
	 * @param lenbits
	 *            ?��?��?��?�� 길이 (비트 ?��?��)
	 */
	public byte[] doFinal(byte[] data, int offset, int lenbits) {
		if (data != null && lenbits > 0) {
			update(data, offset, lenbits);
		}

		return doFinal();
	}

	/**
	 * data�? 추�??��?�� 최종 message digest�? 계산?��?��.
	 * 
	 * @param data
	 *            최종 data
	 * @return 계산?�� message digest
	 */
	public byte[] doFinal(byte[] data) {
		if (data != null) {
			update(data);
		}

		return doFinal();
	}

	/**
	 * algorithm?�� ?��?��?��?�� ?��?��?��?�� 객체 리턴
	 * 
	 * @param algorithm
	 *            ?��고리�?
	 * @return ?��?��?��?�� 객체
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
	 * algorithm?�� ?��?��?��?�� ?��?�� 계산
	 * 
	 * @param algorithm
	 *            ?��고리�?
	 * @param data
	 *            ?��?��값을 계산?�� ?��?��?��
	 * @return
	 */
	public static byte[] digest(Algorithm algorithm, byte[] data) {
		return digest(algorithm, data, 0, data == null ? 0 : data.length << 3);
	}

	/**
	 * algorithm?�� ?��?��?��?�� ?��?�� 계산
	 * 
	 * @param algorithm
	 *            ?��고리�?
	 * @param data
	 *            ?��?��값을 계산?�� ?��?��?��
	 * @param offset
	 *            ?��?��?�� ?��?�� ?��?��?��
	 * @param lenbits
	 *            ?��?��?�� 길이, 비트 ?��?��
	 * @return
	 */
	public static byte[] digest(Algorithm algorithm, byte[] data, int offset,
			int lenbits) {
		Hash lsh = Hash.getInstance(algorithm);
		lsh.update(data, offset, lenbits);
		return lsh.doFinal();
	}

	/**
	 * LSH-wordlenbits-hashlenbits ?��고리즘을 ?��?��?��?�� ?��?�� 계산
	 * 
	 * @param wordlenbits
	 *            ?��?�� 길이, 비트 ?��?��, 256 or 512
	 * @param hashlenbits
	 *            출력 길이, 비트 ?��?��, 1 ~ wordlenbits
	 * @param data
	 *            ?��?���? 계산?�� ?��?��?��
	 * @return ?��?���?
	 */
	public static byte[] digest(int wordlenbits, int hashlenbits, byte[] data) {
		return digest(wordlenbits, hashlenbits, data, 0, data == null ? 0
				: data.length * 8);
	}

	/**
	 * 
	 * @param wordlenbits
	 *            ?��?�� 길이, 비트 ?��?��, 256 or 512
	 * @param hashlenbits
	 *            출력 길이, 비트 ?��?��, 1 ~ wordlenbits
	 * @param data
	 *            ?��?���? 계산?�� ?��?��?��
	 * @param offset
	 *            ?��?��?�� ?��?�� ?��?��?��
	 * @param lenbits
	 *            ?��?��?�� 길이, 비트 ?��?��
	 * @return ?��?���?
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

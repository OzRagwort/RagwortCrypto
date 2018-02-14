package ozr.encryption.sym.LEA.mode;

import static ozr.encryption.sym.LEA.util.Ops.*;

import ozr.encryption.sym.LEA.BlockCipher;
import ozr.encryption.sym.LEA.BlockCipherModeStream;
import ozr.encryption.sym.LEA.BlockCipher.Mode;

// DONE: block vs buffer
public class CFBMode extends BlockCipherModeStream {

	private byte[] iv;
	private byte[] block;
	private byte[] feedback;

	public CFBMode(BlockCipher cipher) {
		super(cipher);
	}

	@Override
	public String getAlgorithmName() {
		return engine.getAlgorithmName() + "/CFB";
	}

	@Override
	public void init(Mode mode, byte[] mk, byte[] iv) {
		this.mode = mode;
		engine.init(Mode.ENCRYPT, mk);

		this.iv = iv.clone();
		block = new byte[blocksize];
		feedback = new byte[blocksize];
		reset();
	}

	@Override
	public void reset() {
		super.reset();
		System.arraycopy(iv, 0, feedback, 0, blocksize);
	}

	@Override
	protected int processBlock(byte[] in, int inOff, byte[] out, int outOff, int outlen) {
		int length = engine.processBlock(feedback, 0, block, 0);
		XOR(out, outOff, in, inOff, block, 0, outlen);

		if (mode == Mode.ENCRYPT) {
			System.arraycopy(out, outOff, feedback, 0, blocksize);

		} else {
			System.arraycopy(in, inOff, feedback, 0, blocksize);
		}

		return length;
	}

}

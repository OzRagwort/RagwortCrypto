package ozr.encryption.sym.LEA.mode;

import static ozr.encryption.sym.LEA.util.Ops.*;

import ozr.encryption.sym.LEA.BlockCipher;
import ozr.encryption.sym.LEA.BlockCipherModeStream;
import ozr.encryption.sym.LEA.BlockCipher.Mode;

// DONE: block vs buffer
public class OFBMode extends BlockCipherModeStream {

	private byte[] iv;
	private byte[] block;

	public OFBMode(BlockCipher cipher) {
		super(cipher);
	}

	@Override
	public String getAlgorithmName() {
		return engine.getAlgorithmName() + "/OFB";
	}

	@Override
	public void init(Mode mode, byte[] mk, byte[] iv) {
		this.mode = mode;
		engine.init(Mode.ENCRYPT, mk);

		this.iv = iv.clone();
		block = new byte[blocksize];
		reset();
	}

	@Override
	public void reset() {
		super.reset();
		System.arraycopy(iv, 0, block, 0, blocksize);
	}

	@Override
	protected int processBlock(byte[] in, int inOff, byte[] out, int outOff, int outlen) {
		int length = engine.processBlock(block, 0, block, 0);
		XOR(out, outOff, in, inOff, block, 0, outlen);

		return length;
	}
}

package ozr.encryption.sym.LEA.symm;

import ozr.encryption.sym.LEA.BlockCipher;
import ozr.encryption.sym.LEA.engine.LeaEngine;
import ozr.encryption.sym.LEA.mac.CMac;
import ozr.encryption.sym.LEA.mode.CBCMode;
import ozr.encryption.sym.LEA.mode.CCMMode;
import ozr.encryption.sym.LEA.mode.CFBMode;
import ozr.encryption.sym.LEA.mode.CTRMode;
import ozr.encryption.sym.LEA.mode.ECBMode;
import ozr.encryption.sym.LEA.mode.GCMMode;
import ozr.encryption.sym.LEA.mode.OFBMode;

public class LEA {
	private LEA() {
		throw new AssertionError();
	}

	public static final BlockCipher getEngine() {
		return new LeaEngine();
	}

	public static final class ECB extends ECBMode {
		public ECB() {
			super(getEngine());
		}
	}

	public static final class CBC extends CBCMode {
		public CBC() {
			super(getEngine());
		}
	}

	public static final class CTR extends CTRMode {
		public CTR() {
			super(getEngine());
		}
	}

	public static final class CFB extends CFBMode {
		public CFB() {
			super(getEngine());
		}
	}

	public static final class OFB extends OFBMode {
		public OFB() {
			super(getEngine());
		}
	}

	public static final class CCM extends CCMMode {
		public CCM() {
			super(getEngine());
		}
	}

	public static final class GCM extends GCMMode {
		public GCM() {
			super(getEngine());
		}
	}

	public static final class CMAC extends CMac {
		public CMAC() {
			super(getEngine());
		}
	}

}

package cryp.sym;

import java.util.Base64;
import java.util.Base64.Encoder;
import java.util.Base64.Decoder;

import ozr.encryption.sym.SEED.*;

public class SEED implements sym {
	
	public byte[] enc(String plain, byte[] key) {
		
		byte[] byte_plain = plain.getBytes();
		
		Encoder encoder = Base64.getEncoder();
		return encoder.encode(enc(byte_plain, key));
	}

	public byte[] enc(byte[] plain, byte[] key) {
		
		return ECB(plain, key, true);
	}
	
	public byte[] dec(String cipher, byte[] key) {
		
		byte[] byte_cipher = cipher.getBytes();
		
		Decoder decoder = Base64.getDecoder();
		return decoder.decode(dec(byte_cipher, key));
	}
	
	public byte[] dec(byte[] cipher, byte[] key) {
		
		return ECB(cipher, key, false);
	}
	
	
	private byte[] ECB(byte[] data, byte[] key, boolean type) {
		
		if(key.length != 16)
			System.out.println("key's length error");
		
		int[] roundkey = new int[32];
		byte[] outdata = new byte[16];
		
		SEED_ECB.SeedRoundKey(roundkey, key);
		
		if(type)
			SEED_ECB.SeedEncrypt(data, roundkey, outdata);
		else
			SEED_ECB.SeedDecrypt(data, roundkey, outdata);
		
		return outdata;
		
	}
}

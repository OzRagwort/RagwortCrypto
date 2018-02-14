package cryp.sym;

import java.util.Base64;
import java.util.Base64.Encoder;
import java.util.Base64.Decoder;

import ozr.encryption.sym.ARIA.*;

public class ARIA implements sym {

    public byte[] enc(String plain, byte[] key) throws Exception {
		
		byte[] byte_plain = plain.getBytes();
		
		Encoder encoder = Base64.getEncoder();
		return encoder.encode(enc(byte_plain, key));
	}
    
	public byte[] enc(byte[] plain, byte[] key) throws Exception {
		
		return ECB(plain, key, true);
	}
	
	public byte[] dec(String cipher, byte[] key) throws Exception {
		
		byte[] byte_cipher = cipher.getBytes();
		
		Decoder decoder = Base64.getDecoder();
		return decoder.decode(dec(byte_cipher, key));
	}
	
	public byte[] dec(byte[] cipher, byte[] key) throws Exception {
		
		return ECB(cipher, key, false);
	}
	
	
	private byte[] ECB(byte[] data, byte[] key, boolean type) throws Exception {
		
		if(type)
		{
			ARIA_ECB instance = new ARIA_ECB(key.length * 8);
			
			byte[] outdata = new byte[key.length];
			
			instance.setKey(key);
			instance.setupRoundKeys();
			
			instance.encrypt(data, 0, outdata, 0);
			
			return outdata;
		}
		else
		{
			ARIA_ECB instance = new ARIA_ECB(key.length * 8);
			
			byte[] outdata = new byte[key.length];
			
			instance.setKey(key);
			instance.setupRoundKeys();
			
			instance.decrypt(data, 0, outdata, 0);
			
			return outdata;
		}
	}

}

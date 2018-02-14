package cryp.sym;

import java.util.Base64;
import java.util.Base64.Encoder;
import java.util.Base64.Decoder;

import ozr.encryption.sym.HIGHT.HIGHT_ECB;
import ozr.encryption.sym.HIGHT.HIGHT_CBC;
import ozr.encryption.sym.HIGHT.HIGHT_CTR;

public class HIGHT implements sym, sym_iv {
	
	private byte[] IV = {(byte)0x00, (byte)0x01, (byte)0x02, (byte)0x03, (byte)0x04, (byte)0x05, (byte)0x06, (byte)0x07};
	
	public byte[] enc(String plain, byte[] key) throws Exception {
		
		byte[] byte_plain = plain.getBytes();
		
		Encoder encoder = Base64.getEncoder();
		return encoder.encode(enc(byte_plain, key));
	}
	
	public byte[] enc(byte[] plain, byte[] key) {
		return ECB(plain, key, true);
	}
	
	public byte[] enc(String plain, byte[] key, String type, byte[] IV) {
		
		byte[] byte_plain = plain.getBytes();
		
		Encoder encoder = Base64.getEncoder();
		return encoder.encode(enc(byte_plain, key, type, IV));
	}

	public byte[] enc(byte[] plain, byte[] key, String type, byte[] IV) {
		
		this.IV = IV;
		
		if(type.equals("CBC") || type.equals("cbc"))
			return CBC(plain, key, true);
		else if(type.equals("CTR") || type.equals("ctr"))
			return CTR(plain, key, true);
		else
			return null;
			//����
	}
	
	public byte[] dec(String cipher, byte[] key) throws Exception {
		
		byte[] byte_cipher = cipher.getBytes();
		
		Decoder decoder = Base64.getDecoder();
		return decoder.decode(dec(byte_cipher, key));
	}
	
	public byte[] dec(byte[] plain, byte[] key) {
		return ECB(plain, key, false);
	}
	
	public byte[] dec(String cipher, byte[] key, String type, byte[] IV) {
		
		byte[] byte_cipher = cipher.getBytes();
		
		Decoder decoder = Base64.getDecoder();
		return decoder.decode(dec(byte_cipher, key, type, IV));
	}
	
	public byte[] dec(byte[] cipher, byte[] key, String type, byte[] IV) {
		
		this.IV = IV;
		
		if(type.equals("CBC") || type.equals("cbc"))
			return CBC(cipher, key, false);
		else if(type.equals("CTR") || type.equals("ctr"))
			return CTR(cipher, key, false);
		else
			return null;
			//����
	}
	
	
	
	
	
	
	private byte[] ECB(byte[] data, byte[] key, boolean type) {
		
    	byte[] cipher =  HIGHT_ECB.HIGHT_ECB_Encrypt(key, data, 0, data.length);
	    byte[] plain = HIGHT_ECB.HIGHT_ECB_Decrypt(key, data, 0, data.length) ;
		
		if(type)
			return cipher;
		else
			return plain;
	}
	
	
	private byte[] CBC(byte[] data, byte[] key, boolean type) {
		
		
		byte[] cipher =  HIGHT_CBC.HIGHT_CBC_Encrypt(key, IV, data, 0, data.length);
	    byte[] plain = HIGHT_CBC.HIGHT_CBC_Decrypt(key, IV,  data, 0, data.length);
	    
	    
	    if(type)
			return cipher;
		else
			return plain;
	}
	
	
	private byte[] CTR(byte[] data, byte[] key, boolean type) {
		
		byte[] cipher = HIGHT_CTR.HIGHT_CTR_Encrypt(key, IV, data,0, data.length);
	    byte[] plain = HIGHT_CTR.HIGHT_CTR_Decrypt(key, IV, data, 0, data.length);
		
	    if(type)
			return cipher;
		else
			return plain;
	}

}

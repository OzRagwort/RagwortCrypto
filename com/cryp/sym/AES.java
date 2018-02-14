package cryp.sym;

import java.security.Key;
import java.util.Base64;
import java.util.Base64.Encoder;
import java.util.Base64.Decoder;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public class AES implements sym, sym_iv {
	
	private byte[] IV = {
			(byte)0x00, (byte)0x01, (byte)0x02, (byte)0x03, (byte)0x04, (byte)0x05, (byte)0x06, (byte)0x07,
			(byte)0x08, (byte)0x09, (byte)0x0a, (byte)0x0b, (byte)0x0c, (byte)0x0d, (byte)0x0e, (byte)0x0f,
			(byte)0x00, (byte)0x01, (byte)0x02, (byte)0x03, (byte)0x04, (byte)0x05, (byte)0x06, (byte)0x07,
			(byte)0x08, (byte)0x09, (byte)0x0a, (byte)0x0b, (byte)0x0c, (byte)0x0d, (byte)0x0e, (byte)0x0f
	};
	private String AESInstance = "AES/ECB/PKCS5Padding";
	public byte[] don;
	
	public byte[] enc(String plain, byte[] key) throws Exception {
		
		byte[] byte_plain = plain.getBytes();
		
		Encoder encoder = Base64.getEncoder();
		return encoder.encode(enc(byte_plain, key));
	}

	public byte[] enc(byte[] plain, byte[] key) throws Exception {
		
		return encAES(plain, key);
	}

	public byte[] enc(String plain, byte[] key, String type, byte[] IV) throws Exception {
		
		this.AESInstance = "AES/"+type+"/PKCS5Padding";
		this.IV = IV;
		byte[] byte_plain = plain.getBytes();
		
		Encoder encoder = Base64.getEncoder();
		return encoder.encode(enc(byte_plain, key));
	}

	public byte[] enc(byte[] plain, byte[] key, String type, byte[] IV) throws Exception {
		this.AESInstance = "AES/"+type+"/PKCS5Padding";
		this.IV = IV;
		return encAES(plain, key);
	}
	
	public byte[] dec(String cipher, byte[] key) throws Exception {
		
		byte[] byte_cipher = cipher.getBytes();
		
		Decoder decoder = Base64.getDecoder();
		return decoder.decode(dec(byte_cipher, key));
	}
	
	public byte[] dec(byte[] cipher, byte[] key) throws Exception {
		
		return decAES(cipher, key);
	}

	public byte[] dec(String cipher, byte[] key, String type, byte[] IV) throws Exception {
		this.AESInstance = "AES/"+type+"/PKCS5Padding";
		this.IV = IV;
		byte[] byte_cipher = cipher.getBytes();
		
		Decoder decoder = Base64.getDecoder();
		return decoder.decode(dec(byte_cipher, key));
	}
	
	public byte[] dec(byte[] cipher, byte[] key, String type, byte[] IV) throws Exception {
		this.AESInstance = "AES/"+type+"/PKCS5Padding";
		this.IV = IV;
		return decAES(cipher, key);
	}
	
	
	
	private Key getAESKey(byte[] key) {
	    Key keySpec;
	    
	    byte[] keyBytes = new byte[key.length];
	    byte[] b = key;

	    int len = b.length;
	    if (len > keyBytes.length) {
	       len = keyBytes.length;
	    }

	    System.arraycopy(b, 0, keyBytes, 0, len);
	    keySpec = new SecretKeySpec(keyBytes, "AES");

	    return keySpec;
	}
	
	
	private byte[] genIV(byte[] IV, int len) {
		
		byte[] returnIV = new byte[len];
		
		System.arraycopy(IV, 0, returnIV, 0, len);
		
		return returnIV;
	}
	

	private byte[] encAES(byte[] plain, byte[] key) throws Exception {
		
		if(key.length != 16 && key.length != 24 && key.length != 32)
	    	return null;
		
		Key keySpec = getAESKey(key);
		Cipher cipher = Cipher.getInstance(AESInstance);
		if(AESInstance.equals("AES/ECB/PKCS5Padding"))
			cipher.init(Cipher.ENCRYPT_MODE, keySpec);
		// ECB/CBC/OFB/CTR
		else
		{
			byte[] cumIV = genIV(IV, 16);
			IvParameterSpec ivs = new IvParameterSpec(cumIV);
			cipher.init(Cipher.ENCRYPT_MODE, keySpec, ivs);
		}
		
		if((plain.length % 16)!=0)
    	{
    		byte[] text1 = cipher.update(plain);
        	byte[] text2 = cipher.doFinal();
        	
    		byte[] ciphertext = new byte[text1.length + text2.length];
    		System.arraycopy(text1, 0, ciphertext, 0, text1.length);
    		System.arraycopy(text2, 0, ciphertext, text1.length, text2.length);
    		
    		return ciphertext;
    	}
    	else
    	{
    		byte[] out = cipher.update(plain);
    		don = cipher.doFinal();
    		return out;
    	}
		
	}

	
	private byte[] decAES(byte[] plain, byte[] key) throws Exception {
		
		if(key.length != 16 && key.length != 24 && key.length != 32)
	    	return null;
		
		Key keySpec = getAESKey(key);
		Cipher cipher = Cipher.getInstance(AESInstance);
		if(AESInstance.equals("AES/ECB/PKCS5Padding"))
			cipher.init(Cipher.DECRYPT_MODE, keySpec);
		else
		{
			byte[] cumIV = genIV(IV, 16);
			IvParameterSpec ivs = new IvParameterSpec(cumIV);
			cipher.init(Cipher.DECRYPT_MODE, keySpec, ivs);
		}
    	
    	try {
    		
    		return cipher.doFinal(plain);
    		
    	} catch(Exception e) {
    		
    		Cipher ciphert = Cipher.getInstance(AESInstance);
    		if(AESInstance.equals("AES/ECB/PKCS5Padding"))
    			ciphert.init(Cipher.DECRYPT_MODE, keySpec);
    		else
    		{
    			byte[] cumIV = genIV(IV, 16);
    			IvParameterSpec ivs = new IvParameterSpec(cumIV);
    			ciphert.init(Cipher.DECRYPT_MODE, keySpec, ivs);
    		}
    		
    		byte[] ciphertext = new byte[plain.length + 16];
    		System.arraycopy(plain, 0, ciphertext, 0, plain.length);
    		System.arraycopy(don, 0, ciphertext, plain.length, 16);
    		
    		return ciphert.doFinal(ciphertext);
    		
    	}
    	
	}

}

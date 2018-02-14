package cryp.sym;

import java.security.Key;
import java.security.spec.KeySpec;

import javax.crypto.Cipher;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.DESedeKeySpec;
import javax.crypto.spec.IvParameterSpec;

import java.util.Base64;
import java.util.Base64.Encoder;
import java.util.Base64.Decoder;

public class DESede implements sym {
	
	private KeySpec ks;
	private SecretKeyFactory skf;
	private Cipher cipher;
	private String DESInstance = "DESede/ECB/PKCS5Padding";
	private byte[] tIV = {
			(byte)0x00, (byte)0x01, (byte)0x02, (byte)0x03, (byte)0x04, (byte)0x05, (byte)0x06, (byte)0x07,
			(byte)0x08, (byte)0x09, (byte)0x0a, (byte)0x0b, (byte)0x0c, (byte)0x0d, (byte)0x0e, (byte)0x0f,
			(byte)0x00, (byte)0x01, (byte)0x02, (byte)0x03, (byte)0x04, (byte)0x05, (byte)0x06, (byte)0x07,
			(byte)0x08, (byte)0x09, (byte)0x0a, (byte)0x0b, (byte)0x0c, (byte)0x0d, (byte)0x0e, (byte)0x0f,
			(byte)0x00, (byte)0x01, (byte)0x02, (byte)0x03, (byte)0x04, (byte)0x05, (byte)0x06, (byte)0x07,
			(byte)0x08, (byte)0x09, (byte)0x0a, (byte)0x0b, (byte)0x0c, (byte)0x0d, (byte)0x0e, (byte)0x0f
			};
	private IvParameterSpec IV;
	
	public byte[] enc(String plain, byte[] key) throws Exception {
		
		byte[] byte_plain = plain.getBytes();
		
		Encoder encoder = Base64.getEncoder();
		return encoder.encode(enc(byte_plain, key));
	}
	
	public byte[] enc(byte[] plain, byte[] key) throws Exception {
		return encDES(plain, key);
	}
	
	public byte[] enc(String plain, byte[] key, String type, byte[] IV) throws Exception {
		
		this.DESInstance = "DESede/"+type+"/PKCS5Padding";
		this.tIV = IV;
		byte[] byte_plain = plain.getBytes();
		
		Encoder encoder = Base64.getEncoder();
		return encoder.encode(enc(byte_plain, key));
	}
	
	public byte[] enc(byte[] plain, byte[] key, String type, byte[] IV) throws Exception {
		this.DESInstance = "DESede/"+type+"/PKCS5Padding";
		this.tIV = IV;
		return encDES(plain, key);
	}
	
	
	public byte[] dec(String cipher, byte[] key) throws Exception {
		
		byte[] byte_cipher = cipher.getBytes();
		
		Decoder decoder = Base64.getDecoder();
		return decoder.decode(dec(byte_cipher, key));
	}
	
	public byte[] dec(byte[] cipher, byte[] key) throws Exception {
		return decDES(cipher, key);
	}
	
	public byte[] dec(String cipher, byte[] key, String type, byte[] IV) throws Exception {
		this.DESInstance = "DESede/"+type+"/PKCS5Padding";
		this.tIV = IV;
		byte[] byte_cipher = cipher.getBytes();
		
		Decoder decoder = Base64.getDecoder();
		return decoder.decode(dec(byte_cipher, key));
	}
	
	public byte[] dec(byte[] cipher, byte[] key, String type, byte[] IV) throws Exception {
		this.DESInstance = "DESede/"+type+"/PKCS5Padding";
		this.tIV = IV;
		return decDES(cipher, key);
	}
	
	
	private Key getDESKey(byte[] key) throws Exception {
		
		ks = new DESedeKeySpec(key);
		skf = SecretKeyFactory.getInstance("DESede");
		
		return skf.generateSecret(ks);
	}
	
	
	private byte[] genIV(byte[] IV, int len) {
		
		byte[] returnIV = new byte[len];
		
		System.arraycopy(IV, 0, returnIV, 0, len);
		
		return returnIV;
	}
	
	
	private byte[] encDES(byte[] plain, byte[] key) throws Exception {
		
		if(key.length != 24 && key.length != 48)
	    	return null;
		
		Key keySpec = getDESKey(key);
		cipher = Cipher.getInstance(DESInstance);
		if(DESInstance.equals("DESede/ECB/PKCS5Padding"))
			cipher.init(Cipher.ENCRYPT_MODE, keySpec);
		else
		{
			IV = new IvParameterSpec(genIV(tIV, 8));
			cipher.init(Cipher.ENCRYPT_MODE, keySpec, IV);
		}
		
		if((plain.length % 16)!=0)
			return cipher.doFinal(plain);
		else
			return cipher.update(plain);
	}


	private byte[] decDES(byte[] plain, byte[] key) throws Exception {
		
		if(key.length != 24 && key.length != 48)
	    	return null;
		
		Key keySpec = getDESKey(key);
		cipher = Cipher.getInstance(DESInstance);
		if(DESInstance.equals("DESede/ECB/PKCS5Padding"))
			cipher.init(Cipher.DECRYPT_MODE, keySpec);
		else
		{
			IV = new IvParameterSpec(genIV(tIV, 8));
			cipher.init(Cipher.DECRYPT_MODE, keySpec, IV);
		}
		
		try {
			return cipher.doFinal(plain);
		} catch(Exception e) {
			Cipher ciphertmp = Cipher.getInstance(DESInstance);
			if(DESInstance.equals("DESede/ECB/PKCS5Padding"))
				ciphertmp.init(Cipher.ENCRYPT_MODE, keySpec);
			else
			{
				IV = new IvParameterSpec(genIV(tIV, key.length/3));
				ciphertmp.init(Cipher.ENCRYPT_MODE, keySpec, IV);
			}
			byte[] don = {(byte)0xa2, (byte)0x54, (byte)0xbe, (byte)0x88, (byte)0xe0, (byte)0x37, (byte)0xdd, (byte)0xd9};
			byte[] pac = {(byte)0xa2, (byte)0x54, (byte)0xbe, (byte)0x88, (byte)0xe0, (byte)0x37, (byte)0xdd, (byte)0xd9};
			don = ciphertmp.doFinal(pac);
			
			byte[] ciphertext = new byte[plain.length + don.length/2];
    		System.arraycopy(plain, 0, ciphertext, 0, plain.length);
    		System.arraycopy(don, 8, ciphertext, plain.length, 8);
    		
    		return cipher.doFinal(ciphertext);
		}
		
	}


}
package cryp.sym;

import java.util.Base64;
import java.util.Base64.Encoder;
import java.util.Base64.Decoder;

import ozr.encryption.sym.LEA.BlockCipher.Mode;
import ozr.encryption.sym.LEA.BlockCipherMode;
import ozr.encryption.sym.LEA.padding.PKCS5Padding;

public class LEA implements sym, sym_iv {
	
	byte IV[] = {
			(byte)0x026, (byte)0x08d, (byte)0x066, (byte)0x0a7, (byte)0x035, (byte)0x0a8, (byte)0x01a, (byte)0x081,
			(byte)0x026, (byte)0x08d, (byte)0x066, (byte)0x0a7, (byte)0x035, (byte)0x0a8, (byte)0x01a, (byte)0x081,
			(byte)0x026, (byte)0x08d, (byte)0x066, (byte)0x0a7, (byte)0x035, (byte)0x0a8, (byte)0x01a, (byte)0x081,
			(byte)0x026, (byte)0x08d, (byte)0x066, (byte)0x0a7, (byte)0x035, (byte)0x0a8, (byte)0x01a, (byte)0x081
			};
	private byte[] don = {
			(byte)0xfa, (byte)0x83, (byte)0xf0, (byte)0xc0, (byte)0xda, (byte)0xf7, (byte)0xa3, (byte)0xdf,
			(byte)0xc4, (byte)0x90, (byte)0x47, (byte)0xf5, (byte)0x32, (byte)0xf3, (byte)0xa7, (byte)0x92
	};

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
		
		switch(type)
		{
		case "ECB":
		case "ecb":
			return ECB(plain, key, true);
		case "CBC":
		case "cbc":
			return CBC(plain, key, true);
		case "CTR":
			BlockCipherMode cipherctr = new ozr.encryption.sym.LEA.symm.LEA.CTR();
			return CTR_CFB_OFB(plain, key, cipherctr, true);
		case "CFB":
			BlockCipherMode ciphercfb = new ozr.encryption.sym.LEA.symm.LEA.CFB();
			return CTR_CFB_OFB(plain, key, ciphercfb, true);
		case "OFB":
			BlockCipherMode cipherofb = new ozr.encryption.sym.LEA.symm.LEA.OFB();
			return CTR_CFB_OFB(plain, key, cipherofb, true);
		default:
			return null;
		}
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
		
		switch(type)
		{
		case "ECB":
		case "ecb":
			return ECB(cipher, key, false);
		case "CBC":
		case "cbc":
			return CBC(cipher, key, false);
		case "CTR":
			BlockCipherMode cipherctr = new ozr.encryption.sym.LEA.symm.LEA.CTR();
			return CTR_CFB_OFB(cipher, key, cipherctr, false);
		case "CFB":
			BlockCipherMode ciphercfb = new ozr.encryption.sym.LEA.symm.LEA.CFB();
			return CTR_CFB_OFB(cipher, key, ciphercfb, false);
		case "OFB":
			BlockCipherMode cipherofb = new ozr.encryption.sym.LEA.symm.LEA.OFB();
			return CTR_CFB_OFB(cipher, key, cipherofb, false);
		default:
			return null;
		}
	}
	
	
	private byte[] genIV(byte[] IV, int len) {
		
		byte[] returnIV = new byte[len];
		
		System.arraycopy(IV, 0, returnIV, 0, len);
		
		return returnIV;
	}
	
	
	private byte[] ECB(byte[] data, byte[] key, boolean type) {
		
		if(key.length != 16 && key.length != 24 && key.length != 32)
	    	return null;
		
    	BlockCipherMode cipher = new ozr.encryption.sym.LEA.symm.LEA.ECB();
    	
    	if(type)
    	{
    		cipher.init(Mode.ENCRYPT, key);
    		cipher.setPadding(new PKCS5Padding(16));
    		
    		/*
        	byte[] text1 = cipher.update(data);
            byte[] text2 = cipher.doFinal();
            	
        	byte[] ciphertext = new byte[text1.length + text2.length];
        	System.arraycopy(text1, 0, ciphertext, 0, text1.length);
        	System.arraycopy(text2, 0, ciphertext, text1.length, text2.length);
        	
        	return ciphertext;
        	*/
    		
    		return cipher.doFinal(data);
    	}
    	else
    	{
    		cipher.init(Mode.DECRYPT, key);
    		cipher.setPadding(new PKCS5Padding(16));
    		
    		/*
        	byte[] text1 = cipher.update(data);
            byte[] text2 = cipher.doFinal();
            	
        	byte[] ciphertext = new byte[text1.length + text2.length];
        	System.arraycopy(text1, 0, ciphertext, 0, text1.length);
        	System.arraycopy(text2, 0, ciphertext, text1.length, text2.length);
        	
        	return ciphertext;
        	*/
    		
    		return cipher.doFinal(data);
    	}
    	
	}
	
	
	
	private byte[] CBC(byte[] data, byte[] key, boolean type) {
		
		if(key.length != 16 && key.length != 24 && key.length != 32)
	    	return null;
		
		BlockCipherMode cipher = new ozr.encryption.sym.LEA.symm.LEA.CBC();
    	
		if(type)
    	{
			cipher.init(Mode.ENCRYPT, key, genIV(IV, key.length));
    		cipher.setPadding(new PKCS5Padding(16));
    		
    		if((data.length % 16)!=0)
        	{
        		byte[] text1 = cipher.update(data);
            	byte[] text2 = cipher.doFinal();
            	
        		byte[] ciphertext = new byte[text1.length + text2.length];
        		System.arraycopy(text1, 0, ciphertext, 0, text1.length);
        		System.arraycopy(text2, 0, ciphertext, text1.length, text2.length);
        	
        		return ciphertext;
        	}
        	else
        		return cipher.update(data);
    	}
    	else
    	{
    		cipher.init(Mode.DECRYPT, key, genIV(IV, key.length));
    		cipher.setPadding(new PKCS5Padding(16));
    		
    		if((data.length % 16)!=0)
        	{
        		byte[] text1 = cipher.update(data);
            	byte[] text2 = cipher.doFinal();
            	
        		byte[] ciphertext = new byte[text1.length + text2.length];
        		System.arraycopy(text1, 0, ciphertext, 0, text1.length);
        		System.arraycopy(text2, 0, ciphertext, text1.length, text2.length);
        	
        		return ciphertext;
        	}
        	else
        	{
        		byte[] ciphertext = new byte[data.length + don.length];
        		System.arraycopy(data, 0, ciphertext, 0, data.length);
        		System.arraycopy(don, 0, ciphertext, data.length, don.length);
        		
        		return cipher.doFinal(ciphertext);
        	}
    	}
		
	}
	
	
	
	private byte[] CTR_CFB_OFB(byte[] data, byte[] key, BlockCipherMode cipher, boolean type) {
		
		if(key.length != 16 && key.length != 24 && key.length != 32)
	    	return null;
		
		if(type)
    	{
			cipher.init(Mode.ENCRYPT, key, genIV(IV, key.length));
    		cipher.setPadding(new PKCS5Padding(16));
    		
    		if((data.length % 16)!=0)
        	{
        		byte[] text1 = cipher.update(data);
            	byte[] text2 = cipher.doFinal();
            	
        		byte[] ciphertext = new byte[text1.length + text2.length];
        		System.arraycopy(text1, 0, ciphertext, 0, text1.length);
        		System.arraycopy(text2, 0, ciphertext, text1.length, text2.length);
        	
        		return ciphertext;
        	}
        	else
        		return cipher.update(data);
    	}
    	else
    	{
    		cipher.init(Mode.DECRYPT, key, genIV(IV, key.length));
    		cipher.setPadding(new PKCS5Padding(16));
    		
    		if((data.length % 16)!=0)
        	{
        		byte[] text1 = cipher.update(data);
            	byte[] text2 = cipher.doFinal();
            	
        		byte[] ciphertext = new byte[text1.length + text2.length];
        		System.arraycopy(text1, 0, ciphertext, 0, text1.length);
        		System.arraycopy(text2, 0, ciphertext, text1.length, text2.length);
        	
        		return ciphertext;
        	}
        	else
        	{
        		byte[] ciphertext = new byte[data.length + don.length];
        		System.arraycopy(data, 0, ciphertext, 0, data.length);
        		System.arraycopy(don, 0, ciphertext, data.length, don.length);
        		
        		return cipher.doFinal(ciphertext);
        	}
    	}
	}
	
}

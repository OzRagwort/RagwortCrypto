package cryp.hash;

import java.security.MessageDigest;

public class MD5 {
	
	private String strplain = null;
	private byte[] byteplain = null;
	
	private String enc_str() throws Exception {
		
		MessageDigest md5 = MessageDigest.getInstance("MD5");
		
		md5.update(strplain.getBytes());
		
		byte[] hash = md5.digest();
		String output = "";
		
		for(int i = 0 ; i < hash.length ; i++)
			output += String.format("%01x", (hash[i]&0xff))+" ";
		
		return output;
	}
	
	
	private byte[] enc_byte() throws Exception {
		
		MessageDigest md5 = MessageDigest.getInstance("MD5");
		
		md5.update(byteplain);
		
		return md5.digest();
	}
	
	public String md5(String plain) throws Exception {
		this.strplain = plain;
		return enc_str();
	}
	
	public byte[] md5(byte[] plain) throws Exception {
		this.byteplain = plain;
		return enc_byte();
	}

}

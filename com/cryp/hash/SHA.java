package cryp.hash;

import java.security.MessageDigest;

public class SHA {
	
	private String strplain = null;
	private byte[] byteplain = null;
	private String SHA_TYPE = null;
	
	private String enc_str() throws Exception {
		
		MessageDigest md = MessageDigest.getInstance(SHA_TYPE);		//SHA1 224 256 384 512
		
		md.update(strplain.getBytes());
		
		byte[] hash = md.digest();
		String output = "";
		
		for(int i = 0 ; i < hash.length ; i++)
			output += String.format("%01x", (hash[i]&0xff))+" ";
		
		return output;
	}
	
	private byte[] enc_byte() throws Exception {
		
		MessageDigest md = MessageDigest.getInstance(SHA_TYPE);		//SHA1 224 256 384 512
		
		md.update(byteplain);
		
		return md.digest();
	}

	
	public String sha1(String plain) throws Exception {
		this.strplain = plain;
		this.SHA_TYPE = "SHA1";
		return enc_str();
	}

	public String sha224(String plain) throws Exception {
		this.strplain = plain;
		this.SHA_TYPE = "SHA-224";
		return enc_str();
	}

	public String sha256(String plain) throws Exception {
		this.strplain = plain;
		this.SHA_TYPE = "SHA-256";
		return enc_str();
	}

	public String sha384(String plain) throws Exception {
		this.strplain = plain;
		this.SHA_TYPE = "SHA-384";
		return enc_str();
	}

	public String sha512(String plain) throws Exception {
		this.strplain = plain;
		this.SHA_TYPE = "SHA-512";
		return enc_str();
	}
	

	public byte[] sha1(byte[] plain) throws Exception {
		this.byteplain = plain;
		this.SHA_TYPE = "SHA1";
		return enc_byte();
	}

	public byte[] sha224(byte[] plain) throws Exception {
		this.byteplain = plain;
		this.SHA_TYPE = "SHA-224";
		return enc_byte();
	}

	public byte[] sha256(byte[] plain) throws Exception {
		this.byteplain = plain;
		this.SHA_TYPE = "SHA-256";
		return enc_byte();
	}

	public byte[] sha384(byte[] plain) throws Exception {
		this.byteplain = plain;
		this.SHA_TYPE = "SHA-384";
		return enc_byte();
	}

	public byte[] sha512(byte[] plain) throws Exception {
		this.byteplain = plain;
		this.SHA_TYPE = "SHA-512";
		return enc_byte();
	}
	
}

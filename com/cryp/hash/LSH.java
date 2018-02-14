package cryp.hash;

import ozr.hash.LSH.Hash;
import ozr.hash.LSH.Hash.Algorithm;

public class LSH {
	
	private String strplain = null;
	private byte[] byteplain = null;
	private Algorithm LSH_TYPE = null;
	
	private String enc_str() {
		byte[] hash = Hash.digest(LSH_TYPE, strplain.getBytes());
		
		String output = "";
		for(int i = 0 ; i < hash.length ; i++)
			output += String.format("%01x", (hash[i]&0xff))+" ";
		
		return output;
	}
	
	private byte[] enc_byte() {
		return Hash.digest(LSH_TYPE, strplain.getBytes());
	}
	
	public String LSH256_224(String plain) throws Exception {
		this.strplain = plain;
		this.LSH_TYPE = Hash.Algorithm.LSH256_224;
		return enc_str();
	}

	public String LSH256_256(String plain) throws Exception {
		this.strplain = plain;
		this.LSH_TYPE = Hash.Algorithm.LSH256_256;
		return enc_str();
	}

	public String LSH512_224(String plain) throws Exception {
		this.strplain = plain;
		this.LSH_TYPE = Hash.Algorithm.LSH512_224;
		return enc_str();
	}

	public String LSH512_256(String plain) throws Exception {
		this.strplain = plain;
		this.LSH_TYPE = Hash.Algorithm.LSH512_256;
		return enc_str();
	}

	public String LSH512_384(String plain) throws Exception {
		this.strplain = plain;
		this.LSH_TYPE = Hash.Algorithm.LSH512_384;
		return enc_str();
	}

	public String LSH512_512(String plain) throws Exception {
		this.strplain = plain;
		this.LSH_TYPE = Hash.Algorithm.LSH512_512;
		return enc_str();
	}
	
	
	
	public byte[] LSH256_224(byte[] plain) throws Exception {
		this.byteplain = plain;
		this.LSH_TYPE = Hash.Algorithm.LSH256_224;
		return enc_byte();
	}

	public byte[] LSH256_256(byte[] plain) throws Exception {
		this.byteplain = plain;
		this.LSH_TYPE = Hash.Algorithm.LSH256_256;
		return enc_byte();
	}

	public byte[] LSH512_224(byte[] plain) throws Exception {
		this.byteplain = plain;
		this.LSH_TYPE = Hash.Algorithm.LSH512_224;
		return enc_byte();
	}

	public byte[] LSH512_256(byte[] plain) throws Exception {
		this.byteplain = plain;
		this.LSH_TYPE = Hash.Algorithm.LSH512_256;
		return enc_byte();
	}

	public byte[] LSH512_384(byte[] plain) throws Exception {
		this.byteplain = plain;
		this.LSH_TYPE = Hash.Algorithm.LSH512_384;
		return enc_byte();
	}

	public byte[] LSH512_512(byte[] plain) throws Exception {
		this.byteplain = plain;
		this.LSH_TYPE = Hash.Algorithm.LSH512_512;
		return enc_byte();
	}
	
}

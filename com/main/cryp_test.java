package main;

import cryp.sym.*;

import java.util.Arrays;

import cryp.hash.*;

public class cryp_test {
	
	public static void main(String argv[]) {
		
		byte[] text = {
				(byte)0x00, (byte)0x01, (byte)0x02, (byte)0x03, (byte)0x04, (byte)0x05, (byte)0x06, (byte)0x07,
				(byte)0x08, (byte)0x09, (byte)0x0a, (byte)0x0b, (byte)0x0c, (byte)0x0d, (byte)0x0e, (byte)0x0f
		}; //평문
		byte[] key = {
				(byte)0xf0, (byte)0xf1, (byte)0xf2, (byte)0xf3, (byte)0xf4, (byte)0xf5, (byte)0xf6, (byte)0xf7,
				(byte)0xf8, (byte)0xf9, (byte)0xfa, (byte)0xfb, (byte)0xfc, (byte)0xfd, (byte)0xfe, (byte)0xff
		}; //암호에 사용될 키 128bit(16byte)
		byte[] key_des = {
				(byte)0x00, (byte)0x01, (byte)0x02, (byte)0x03, (byte)0x04, (byte)0x05, (byte)0x06, (byte)0x07,	//첫번째 키
				(byte)0x08, (byte)0x09, (byte)0x0a, (byte)0x0b, (byte)0x0c, (byte)0x0d, (byte)0x0e, (byte)0x0f,	//두번째 키
				(byte)0x08, (byte)0x09, (byte)0x0a, (byte)0x0b, (byte)0x0c, (byte)0x0d, (byte)0x0e, (byte)0x0f	//세번째 키
		}; //Triple DES에서 사용될 키 3개
		byte[] cipher = null;
		byte[] cipher_des = null;
		byte[] plain = new byte[text.length];
		
		// LEA 암호화 알고리즘 예시
		AES aes = new AES();
		
		try {
			cipher = aes.enc(text, key);
			plain = aes.dec(cipher, key);
		} catch (Exception e) {
			e.printStackTrace();
		}
		System.out.print("AES's KEY	:	");
		for(int i = 0 ; i < key.length ; i++) {
			System.out.print(Integer.toHexString(key[i]&0xff)+" ");
		}
		System.out.println();
		System.out.print("AES 암호화	:	");
		for(int i = 0 ; i < cipher.length ; i++) {
			System.out.print(Integer.toHexString(cipher[i]&0xff)+" ");
		}
		System.out.println();
		System.out.print("AES 복호화	:	");
		for(int i = 0 ; i < plain.length ; i++) {
			System.out.print(Integer.toHexString(plain[i]&0xff)+" ");
		}
		System.out.println();
		System.out.println();
		
		
		// Triple DES 암호화 알고리즘 예시
		DESede des = new DESede();
		
		try {
			cipher_des = des.enc(text, key_des);
			plain = des.dec(cipher_des, key_des);
		} catch (Exception e) {
			e.printStackTrace();
		}
		
		System.out.print("TDES's KEY	:	");
		for(int i = 0 ; i < key_des.length ; i++) {
			System.out.print(Integer.toHexString(key_des[i]&0xff)+" ");
		}
		System.out.println();
		System.out.print("TDES 암호화	:	");
		for(int i = 0 ; i < cipher_des.length ; i++) {
			System.out.print(Integer.toHexString(cipher_des[i]&0xff)+" ");
		}
		System.out.println();
		System.out.print("TDES 복호화	:	");
		for(int i = 0 ; i < plain.length ; i++) {
			System.out.print(Integer.toHexString(plain[i]&0xff)+" ");
		}
		System.out.println();
		System.out.println();
		
		
		// SHA 해시함수 알고리즘 예시
		SHA sha = new SHA();
		
		try {
			// byte형의 hello문자를 해시화
			byte[] hash = null;
			hash = sha.sha1("hello".getBytes());
			
			System.out.print("SHA 바이트형	:	");
			for(int i = 0 ; i < hash.length ; i++) {
				System.out.print(Integer.toHexString(hash[i]&0xff)+" ");
			}
			System.out.println();
			
			// String형의 hello문자를 해시화
			System.out.print("SHA 문자형	:	");
			System.out.println(sha.sha1("hello"));
			
		} catch (Exception e) {
			e.printStackTrace();
		}
		
		
	}

}

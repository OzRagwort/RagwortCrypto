package cryp.sym;

public interface sym {

	byte[] enc(String plain, byte[] key) throws Exception;

	byte[] enc(byte[] plain, byte[] key) throws Exception;

	byte[] dec(String cipher, byte[] key) throws Exception;

	byte[] dec(byte[] cipher, byte[] key) throws Exception;

}
package cryp.sym;

public interface sym_iv {
	
	byte[] enc(String plain, byte[] key, String type, byte[] IV) throws Exception;

	byte[] enc(byte[] plain, byte[] key, String type, byte[] IV) throws Exception;

	byte[] dec(String cipher, byte[] key, String type, byte[] IV) throws Exception;

	byte[] dec(byte[] cipher, byte[] key, String type, byte[] IV) throws Exception;

}

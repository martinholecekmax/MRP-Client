package algorithms;

import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

/**
 * This class provides the functionality of a cryptographic AES cipher for encrytion and decryption
 * 
 * @author Martin Holecek
 *
 */
public class AESAlgorithm {

	/**
	 * Returns the cipher text encrypted with Cipher Block Chaining mode
	 * 
	 * @param input the input buffer
	 * @param key the encryption key
	 * @param initVector the buffer with the initialization vector
	 * @return encrypted cipher text
	 * @throws NoSuchPaddingException if transformation contains a padding scheme that is not available. 
	 * @throws InvalidAlgorithmParameterException if the given algorithm parameters are inappropriate for this cipher, or this cipher requires algorithm parameters and params is null, or the given algorithm parameters imply a cryptographic strength that would exceed the legal limits (as determined from the configured jurisdiction policy files). 
	 * @throws NoSuchAlgorithmException if transformation is null, empty, in an invalid format, or if a CipherSpi implementation for the specified algorithm is not available from the specified Provider object. 
	 * @throws InvalidKeyException if the given key is inappropriate for initializing this cipher, or requires algorithm parameters that cannot be determined from the given key, or if the given key has a keysize that exceeds the maximum allowable keysize (as determined from the configured jurisdiction policy files). 
	 * @throws BadPaddingException if this cipher is in decryption mode, and (un)padding has been requested, but the decrypted data is not bounded by the appropriate padding bytes
	 * @throws IllegalBlockSizeException if this cipher is a block cipher, no padding has been requested (only in encryption mode), and the total input length of the data processed by this cipher is not a multiple of block size; or if this encryption algorithm is unable to process the input data provided. 
	 */
	public static byte[] encryptCBC(String input, byte[] key, byte[] initVector) throws IllegalBlockSizeException, BadPaddingException, NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, InvalidAlgorithmParameterException {		
		SecretKeySpec skey = new SecretKeySpec(key, 0, 16, "AES");	
		IvParameterSpec iv = new IvParameterSpec(initVector);
		Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
		cipher.init(Cipher.ENCRYPT_MODE, skey, iv);
		byte[] cipherText = cipher.doFinal(input.getBytes());		
		return cipherText;
	}

	/**
	 * Returns the decrypted text, Cipher Block Chaining mode
	 * 
	 * @param input the input buffer
	 * @param key the encryption key, must be 16, 24 or 32 bit long
	 * @param initVector the buffer with the initialization vector, must be 16 bytes long
	 * @return decrypted cipher text
	 * @throws NoSuchPaddingException if transformation contains a padding scheme that is not available. 
	 * @throws NoSuchAlgorithmException if transformation is null, empty, in an invalid format, or if a CipherSpi implementation for the specified algorithm is not available from the specified Provider object. 
	 * @throws InvalidAlgorithmParameterException if the given algorithm parameters are inappropriate for this cipher, or this cipher requires algorithm parameters and params is null, or the given algorithm parameters imply a cryptographic strength that would exceed the legal limits (as determined from the configured jurisdiction policy files). 
	 * @throws InvalidKeyException if the given key is inappropriate for initializing this cipher, or requires algorithm parameters that cannot be determined from the given key, or if the given key has a keysize that exceeds the maximum allowable keysize (as determined from the configured jurisdiction policy files). 
	 * @throws BadPaddingException if this cipher is in decryption mode, and (un)padding has been requested, but the decrypted data is not bounded by the appropriate padding bytes 
	 * @throws IllegalBlockSizeException if this cipher is a block cipher, no padding has been requested (only in encryption mode), and the total input length of the data processed by this cipher is not a multiple of block size; or if this encryption algorithm is unable to process the input data provided. 
	 */
	public static String decryptCBC(byte[] input, byte[] key, byte[] initVector) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException {
		SecretKeySpec skey = new SecretKeySpec(key, 0, 16, "AES");	
		IvParameterSpec iv = new IvParameterSpec(initVector);
		Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
		cipher.init(Cipher.DECRYPT_MODE, skey, iv);
		byte[] plaintext = cipher.doFinal(input);		
		return new String(plaintext);
	}

	/**
	 * Returns the cipher text encrypted with Electronic CodeBook mode
	 * 
	 * @param input the input buffer
	 * @param key the encryption key, must be 16, 24 or 32 bit long
	 * @return encrypted cipher text
	 * @throws NoSuchPaddingException if transformation contains a padding scheme that is not available. 
	 * @throws NoSuchAlgorithmException if transformation is null, empty, in an invalid format, or if a CipherSpi implementation for the specified algorithm is not available from the specified Provider object. 
	 * @throws InvalidKeyException if the given key is inappropriate for initializing this cipher, or requires algorithm parameters that cannot be determined from the given key, or if the given key has a keysize that exceeds the maximum allowable keysize (as determined from the configured jurisdiction policy files). 
	 * @throws BadPaddingException if this cipher is in decryption mode, and (un)padding has been requested, but the decrypted data is not bounded by the appropriate padding bytes
	 * @throws IllegalBlockSizeException if this cipher is a block cipher, no padding has been requested (only in encryption mode), and the total input length of the data processed by this cipher is not a multiple of block size; or if this encryption algorithm is unable to process the input data provided. 
	 */
	public static byte[] encryptECB(String input, byte[] key) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
		SecretKeySpec skey = new SecretKeySpec(key, 0, 16, "AES");	
		Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
		cipher.init(Cipher.ENCRYPT_MODE, skey);
		byte[] cipherText = cipher.doFinal(input.getBytes());		
		return cipherText;
	}

	/**
	 * Returns the decrypted text, Electronic CodeBook mode
	 * 
	 * @param input the input buffer
	 * @param key the decryption key, must be 16, 24 or 32 bit long
	 * @return decrypted cipher text
	 * @throws InvalidKeyException if the given key is inappropriate for initializing this cipher, or requires algorithm parameters that cannot be determined from the given key, or if the given key has a keysize that exceeds the maximum allowable keysize (as determined from the configured jurisdiction policy files). 
	 * @throws NoSuchPaddingException if transformation contains a padding scheme that is not available. 
	 * @throws NoSuchAlgorithmException if transformation is null, empty, in an invalid format, or if a CipherSpi implementation for the specified algorithm is not available from the specified Provider object. 
	 * @throws BadPaddingException if this cipher is in decryption mode, and (un)padding has been requested, but the decrypted data is not bounded by the appropriate padding bytes
	 * @throws IllegalBlockSizeException if this cipher is a block cipher, no padding has been requested (only in encryption mode), and the total input length of the data processed by this cipher is not a multiple of block size; or if this encryption algorithm is unable to process the input data provided. 
	 */
	public static String decryptECB(byte[] input, byte[] key) throws InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException {	
		SecretKeySpec skey = new SecretKeySpec(key, 0, 16, "AES");			
		Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
		cipher.init(Cipher.DECRYPT_MODE, skey);
		byte[] plaintext = cipher.doFinal(input);
		return new String(plaintext);
	}

	/**
	 * Converts cipher text to HEX charset and print result to the console
	 * 
	 * @param cipherText encrypted cipher text
	 */
	public static void printHexCipherText(byte[] cipherText) {
		StringBuffer hexCipherText = new StringBuffer();
		for (int i = 0; i < cipherText.length; i++) {
			hexCipherText.append(Integer.toString((cipherText[i]&0xff)+0x100,16).substring(1));
		}
		System.out.println("Cipher Text is: " + hexCipherText);
	}
}

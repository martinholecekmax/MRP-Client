package client;

import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.net.Socket;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import algorithms.AESAlgorithm;
import algorithms.DESedeAlgorithm;
import diffie_hellman.KeyExchange;

/**
 * This Class creates Session between the server and client.
 * 
 * @author Martin Holecek
 *
 */
public class Session {

	public enum Encryption {
		AES_ECB, AES_CBC, DES_ECB, DES_CBC, PLAIN
	}

	private Socket socket = null;
	private Encryption mode;
	private DataInputStream input = null;
	private DataOutputStream output = null;
	private Logger logger;
	private KeyExchange keyExchange;
	private byte[] key;

	private static final int INITIAL_VECTOR_TRIPLE_DES = 8;
	private static final int INITIAL_VECTOR_AES = 16;
	private static final int TEN_MINUTES_TIMEOUT = 600000;
	
	/**
	 * Initialize Session object
	 * 
	 * @param socket an endpoint for communication between two machines. 
	 * @param logger the logger object which logs any inappropriate behavior of the client
	 * @throws IOException if the stream has been closed or another I/O error
	 */
	public Session(Socket socket, Logger logger) throws IOException {
		this.socket = socket;
		this.logger = logger;
		socket.setSoTimeout(TEN_MINUTES_TIMEOUT);
		input = new DataInputStream(socket.getInputStream());
		output = new DataOutputStream(socket.getOutputStream());
		keyExchange = new KeyExchange();
		mode = Encryption.PLAIN;
	}

	/**
	 * Returns the encryption mode contains the name of encryption algorithm used to encrypt messages between the server and client
	 * 
	 * @return the encryption mode
	 */
	public Encryption getMode() {
		return mode;
	}	
	
	/**
	 * Select which encryption algorithm will be used to encrypt communication between the server and client
	 * 
	 * @param encryption the enumeration of the name of the algorithm
	 * @throws IOException if the stream has been closed or another I/O error
	 * @throws InvalidKeyException if the given key is inappropriate for initializing this cipher, or requires algorithm parameters that cannot be determined from the given key, or if the given key has a keysize that exceeds the maximum allowable keysize (as determined from the configured jurisdiction policy files). 
	 * @throws NoSuchAlgorithmException if transformation is null, empty, in an invalid format, or if a CipherSpi implementation for the specified algorithm is not available from the specified Provider object. 
	 * @throws InvalidKeySpecException if the given key specification is inappropriate for this secret-key factory to produce a secret key.
	 */
	public void selectEncryptionMode(Encryption encryption) throws IOException, InvalidKeyException, NoSuchAlgorithmException, InvalidKeySpecException {
		mode = encryption;
		if (mode != Encryption.PLAIN) {
			key = keyExchange.initClient(this);			
		}		
	}

	/**
	 * Send messages to the client
	 * 
	 * @param input the string object of the message
	 * @throws IOException if the stream has been closed or another I/O error
	 */
	public void write(String input) throws IOException {
		switch (mode) {
		case AES_CBC:	
			sendAESCBC(input);
			break;
		case AES_ECB:
			sendAESECB(input);
			break;
		case DES_CBC:
			sendDESedeCBC(input);
			break;
		case DES_ECB:	
			sendDESedeECB(input);
			break;
		case PLAIN:	
			sendBytes(input.getBytes());
			break;		
		}
	}

	/**
	 * Read message sent by the client
	 * 
	 * @return string object sent from the client
	 * @throws IOException if the stream has been closed or another I/O error
	 */
	public String read() throws IOException {
		switch (mode) {
		case AES_CBC:
			return readAESCBC();
		case AES_ECB:
			return readAESECB();
		case DES_CBC:
			return readDESedeCBC();
		case DES_ECB:
			return readDESedeECB();
		case PLAIN:	
			return new String(readBytes());
		}
		return null;
	}

	/**
	 * Send bytes to the client
	 * 
	 * @param keyBytes the buffer with message to be sent to the client
	 * @throws IOException if the stream has been closed or another I/O error
	 */
	public void sendBytes(byte[] keyBytes) throws IOException {
		output.writeInt(keyBytes.length);
		output.write(keyBytes);
	}

	/**
	 * Read bytes sent from the client
	 * @return the new buffer with message from the client
	 * @throws IOException if the stream has been closed or another I/O error
	 */
	public byte[] readBytes() throws IOException {
		byte[] keyBytes = new byte[input.readInt()];
		input.readFully(keyBytes);
		return keyBytes;
	}
	
	/**
	 * Close data streams and socket connection
	 */
	public void close() {
		try {
			input.close();
			output.close();
			socket.close();
		} catch (IOException e) {
			logger.log(Level.SEVERE, "Error timeout exceeded", e);
		}
	}
	
	/**
	 * Send message to the client encrypted by AES Algorithm with Electronic CodeBook mode
	 * 
	 * @param message the string object to be sent to the client
	 * @throws IOException if the stream has been closed or another I/O error
	 */
	private void sendAESECB(String message) throws IOException {
		try {
			byte[] data = AESAlgorithm.encryptECB(message, key);
			sendBytes(data);
		} catch (InvalidKeyException | NoSuchAlgorithmException | NoSuchPaddingException | IllegalBlockSizeException
				| BadPaddingException e) {
			logger.log(Level.SEVERE, "AES Algorithm failed to encrypt data!", e);
			throw new IOException(e);
		}
	}
	
	/**
	 * Send message to the client encrypted by AES Algorithm with Cipher Block Chaining mode
	 * 
	 * @param message the string object to be sent to the client
	 * @throws IOException if the stream has been closed or another I/O error
	 */
	private void sendAESCBC(String message) throws IOException {
		try {
			byte[] initVector = getInitialVector(INITIAL_VECTOR_AES);
			byte[] data = AESAlgorithm.encryptCBC(message, key, initVector);
			sendBytes(initVector);
			sendBytes(data);
		} catch (InvalidKeyException | IllegalBlockSizeException | BadPaddingException | NoSuchAlgorithmException
				| NoSuchPaddingException | InvalidAlgorithmParameterException e) {
			logger.log(Level.SEVERE, "AES Algorithm failed to encrypt data!", e);
			throw new IOException(e);
		}
	}
	
	/**
	 * Send message to the client encrypted by Triple DES Algorithm with Electronic CodeBook mode
	 * 
	 * @param message the string object to be sent to the client
	 * @throws IOException if the stream has been closed or another I/O error
	 */
	private void sendDESedeECB(String message) throws IOException {
		try {
			byte[] data = DESedeAlgorithm.encryptECB(message, key);
			sendBytes(data);
		} catch (InvalidKeyException | NoSuchAlgorithmException | InvalidKeySpecException | NoSuchPaddingException
				| IllegalBlockSizeException | BadPaddingException e) {
			logger.log(Level.SEVERE, "DES Algorithm failed to encrypt data!", e);
			throw new IOException(e);
		}
	}
	
	/**
	 * Send message to the client encrypted by Triple DES Algorithm with Cipher Block Chaining mode
	 * 
	 * @param message the string object to be sent to the client
	 * @throws IOException if the stream has been closed or another I/O error
	 */
	private void sendDESedeCBC(String message) throws IOException {
		byte[] initVector = getInitialVector(INITIAL_VECTOR_TRIPLE_DES);
		byte[] data;
		try {
			data = DESedeAlgorithm.encryptCBC(message, key, initVector);
		} catch (InvalidKeyException | NoSuchAlgorithmException | InvalidKeySpecException | NoSuchPaddingException
				| InvalidAlgorithmParameterException | IllegalBlockSizeException | BadPaddingException e) {
			logger.log(Level.SEVERE, "DES Algorithm failed to encrypt data!", e);
			throw new IOException(e);
		}
		sendBytes(initVector);
		sendBytes(data);
	}
	
	/**
	 * Read message from the client encrypted by AES Algorithm with Electronic CodeBook mode
	 * 
	 * @return decrypted message sent by the client
	 * @throws IOException if the stream has been closed or another I/O error
	 */
	private String readAESECB() throws IOException {
		try {
			byte[] data = readBytes();
			return AESAlgorithm.decryptECB(data, key);
		} catch (InvalidKeyException | NoSuchAlgorithmException | NoSuchPaddingException | IllegalBlockSizeException
				| BadPaddingException e) {
			logger.log(Level.SEVERE, "AES Algorithm failed to decrypt data!", e);
			throw new IOException(e);
		}
	}

	/**
	 * Read message from the client encrypted by AES Algorithm with Cipher Block Chaining mode
	 * 
	 * @return decrypted message sent by the client
	 * @throws IOException if the stream has been closed or another I/O error
	 */
	private String readAESCBC() throws IOException {
		try {
			byte[] iv = readBytes();
			byte[] data = readBytes();
			return AESAlgorithm.decryptCBC(data, key, iv);
		} catch (InvalidKeyException | NoSuchAlgorithmException | NoSuchPaddingException
				| InvalidAlgorithmParameterException | IllegalBlockSizeException | BadPaddingException e) {
			logger.log(Level.SEVERE, "AES Algorithm failed to decrypt data!", e);
			throw new IOException(e);
		}
	}
		
	/**
	 * Read message from the client encrypted by Triple DES Algorithm with Electronic CodeBook mode
	 * 
	 * @return decrypted message sent by the client
	 * @throws IOException if the stream has been closed or another I/O error
	 */
	private String readDESedeECB() throws IOException {
		try {
			byte[] data = readBytes();
			String text = DESedeAlgorithm.decryptECB(data, key);
			return text;
		} catch (InvalidKeyException | NoSuchAlgorithmException | InvalidKeySpecException | NoSuchPaddingException
				| IllegalBlockSizeException | BadPaddingException e) {
			logger.log(Level.SEVERE, "DES Algorithm failed to decrypt data!", e);
			throw new IOException(e);
		}
	}

	/**
	 * Read message from the client encrypted by Triple DES Algorithm with Cipher Block Chaining mode
	 * 
	 * @return decrypted message sent by the client
	 * @throws IOException if the stream has been closed or another I/O error
	 */
	private String readDESedeCBC() throws IOException {
		try {
			byte[] iv = readBytes();
			byte[] data = readBytes();
			return DESedeAlgorithm.decryptCBC(data, key, iv);
		} catch (InvalidKeyException | NoSuchAlgorithmException | InvalidKeySpecException | NoSuchPaddingException
				| InvalidAlgorithmParameterException | IllegalBlockSizeException | BadPaddingException e) {
			logger.log(Level.SEVERE, "DES Algorithm failed to decrypt data!", e);
			throw new IOException(e);
		}
	}
	
	/**
	 * Return randomly generated initialization vector (IV) by using Secure Random value
	 * 
	 * @param ivSizeBytes the size of the buffer with the initialization vector
	 * @return the buffer with the initialization vector
	 */
	private static byte[] getInitialVector(int ivSizeBytes) {
		byte[] iv = new byte[ivSizeBytes];
		SecureRandom random = new SecureRandom();
		random.nextBytes(iv);
		return iv;
	}
}
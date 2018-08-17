package diffie_hellman;

import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import javax.crypto.KeyAgreement;
import client.Session;

/**
 * This class provides mechanism for key exchange using Diffie-Hellman method
 * 
 * @author Maxim
 *
 */
public class KeyExchange {
	private static final int KEY_SIZE = 2048;
	private static final String DIFFIE_HELLMAN_ALGORITHM = "DH";

	/**
	 * Initialize key exchange between server and client. This method MUST be used by the client to initialize key exchange.
	 * 
	 * @param session the object that handles connection between server and client
	 * @return the secret key object used for encryption
	 * @throws IOException if the stream has been closed or another I/O error
	 * @throws InvalidKeySpecException if the given key specification is inappropriate for this secret-key factory to produce a secret key.
	 * @throws NoSuchAlgorithmException if transformation is null, empty, in an invalid format, or if a CipherSpi implementation for the specified algorithm is not available from the specified Provider object. 
	 * @throws InvalidKeyException if the given key is inappropriate for initializing this cipher, or requires algorithm parameters that cannot be determined from the given key, or if the given key has a keysize that exceeds the maximum allowable keysize (as determined from the configured jurisdiction policy files). 
	 */
	public byte[] initClient(Session session) throws IOException, NoSuchAlgorithmException, InvalidKeySpecException, InvalidKeyException {
		KeyPair keyPair = generateKeyPair();
		sendPublicKey(session, keyPair);
		PublicKey publicKey = readPublicKey(session);
		return generateSecret(keyPair, publicKey);
	}

	/**
	 * Initialize key exchange between server and client. This method MUST be used by the server to initialize key exchange.
	 * 
	 * @param session the object that handles connection between server and client
	 * @return the secret key object used for encryption
	 * @throws IOException if the stream has been closed or another I/O error
	 * @throws InvalidKeySpecException if the given key specification is inappropriate for this secret-key factory to produce a secret key.
	 * @throws NoSuchAlgorithmException if transformation is null, empty, in an invalid format, or if a CipherSpi implementation for the specified algorithm is not available from the specified Provider object. 
	 * @throws InvalidKeyException if the given key is inappropriate for initializing this cipher, or requires algorithm parameters that cannot be determined from the given key, or if the given key has a keysize that exceeds the maximum allowable keysize (as determined from the configured jurisdiction policy files). 
	 */
	public byte[] initServer(Session session) throws IOException, NoSuchAlgorithmException, InvalidKeySpecException, InvalidKeyException {
		KeyPair keyPair = generateKeyPair();
		PublicKey publicKey = readPublicKey(session);
		sendPublicKey(session, keyPair);
		return generateSecret(keyPair, publicKey);
	}

	/**
	 * Generate private and public key
	 * 
	 * @return the generated key pair
	 * @throws NoSuchAlgorithmException if no Provider supports a KeyPairGeneratorSpi implementation for the specified algorithm.
	 */
	private KeyPair generateKeyPair() throws NoSuchAlgorithmException {
		KeyPairGenerator kpg = KeyPairGenerator.getInstance(DIFFIE_HELLMAN_ALGORITHM);
		kpg.initialize(KEY_SIZE);
		KeyPair keyPair = kpg.genKeyPair();
		return keyPair;		
	}

	/**
	 * Send public key to the server or client over the network.
	 * 
	 * @param session the object that handles connection between server and client
	 * @param keyPair the keyPair object of the public and private key
	 * @throws IOException if the stream has been closed or another I/O error
	 */
	private void sendPublicKey(Session session, KeyPair keyPair) throws IOException {		
		byte[] keyBytes = keyPair.getPublic().getEncoded();
		session.sendBytes(keyBytes);		
	}

	/**
	 * Read public key sent by the server or client over the network
	 * 
	 * @param session the object that handles connection between server and client
	 * @return a reference to the public key
	 * @throws IOException if the stream has been closed or another I/O error
	 * @throws NoSuchAlgorithmException if transformation is null, empty, in an invalid format, or if a CipherSpi implementation for the specified algorithm is not available from the specified Provider object. 
	 * @throws InvalidKeySpecException if the given key specification is inappropriate for this secret-key factory to produce a secret key.
	 */
	private PublicKey readPublicKey(Session session) throws IOException, NoSuchAlgorithmException, InvalidKeySpecException {		
		byte[] keyBytes = session.readBytes();
		KeyFactory keyFactory = KeyFactory.getInstance(DIFFIE_HELLMAN_ALGORITHM);
		X509EncodedKeySpec x509EncodedKeySpec = new X509EncodedKeySpec(keyBytes);
		PublicKey publicKey = keyFactory.generatePublic(x509EncodedKeySpec);		
		return publicKey;
	}

	/**
	 * Generate shared secret from keyPair object and public key
	 * 
	 * @param keyPair the keyPair object contains the public and private key
	 * @param publicKey the public key object
	 * @return the new buffer with the shared secret 
	 * @throws NoSuchAlgorithmException if no Provider supports a KeyAgreementSpi implementation for the specified algorithm
	 * @throws InvalidKeyException if the given key is inappropriate for this phase
	 */
	private byte[] generateSecret(KeyPair keyPair, Key publicKey) throws NoSuchAlgorithmException, InvalidKeyException {
		KeyAgreement keyAgreement = KeyAgreement.getInstance(DIFFIE_HELLMAN_ALGORITHM);
		keyAgreement.init(keyPair.getPrivate());
		keyAgreement.doPhase(publicKey, true);
		return keyAgreement.generateSecret();
	}
}

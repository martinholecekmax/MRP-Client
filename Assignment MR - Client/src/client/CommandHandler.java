package client;

import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.util.ArrayList;
import java.util.Scanner;
import client.Session.Encryption;

/**
 * This class handles sending commands to the server and receiving responses from the server
 * 
 * @author Martin Holecek
 *
 */
public class CommandHandler {

	private Session session;
	private Scanner scanner;
	private ArrayList<Message> messages;
	private boolean testLoop;

	/**
	 * Creates command handler object
	 * 
	 * @param session the object that handles connection between server and client
	 * @param scanner reads string from user
	 */
	public CommandHandler(Session session, Scanner scanner) {
		this.session = session;
		this.scanner = scanner;
		messages = new ArrayList<>();
		testLoop = true;
	}

	/**
	 * This method starts sending commands to the server and receiving responses from the server
	 * 
	 * @throws IOException if the stream has been closed or another I/O error
	 * @throws InvalidKeyException if the given key is inappropriate for initializing this cipher, or requires algorithm parameters that cannot be determined from the given key, or if the given key has a keysize that exceeds the maximum allowable keysize (as determined from the configured jurisdiction policy files). 
	 * @throws NoSuchAlgorithmException if transformation is null, empty, in an invalid format, or if a CipherSpi implementation for the specified algorithm is not available from the specified Provider object. 
	 * @throws InvalidKeySpecException if the given key specification is inappropriate for this secret-key factory to produce a secret key.
	 */
	public void start() throws IOException, InvalidKeyException, NoSuchAlgorithmException, InvalidKeySpecException {
		while (testLoop) {
			// Print message to the user console
			System.out.println("Please Enter Command: ");
			System.out.print("--> ");

			// Get Recipient from user input
			String command = scanner.nextLine();
			command = command.trim();

			if(!selsectCommand(command)) {
				testLoop = false;
			}
		}
	}

	/**
	 * Select command that will be send to the server
	 * 
	 * @param command string object that client wants to send to the server
	 * @return false if client want to terminate connection, true otherwise
	 * @throws IOException if the stream has been closed or another I/O error
	 * @throws InvalidKeyException if the given key is inappropriate for initializing this cipher, or requires algorithm parameters that cannot be determined from the given key, or if the given key has a keysize that exceeds the maximum allowable keysize (as determined from the configured jurisdiction policy files). 
	 * @throws NoSuchAlgorithmException if transformation is null, empty, in an invalid format, or if a CipherSpi implementation for the specified algorithm is not available from the specified Provider object. 
	 * @throws InvalidKeySpecException if the given key specification is inappropriate for this secret-key factory to produce a secret key.
	 */
	private boolean selsectCommand(String command) throws IOException, InvalidKeyException, NoSuchAlgorithmException, InvalidKeySpecException {
		if (command.toUpperCase().startsWith("AUTH")) {
			authCommand(command);
		} else if (command.equalsIgnoreCase("QUIT")) {
			return false;
		} else if (command.toUpperCase().startsWith("FETCH")) {
			fetchCommand(command);
		} else {
			sendAnyCommand(command);
		}
		return true;
	}

	/**
	 * This method will send any command to the server, except AUTH, QUIT and FETCH Commands.
	 * These commands are handled in separated methods.
	 * 
	 * @param command string object that client wants to send to the server
	 * @throws IOException if the stream has been closed or another I/O error
	 */
	private void sendAnyCommand(String command) throws IOException {
		session.write(command);
		String serverResponse = session.read();
		if (serverResponse.startsWith("BAD")) {
			System.out.println(serverResponse);
		} else if (serverResponse.startsWith("*")) {
			System.out.println(serverResponse);
			do {
				serverResponse = session.read();
				System.out.println(serverResponse);
			} while (!serverResponse.startsWith("OK"));
		} else {
			System.out.println(serverResponse);
		}
	}

	/**
	 * This method handles sending of the AUTH Command which will set encryption algorithm
	 * 
	 * @param command string object that client wants to send to the server
	 * @throws IOException if the stream has been closed or another I/O error
	 * @throws InvalidKeyException if the given key is inappropriate for initializing this cipher, or requires algorithm parameters that cannot be determined from the given key, or if the given key has a keysize that exceeds the maximum allowable keysize (as determined from the configured jurisdiction policy files). 
	 * @throws NoSuchAlgorithmException if transformation is null, empty, in an invalid format, or if a CipherSpi implementation for the specified algorithm is not available from the specified Provider object. 
	 * @throws InvalidKeySpecException if the given key specification is inappropriate for this secret-key factory to produce a secret key.
	 */
	private void authCommand(String command) throws IOException, InvalidKeyException, NoSuchAlgorithmException, InvalidKeySpecException {		
		String[] message = command.split(" ");
		if(message.length == 2) {
			switch (message[1].toUpperCase()) {
			case "AES/ECB":
				session.write("AUTH AES/ECB");
				session.selectEncryptionMode(Encryption.AES_ECB);
				System.out.println(session.read());
				break;
			case "AES/CBC":
				session.write("AUTH AES/CBC");
				session.selectEncryptionMode(Encryption.AES_CBC);
				System.out.println(session.read());
				break;
			case "DES/ECB":			
				session.write("AUTH DES/ECB");
				session.selectEncryptionMode(Encryption.DES_ECB);
				System.out.println(session.read());
				break;
			case "DES/CBC":
				session.write("AUTH DES/CBC");
				session.selectEncryptionMode(Encryption.DES_CBC);
				System.out.println(session.read());
				break;
			case "PLAIN":
				session.write("AUTH PLAIN");
				session.selectEncryptionMode(Encryption.PLAIN);
				System.out.println(session.read());
				break;
			default:
				session.write(command);
				break;
			}
			System.out.println(session.read());
		} else {
			System.out.println("Wrong command");
		}
	}

	/**
	 * This method handles sending of the FETCH Command that retrieve messages from the server
	 * 
	 * @param command string object that client wants to send to the server
	 * @throws IOException if the stream has been closed or another I/O error
	 */
	private void fetchCommand(String command) throws IOException {
		messages.clear();
		session.write(command);
		String serverResponse = session.read();
		String message = "";
		if (serverResponse.startsWith("BAD")) {
			System.out.println(serverResponse);
		} else if (serverResponse.startsWith("*")) {
			do {
				serverResponse = session.read();
				if (!serverResponse.startsWith("OK FETCH")) {
					message += serverResponse;
				}
			} while (!serverResponse.startsWith("OK FETCH"));
			parseMessages(message);
			displayVerboseMessage();
		} else {
			System.out.println(serverResponse);
		}
	}

	/**
	 * Parse the message string object from the server into the message object
	 * 
	 * @param input string object that contains message data
	 */
	private void parseMessages(String input) {
		String parse[] = input.split("\r\n");
		String message = "";
		for (String string : parse) {
			if (string.startsWith("*")) {
				createMessage(message);
				message = "";
			} else {
				message += string + "\r\n";
			}
		}
		createMessage(message);
	}

	/**
	 * Set individual parts of the message from the input string object
	 * 
	 * @param input string object that contains message data
	 */
	private void createMessage(String input) {
		Message message = new Message();
		String parse[] = input.split("\r\n");
		for (String string : parse) {
			if (string.startsWith("ID: ")) {
				message.setMessageID(Integer.parseInt(string.substring(4)));
			} else if (string.startsWith("UID:")) {
				message.setMessageUID(Integer.parseInt(string.substring(5)));
			} else if (string.startsWith("Sender:")) {
				message.setSender(string.substring(8));
			} else if (string.startsWith("Recipients:")) {
				message.setRecipients(string.substring(12));
			} else if (string.startsWith("Subject:")) {
				message.setSubject(string.substring(9));
			} else if (string.startsWith("Date:")) {
				message.setDate(java.sql.Date.valueOf(string.substring(6)));
			} else if (string.startsWith("Mime:")) {
				message.setMime(string.substring(6));
			} else {
				message.setBody(string);
			}
		}
		messages.add(message);
	}

	/**
	 * Print message to the console
	 */
	private void displayVerboseMessage() {
		System.out.println("Number of messages: " + messages.size());
		for (Message message : messages) {
			System.out.println("///////////////// BEGIN MAIL /////////////////");
			System.out.println(message);
			System.out.println("///////////////// END MAIL /////////////////");
		}
	}

	/**
	 * Send quit to the server and close transmission channel
	 * 
	 * @throws IOException if the stream has been closed or another I/O error
	 */
	public void sendQuit() throws IOException {
		// Send QUIT Command to the SMTP Server
		session.write("QUIT");

		// Check if server response is OK
		if(session.read().startsWith("2")) {
			System.out.println("\nProgram Terminated ...");

			// Close socket and data streams
			session.close();
		}
		System.out.println("Client Terminated");
	}

	/**
	 * Check if server is available
	 * 
	 * @return true if server is ready, false otherwise
	 * @throws IOException if the stream has been closed or another I/O error
	 */
	public boolean checkServerConnection() throws IOException {
		// Connection established
		String input = session.read();

		// Check if server response is OK
		if (!input.startsWith("OK")) {
			System.out.println("\n" + input + "\n");
			return false;
		} else {
			System.out.println("\n" + input + "\n");
			return true;
		}
	}
}

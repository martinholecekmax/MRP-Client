package client;
import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.util.Scanner;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * This class initialize client and handles connection to the server
 * 
 * @author Martin Holecek
 * 
 */
public class ClientHandler implements Runnable{
	private CommandHandler commandHandler;
	private Logger logger;

	/**
	 * Constructs client handler object that handles connection to the server
	 * 
	 * @param session sends and receives messages from the SMTP Server
	 * @param scanner reads string from user
	 * @param logger is used to log any errors to the file or console
	 */
	public ClientHandler(Session session, Logger logger, Scanner scanner) {
		this.logger = logger;
		commandHandler = new CommandHandler(session, scanner);
	}

	/**
	 * Starting the thread will called this method
	 * 
	 * {@inheritDoc} implementation of the runnable interface
	 */
	public void run() {
		try {
			// Connection Establishment
			if(!commandHandler.checkServerConnection()) {
				commandHandler.sendQuit();
				return;
			}

			// Process commands
			commandHandler.start();
			
			// Close connection
			commandHandler.sendQuit();

		} catch (IOException | InvalidKeyException | NoSuchAlgorithmException | InvalidKeySpecException e) {
			logger.log(Level.SEVERE, "Input Error", e);			
			System.out.println("Program has been Terminated ...");
		}
	}
}
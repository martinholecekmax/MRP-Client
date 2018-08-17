package client;

import java.io.IOException;
import java.net.Socket;
import java.net.UnknownHostException;
import java.util.Scanner;
import java.util.logging.ConsoleHandler;
import java.util.logging.FileHandler;
import java.util.logging.Level;
import java.util.logging.LogManager;
import java.util.logging.Logger;

/**
 * This program allow user to fetch emails from Message Retrieval Server
 * 
 * @author Martin Holecek
 *
 */
public class Client {
	private int port = 5000;
	private boolean verbose = true;
	private final static Logger lOGGER = Logger.getLogger("ServerHandler");
	private static Scanner scanner = new Scanner(System.in);
	private ClientHandler clientHandler;

	/**
	 * Constructs client object that connects to the server
	 * 
	 * @param port number must be between 2048 and 65535 
	 * @param verbose if true error are visible otherwise errors are saved to the file only
	 */
	public Client(int port, boolean verbose) {
		// range of the port number must be valid
		if (port > 2048 && port < 65535) {
			this.port = port;
		}
		this.verbose = verbose;
	}

	/**
	 * This method will start client
	 */
	public void StartClient() {
		
		// Initialize logger
		InitializeLogger();
		
		try {
			// Create socket
			Socket socket = new Socket("localhost", port);
			//Socket socket = new Socket("192.168.1.5", port);
			//Socket socket = new Socket("192.168.1.2", port);
			//Socket socket = new Socket("192.168.1.16", port);
			//Socket socket = new Socket("martinholecekmax.ddns.net", port);
			
			// Create new session
			Session session = new Session(socket, lOGGER);

			// Create new client handler
			clientHandler = new ClientHandler(session, lOGGER, scanner);
			Thread clientHandlerThread = new Thread(clientHandler);
			clientHandlerThread.start();

		} catch (UnknownHostException e) {
			lOGGER.log(Level.SEVERE, "Host is unknown", e);
			System.out.println("\nError Unknown Host Exception, Program Terminated ...");
		} catch (IOException e) {
			lOGGER.log(Level.SEVERE, "Input Error", e);
			System.out.println("\nIO Exception, Program Terminated ....");
		}
	}

	/**
	 * This method will initialize logger file and if the verbose is set
	 * then it will also add console handler to print logs into the console.
	 * 
	 * @throws SecurityException is when the file handler fails to create file
	 */
	private void InitializeLogger(){
		LogManager.getLogManager().reset();
		lOGGER.setLevel(Level.ALL);

		// Print logger messages to the file
		try {
			FileHandler fileHandler = new FileHandler("logger.log");
			fileHandler.setLevel(Level.ALL);
			lOGGER.addHandler(fileHandler);
		} catch (IOException | SecurityException ex) {
			lOGGER.log(Level.SEVERE, "File logger not working !!!", ex);

			// If file handler fail to load log messages in the console
			ConsoleHandler consoleHandler = new ConsoleHandler();
			consoleHandler.setLevel(Level.SEVERE);
			lOGGER.addHandler(consoleHandler);
		}

		if (verbose) {
			// Print logger messages in the console
			ConsoleHandler consoleHandler = new ConsoleHandler();
			consoleHandler.setLevel(Level.SEVERE);
			lOGGER.addHandler(consoleHandler);
		}
	}
	
	/**
	 * Start point of the program
	 * 
	 * @param args the command line arguments are not used
	 */
	public static void main(String[] args) {	
		
		// Print banner
		printBanner();
		
		// Initialize port number to zero
		int port = 0;
		boolean verbose = true;
				
		// Check if user inputs number as a port
		port = getPortNumber();
		
		// Check if user will see error messages
		verbose = getVerbose();
		
		// Create the Client
		Client client = new Client(port, verbose);
		client.StartClient();
	}

	/**
	 * Print ASCII ART banner to the console
	 */
	private static void printBanner() {
		System.out.println("");
		System.out.println("  (       *            (             (     (            )          ");
		System.out.println("  )\\ )  (  `     *   ) )\\ )     (    )\\ )  )\\ )      ( /(   *   )  ");
		System.out.println(" (()/(  )\\))(  ` )  /((()/(     )\\  (()/( (()/( (    )\\())` )  /(  ");
		System.out.println("  /(_))((_)()\\  ( )(_))/(_))  (((_)  /(_)) /(_)))\\  ((_)\\  ( )(_)) ");
		System.out.println(" (_))  (_()((_)(_(_())(_))    )\\___ (_))  (_)) ((_)  _((_)(_(_())  ");
		System.out.println(" / __| |  \\/  ||_   _|| _ \\  ((/ __|| |   |_ _|| __|| \\| ||_   _|  ");
		System.out.println(" \\__ \\ | |\\/| |  | |  |  _/   | (__ | |__  | | | _| | .` |  | |    ");
		System.out.println(" |___/ |_|  |_|  |_|  |_|      \\___||____||___||___||_|\\_|  |_|    ");
		System.out.println("");
	}

	/**
	 * User can set if he wants to see error messages.
	 * Default verbose is true.
	 * 
	 * @return true if user sets verbose
	 */
	private static boolean getVerbose() {
		// Ask user if he wants verbose
		System.out.println("\nDo you want messages to be verbose? (y or n, default = y): ");
		
		// Get input from user
		String input = scanner.nextLine();
		
		// Set verbose
		if (input.equalsIgnoreCase("N")) {
			System.out.println("Verbose is disabled.");
			return false;
		} else if (input.equalsIgnoreCase("Y")) {
			System.out.println("Verbose is enabled.");
			return true;
		} else {
			System.out.println("\nSorry, Wrong answer, Verbose is enabled.");
			return true;
		}
	}

	/**
	 * Get port number from user input
	 * 
	 * @return port number
	 */
	private static int getPortNumber() {
		// Initialize scanner and port number
		int port = 0;
		
		// Check if user enters valid port number
		boolean validPort = true;
		do {
			
		// Ask user to enter the port number
		System.out.println("Please Enter Port Number: ");

		// Get port number from user input
		String input = scanner.nextLine();

			try {
				// Try to parse integer
				port = Integer.parseInt(input);
				
				// Port number must be between 2048 and 65535 
				if (port > 2048 && port < 65535) {
					validPort = false;
				} else {
					System.out.println("Port number must be between 2048 and 65535");
				}
			} catch (Exception e) {
				// port is not valid port number
				System.out.println("\"" + input + "\" is not valid Port Number.");
				System.out.println("Port must be a number!");
			}
		} while (validPort);
		
		return port;
	}
}
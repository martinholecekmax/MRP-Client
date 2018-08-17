package client;

import java.sql.Date;

/**
 * This class hold information of the message
 * 
 * @author Martin Holecek
 *
 */
public class Message {
	private int messageID;
	private int messageUID;
	private String sender;
	private String recipients;
	private String subject;
	private Date date;
	private String body;
	private String mime;

	private static final Date DEFAULT_DATE = new Date(System.currentTimeMillis());
	private static final String EMPTY_STRING = "";
	private static final String EMPTY_SUBJECT = "Empty subject";
	private static final int DEFAULT_ID = 0;
	private static final String CRLF = "\r\n";

	/**
	 * Initialize message object
	 */
	public Message() {
		messageID = DEFAULT_ID;
		sender = EMPTY_STRING;
		recipients = EMPTY_STRING;
		subject = EMPTY_STRING;
		date = DEFAULT_DATE;
		body = EMPTY_STRING;
		mime = EMPTY_STRING;
	}

	/**
	 * Return message ID
	 * 
	 * @return message ID
	 */
	public int getMessageID() {
		return messageID;
	}

	/**
	 * Set message ID
	 * 
	 * @param messageID the message ID
	 */
	public void setMessageID(int messageID) {
		this.messageID = messageID;
	}

	/**
	 * Return message unique identifier (UID)
	 * 
	 * @return message UID
	 */
	public int getMessageUID() {
		return messageUID;
	}

	/**
	 * Set message unique identifier (UID)
	 * 
	 * @param messageUID message UID
	 */
	public void setMessageUID(int messageUID) {
		this.messageUID = messageUID;
	}
	
	/**
	 * Return sender of a message
	 * 
	 * @return a sender of the message
	 */
	public String getSender() {
		return sender;
	}

	/**
	 * Set sender of a message
	 * 
	 * @param sender the string object of the message sender
	 */
	public void setSender(String sender) {
		this.sender = sender;
	}

	/**
	 * Return recipient of a message
	 * 
	 * @return a recipient of the message
	 */
	public String getRecipients() {
		return recipients;
	}

	/**
	 * Set recipients of a message
	 * 
	 * @param recipients the string object of the message recipients
	 */
	public void setRecipients(String recipients) {
		this.recipients = recipients;
	}

	/**
	 * Return subject of a message
	 * 
	 * @return a subject of the message
	 */
	public String getSubject() {
		if (subject.isEmpty()) {
			return EMPTY_SUBJECT;
		}
		return subject;
	}

	/**
	 * Set subject of a message
	 * @param subject the string object of the message subject
	 */
	public void setSubject(String subject) {
		this.subject = subject;
	}

	/**
	 * Return received date of the message
	 * 
	 * @return a date of the message
	 */
	public Date getDate() {
		return date;
	}

	/**
	 * Return string object of the received date of the message
	 * 
	 * @return a string object of a date
	 */
	public String getDateText() {
		return date.toString();
	}

	/**
	 * Set date of the message
	 * 
	 * @param date the date object
	 */
	public void setDate(Date date) {
		this.date = date;
	}

	/**
	 * Return body of the message
	 * 
	 * @return the string object of the message body
	 */
	public String getBody() {
		return body;
	}

	/**
	 * Set body of the message
	 * 
	 * @param body the string object of the message body
	 */
	public void setBody(String body) {
		this.body = body;
	}

	/**
	 * Return the mime header of the message
	 * 
	 * @return the string object of the message mime header
	 */
	public String getMime() {
		return mime;
	}

	/**
	 * Set message mime header
	 * 
	 * @param header the string object of the message mime header
	 */
	public void setMime(String header) {
		this.mime = header;
	}
		
	/**
	 * The string representation of the message
	 * 
	 * {@inheritDoc} toString in class Object
	 */
	public String toString() {
		String fullMessage = EMPTY_STRING;
		fullMessage += "ID: " + messageID + CRLF;
		fullMessage += "UID: " + messageUID + CRLF;
		fullMessage += "Sender: " + sender + CRLF;
		fullMessage += "Recipients: " + recipients + CRLF;
		fullMessage += "Subject: " + subject + CRLF;
		fullMessage += "Date: " + date.toString() + CRLF;
		fullMessage += "Mime: " + mime + CRLF;
		fullMessage += body;
		return fullMessage;
	}
	
	/**
	 * Compares two message objects by the message ID
	 * 
	 * {@inheritDoc} equals in class Object
	 */
	public boolean equals(Object obj) {
		Message message = (Message) obj;
		return messageID == message.getMessageID();
	}
}
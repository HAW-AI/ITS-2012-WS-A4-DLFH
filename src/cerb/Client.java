package cerb;

/* Simulation einer Kerberos-Session mit Zugriff auf einen Fileserver
 /* Client-Klasse
 */

import java.util.*;

public class Client extends Object {

	private KDC myKDC;

	private Server myFileserver;

	private String currentUser;

	private Ticket tgsTicket = null;

	private long tgsSessionKey; // K(C,TGS)

	private Ticket serverTicket = null;

	private long serverSessionKey; // K(C,S)

	// Konstruktor
	public Client(KDC kdc, Server server) {
		myKDC = kdc;
		myFileserver = server;
	}

	public boolean login(String userName, char[] password) {
		/*Anmeldung eines Benutzers bearbeiten*/
		boolean result = false;
		currentUser = userName;
		long simpleKey = generateSimpleKeyForPassword(password);
		long nonce = generateNonce();
		//Anmelden beim KDC und TGS-Ticket holen (requestTGSTicket)
		TicketResponse response = myKDC.requestTGSTicket(userName, myKDC.getName(), nonce);
		//TGS-Response entschlüsseln und auswerten
		if(response.decrypt(simpleKey)){//Schlüssel falsch oder bereits entschlüsselt 
			result = true;
			//TGS-Session key und TGS-Ticket speichern
			tgsSessionKey = response.getSessionKey();
			tgsTicket = response.getResponseTicket();
		}
		//PW im Hauptspeicher löschen
		password = null;
		return result;
	}

	public boolean showFile(String serverName, String filePath) {
		/*Bei angegebenem Server authentifizieren und Kommando "showFile" ausführen lassen*/
		boolean result = false;
		//Login prüfen (TGS-Ticket vorhanden?)
		if(tgsTicket != null){
			System.out.println("TGS ticket at hand");
			//Serverticket vorhanden?
			if(serverTicket == null){
				System.out.println("Server ticket not at hand. Requesting one...");
				//Nein -> neues Serverticket anfordern (requestServerTicket) und Antwort auswerten
				long nonce = generateNonce();
				Auth auth = new Auth(currentUser,System.currentTimeMillis());
				auth.encrypt(tgsSessionKey);
				TicketResponse response = myKDC.requestServerTicket(tgsTicket, auth, serverName, nonce);
				if(response.decrypt(tgsSessionKey)){
					System.out.println("Server ticket received and decrypted");
					serverSessionKey = response.getSessionKey();
					serverTicket = response.getResponseTicket();
				} else {
					System.out.println("Server ticket received but decrypting failed");
				}
			} else {
				System.out.println("TGS ticket not at hand");
			}
			if(serverTicket != null){
				System.out.println("Requesting service...");
				Auth auth = new Auth(currentUser,System.currentTimeMillis());
				//Service beim Server anfordern (requestService)
				result =  myFileserver.requestService(serverTicket, auth, "showFile", filePath);
			} else {
				System.out.println("Still not server ticket at hand. Can't request service");
			}
		}
		return result;
	}

	/* *********** Hilfsmethoden **************************** */

	private long generateSimpleKeyForPassword(char[] pw) {
		// Liefert einen Schlüssel für ein Passwort zurück, hier simuliert als
		// long-Wert
		long pwKey = 0;
		for (int i = 0; i < pw.length; i++) {
			pwKey = pwKey + pw[i];
		}
		return pwKey;
	}

	private long generateNonce() {
		// Liefert einen neuen Zufallswert
		long rand = (long) (100000000 * Math.random());
		return rand;
	}
}

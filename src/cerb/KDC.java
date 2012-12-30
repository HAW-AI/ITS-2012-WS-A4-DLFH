package cerb;

/* Simulation einer Kerberos-Session mit Zugriff auf einen Fileserver
 /* KDC-Klasse
 */

import java.util.*;

public class KDC extends Object {

	private final long tenHoursInMillis = 36000000; // 10 Stunden in
													// Millisekunden

	private final long fiveMinutesInMillis = 300000; // 5 Minuten in
														// Millisekunden

	/* *********** Datenbank-Simulation **************************** */

	private String tgsName;

	private String user; // C

	private long userPasswordKey; // K(C)

	private String serverName; // S

	private long serverKey; // K(S)

	private long serverSessionKey; // K(C,S)

	private long tgsKey; // K(TGS)

	private long tgsSessionKey; // K(C,TGS)

	// Konstruktor
	public KDC(String name) {
		tgsName = name;
		// Eigenen Key für TGS erzeugen (streng geheim!!!)
		tgsKey = generateSimpleKey();
	}

	public String getName() {
		return tgsName;
	}

	/* *********** Initialisierungs-Methoden **************************** */

	public long serverRegistration(String sName) {
		// Rückgabe: ein neuer geheimer Schlüssel für den Server
		serverName = sName;
		// Eigenen Key für Server erzeugen (streng geheim!!!)
		serverKey = generateSimpleKey();
		return serverKey;
	}

	public void userRegistration(String userName, char[] password) {
		// Eintrag des Usernamens in die Benutzerdatenbank
		user = userName;
		userPasswordKey = generateSimpleKeyForPassword(password);

		System.out.println("Principal: " + user);
		System.out.println("Password-Key: " + userPasswordKey);
	}

	/* *********** AS-Modul: TGS - Ticketanfrage **************************** */

	public TicketResponse requestTGSTicket(String userName, String tgsServerName, long nonce) {
		// Anforderung eines TGS-Tickets bearbeiten

		TicketResponse tgsTicketResp = null;
		Ticket tgsTicket = null;
		long currentTime = 0;

		// TGS-Antwort zusammenbauen
		if (userName.equals(user) && // Usernamen und Userpasswort in der
										// Datenbank suchen!
				tgsServerName.equals(tgsName)) {
			// OK, neuen Session Key für Client und TGS generieren
			tgsSessionKey = generateSimpleKey();
			currentTime = (new Date()).getTime(); // Anzahl mSek. seit
													// 1.1.1970

			// Zuerst TGS-Ticket basteln ...
			tgsTicket = new Ticket(user, tgsName, currentTime, currentTime
					+ tenHoursInMillis, tgsSessionKey);

			// ... dann verschlüsseln ...
			tgsTicket.encrypt(tgsKey);

			// ... dann Antwort erzeugen
			tgsTicketResp = new TicketResponse(tgsSessionKey, nonce, tgsTicket);

			// ... und verschlüsseln
			tgsTicketResp.encrypt(userPasswordKey);
		}
		return tgsTicketResp;
	}

	/*
	 * *********** TGS-Modul: Server - Ticketanfrage
	 * ****************************
	 */

	public TicketResponse requestServerTicket(Ticket tgsTicket, Auth tgsAuth,
			String serverName, long nonce) {
		// Anforderung eines Server-Tickets bearbeiten
		TicketResponse srvTicketResp = null;

		Ticket srvTicket = null;
		long currentTime = 0;

		// Ticket entschlüsseln
		tgsTicket.decrypt(tgsKey);

		// Authentifikation entschlüsseln
		tgsAuth.decrypt(tgsTicket.getSessionKey());

		// TGS-Ticket + Authentifikation prüfen
		if (tgsTicket.getServerName().equals(tgsName)
				&& timeValid(tgsTicket.getStartTime(), tgsTicket.getEndTime())
				&& tgsAuth.getClientName().equals(tgsTicket.getClientName())
				&& timeFresh(tgsAuth.getCurrentTime())) {
			// Serverticket-Antwort zusammenbauen
			// OK, neuen Session Key für Client und Server generieren
			serverSessionKey = generateSimpleKey();
			currentTime = (new Date()).getTime(); // Anzahl mSek. seit
													// 1.1.1970

			// Zuerst Server-Ticket basteln ...
			srvTicket = new Ticket(user, serverName, currentTime, currentTime
					+ tenHoursInMillis, serverSessionKey);

			// ... dann verschlüsseln ...
			srvTicket.encrypt(getServerKey(serverName));

			// ... dann Antwort erzeugen
			srvTicketResp = new TicketResponse(serverSessionKey, nonce,
					srvTicket);

			// ... und verschlüsseln
			srvTicketResp.encrypt(tgsSessionKey);
		}
		return srvTicketResp;
	}

	/* *********** Hilfsmethoden **************************** */

	private long getServerKey(String sName) {
		// Liefert den zugehörigen Serverkey für den Servernamen zurück
		// Wenn der Servername nicht bekannt, wird -1 zurückgegeben
		if (sName.equalsIgnoreCase(serverName)) {
			System.out.println("Serverkey ok");
			return serverKey;
		} else {
			System.out.println("Serverkey unbekannt!!!!");
			return -1;
		}
	}

	private long generateSimpleKeyForPassword(char[] pw) {
		// Liefert einen Schlüssel für ein Passwort zurück, hier simuliert als
		// long-Wert
		long pwKey = 0;
		for (int i = 0; i < pw.length; i++) {
			pwKey = pwKey + pw[i];
		}
		return pwKey;
	}

	private long generateSimpleKey() {
		// Liefert einen neuen geheimen Schlüssel, hier nur simuliert als
		// long-Wert
		long sKey = (long) (100000000 * Math.random());
		return sKey;
	}

	boolean timeValid(long lowerBound, long upperBound) {
		long currentTime = (new Date()).getTime(); // Anzahl mSek. seit
													// 1.1.1970
		if (currentTime >= lowerBound && currentTime <= upperBound) {
			return true;
		} else {
			System.out.println("-------- Time not valid: " + currentTime
					+ " not in (" + lowerBound + "," + upperBound + ")!");
			return false;
		}
	}

	boolean timeFresh(long testTime) {
		// Wenn die übergebene Zeit nicht mehr als 5 Minuten von der aktuellen
		// Zeit abweicht,
		// wird true zurückgegeben
		long currentTime = (new Date()).getTime(); // Anzahl mSek. seit
													// 1.1.1970
		if (Math.abs(currentTime - testTime) < fiveMinutesInMillis) {
			return true;
		} else {
			System.out.println("-------- Time not fresh: " + currentTime
					+ " is current, " + testTime + " is old!");
			return false;
		}
	}
}

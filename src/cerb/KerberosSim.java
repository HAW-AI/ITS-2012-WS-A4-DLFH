package cerb;

/* Simulation einer Kerberos-Session mit Zugriff auf einen Fileserver */

import java.util.*;
import java.io.*;

public class KerberosSim extends Object {

	public Client initKerberos(String userName, char[] password,
			String serverName, String tgsName) {
		// KDC initialisieren
		KDC myKDC = new KDC(tgsName);
		myKDC.userRegistration(userName, password);

		// Server initialisieren
		Server myFileserver = new Server(serverName);
		myFileserver.setupService(myKDC); // Schlüsselerzeugung und -austausch

		// Client erzeugen
		Client myClient = new Client(myKDC, myFileserver);

		return myClient;
	}

	/**
	 * Reads user password from given input stream.
	 */
	public char[] readPasswd(InputStream in) {
		char[] buf = new char[1024]; // maximale Länge auf 1024 gesetzt
		int offset = 0;
		int c = 0;
		loop: while (true) {
			try {
				c = in.read();
			} catch (IOException ex) {
				System.out.println("Fehler beim Lesen des Passworts! " + ex);
			}
			switch (c) {
			case -1:
			case '\n':
			case '\r':
				break loop;
			default:
				buf[offset++] = (char) c;
				break;
			}
		}
		if (offset == 0) {
			return null;
		}
		char[] ret = new char[offset];
		// Passwort in die neue Rückgabevariable kopieren!!
		System.arraycopy(buf, 0, ret, 0, offset);
		// Passwort in der alten Variablen buf (im Hauptspeicher) löschen
		// (überschreiben)!!
		Arrays.fill(buf, ' ');
		return ret;
	}

	/**
	 * Die main Methode
	 */
	public static void main(String args[]) {

		/*
		 * Simulation einer Benutzer-Session: Anmeldung und Zugriff auf
		 * Fileserver
		 */

		// -------- Start Initialisierung des Systems ------------------
		String userName = "myName";
		char[] password = { 'S', 'e', 'c', 'r', 'e', 't', '!' };
		String serverName = "myFileserver";
		String tgsName = "myTGS";
		String filePath = "testfiles/ITS.txt";

		boolean loginOK;
		boolean serviceOK;
		KerberosSim thisSession = new KerberosSim();

		// KDC + alle Server + Client initialisieren
		Client myClient = thisSession.initKerberos(userName, password,
				serverName, tgsName);
		// -------- Ende Initialisierung des Systems ------------------
		
		/* -------- Benutzersession simulieren ------ */
		// Passwort vom Benutzer holen
		System.out.println("Benutzer: " + userName);
		System.out.print("Passwort: ");
		password = thisSession.readPasswd(System.in);

		// Benutzeranmeldung beim KDC
		loginOK = myClient.login(userName, password);
		
		// Passwort im Hauptspeicher löschen (überschreiben)!!
		Arrays.fill(password, ' ');
		
		if (loginOK) {
			System.out.println("Login erfolgreich!\n");
		} else {
			System.out.println("Login fehlgeschlagen!");
			System.exit(0);
		}

		// Zugriff auf Fileserver
		serviceOK = myClient.showFile(serverName, filePath);
		if (!serviceOK) {
			System.out.println("Zugriff auf Server " + serverName
					+ " ist fehlgeschlagen!");
		}

	}

}

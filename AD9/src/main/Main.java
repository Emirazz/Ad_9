package main;

import java.util.*;

import crypt.*;

public class Main {

	public static void main(String[] args) {
		Scanner in = new Scanner(System.in);
		System.out.println("Bitte druecke 1 fuer eine Verschluesselung oder 2 fuer eine Entschluesselung:");
		int input = in.nextInt();
		if(input == 1) {
			verschlusseln();
		}else if(input == 2){
			entschluesseln();
		}else {
			System.out.println("ungueltige Eingabe");
		}
		in.close();
	}

	private static void verschlusseln() {
		Scanner scanner = new Scanner(System.in);
		System.out.println("Enter public key:");
		String pubkey = scanner.nextLine();
		RSA rsa = new RSA();
		rsa.extractKey(pubkey);
		boolean eingeben = false;
		do {
			System.out.println("Enter message:");
			scanner = new Scanner(System.in);
			String plaintext = scanner.nextLine();
			Cipher cipher = new Cipher();
			String encryptedtext = cipher.encrypt(plaintext, rsa);
			System.out.println("encryptedtext:" + encryptedtext);
			System.out.println("");
			System.out.println("");
			System.out.println("Fuer weitere Eingaben druecke 1, ansonsten 2");
			int input1 = scanner.nextInt();
			if(input1 == 1) {
				eingeben = true;
			}else if(input1 == 2){
				eingeben = false;
			}else {
				System.out.println("ungueltige Eingabe");
				eingeben = false;
			}
		}while(eingeben);
		scanner.close();
	}
	private static void entschluesseln() {
		RSA rsa = new RSA();
		String ownpubkey = rsa.generateKeys(16);
		System.out.println("eigener public key:" + ownpubkey);
		boolean eingabe = false;
		Scanner scanner;
		do {
			System.out.println("Enter encrypted message:");
			scanner = new Scanner(System.in);
			String input = scanner.nextLine();
			
			Cipher cipher = new Cipher();
			String plaintext = cipher.decrypt(input, rsa);
			System.out.println("plaintext:" + plaintext);
			System.out.println("");
			System.out.println("");
			System.out.println("Fuer weitere Eingaben druecke 1, ansonsten 2");
			int input1 = scanner.nextInt();
			if(input1 == 1) {
				eingabe = true;
			}else if(input1 == 2){
				eingabe = false;
			}else {
				System.out.println("ungueltige Eingabe");
				eingabe = false;
			}
		}while(eingabe);
		scanner.close();
	}


}

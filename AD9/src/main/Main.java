package main;

import java.util.*;

import crypt.*;

public class Main {

	public static void main(String[] args) {
		Scanner in = new Scanner(System.in);
		System.out.println("1 für Verschlüsselung / 2 für Entschlüsselung:");
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
		boolean z = true;
		do {
			System.out.println("Enter message:");
			scanner = new Scanner(System.in);
			String plaintext = scanner.nextLine();
			Cipher cipher = new Cipher();
			String encryptedtext = cipher.encrypt(plaintext, rsa);
			System.out.println("encryptedtext:" + encryptedtext);
			System.out.println("");
			System.out.println("Für Eingabe Beenden drücke 1, ansonsten etwas anders");
			int input = scanner.nextInt();
			if(input == 1) {
				z = false;
			}
		}while(z);
		scanner.close();
	}
	private static void entschluesseln() {
		RSA rsa = new RSA();
		String ownpubkey = rsa.generateKeys(16);
		System.out.println("eigener public key:" + ownpubkey);
		Scanner scanner;
		boolean z = true;
		do {
			System.out.println("Enter encrypted message:");
			scanner = new Scanner(System.in);
			String input = scanner.nextLine();
			
			Cipher cipher = new Cipher();
			String plaintext = cipher.decrypt(input, rsa);
			System.out.println("plaintext:" + plaintext);
			System.out.println("");
			System.out.println("");
			System.out.println("Für Eingabe Beenden drücke 1, ansonsten etwas anders");
			int in = scanner.nextInt();
			if(in == 1) {
				z = false;
			}
		}while(z);
		scanner.close();
	}
}

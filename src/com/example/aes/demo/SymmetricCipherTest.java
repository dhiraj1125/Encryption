package com.example.aes.demo;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;

public class SymmetricCipherTest {

	private static byte[] iv = { 11, 22, 33, 44, 99, 88, 77, 66  };

	private static byte[] encrypt(byte[] inpBytes, SecretKey key, String xform) throws Exception {
		Cipher cipher = Cipher.getInstance(xform);
		IvParameterSpec ips = new IvParameterSpec(iv);
		cipher.init(Cipher.ENCRYPT_MODE, key, ips);
		return cipher.doFinal(inpBytes);
	}

	private static byte[] decrypt(byte[] inpBytes, SecretKey key, String xform) throws Exception {
		Cipher cipher = Cipher.getInstance(xform);
		IvParameterSpec ips = new IvParameterSpec(iv);
		cipher.init(Cipher.DECRYPT_MODE, key, ips);
		return cipher.doFinal(inpBytes);
	}

	public static void main(String[] unused) throws Exception {
		String xform = "DES/CBC/PKCS5Padding";
		// Generate a secret key
		KeyGenerator kg = KeyGenerator.getInstance("DES");
		kg.init(56); // 56 is the keysize. Fixed for DES
		SecretKey key = kg.generateKey();

		byte[] dataBytes = "J2EE Security for Servlets, EJBs and Web Services".getBytes();

		byte[] encBytes = encrypt(dataBytes, key, xform);
		byte[] decBytes = decrypt(encBytes, key, xform);

		boolean expected = java.util.Arrays.equals(dataBytes, decBytes);
		System.out.println("Test " + (expected ? "SUCCEEDED!" : "FAILED!"));
	}

}

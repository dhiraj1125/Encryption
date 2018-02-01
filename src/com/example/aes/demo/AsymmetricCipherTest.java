package com.example.aes.demo;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;

import javax.crypto.Cipher;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

public class AsymmetricCipherTest {
	
	private static byte[] encrypt(byte[] inpBytes, PublicKey key, String xform) throws Exception {
		Cipher cipher = Cipher.getInstance(xform);
		cipher.init(Cipher.ENCRYPT_MODE, key);
		return cipher.doFinal(inpBytes);
	}
	private static byte[] decrypt(byte[] inpBytes, PrivateKey key, String xform) throws Exception{
		Cipher cipher = Cipher.getInstance(xform);
		cipher.init(Cipher.DECRYPT_MODE, key);
		return cipher.doFinal(inpBytes);
	}

	public static void main(String[] unused) throws Exception {

		Security.addProvider(new BouncyCastleProvider());
		String xform = "RSA/NONE/PKCS1PADDING";
		// Generate a key-pair
		KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
		kpg.initialize(512); // 512 is the keysize.
		KeyPair kp = kpg.generateKeyPair();
		PublicKey pubk = kp.getPublic();
		PrivateKey prvk = kp.getPrivate();

		byte[] dataBytes =
				"J2EE Security for Servlets, EJBs and Web Services".getBytes();

		byte[] encBytes = encrypt(dataBytes, pubk, xform);
		byte[] decBytes = decrypt(encBytes, prvk, xform);

		boolean expected = java.util.Arrays.equals(dataBytes, decBytes);
		System.out.println("Test " + (expected ? "SUCCEEDED!" : "FAILED!"));
	}


}

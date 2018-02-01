package com.example.aes.demo;

import java.io.UnsupportedEncodingException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.Base64;

import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;

public class AesDemo {

	private static SecretKeySpec secretKey;
	private static byte[] key;

	public static void setKey(String myKey) {
		MessageDigest sha = null;

		try {
			key = myKey.getBytes("UTF-8");
			sha = MessageDigest.getInstance("SHA-1");
			key = sha.digest(key);
			key = Arrays.copyOf(key, 16);//here 16 is new length
			secretKey = new SecretKeySpec(key, "AES");//here AES is choice of algorithm

		}catch (NoSuchAlgorithmException | UnsupportedEncodingException e) {
			//In Java 7, we can catch both these exceptions in a single catch block as above:
			e.printStackTrace();
		}
	}

	public static String encrypt(String strToEncrypt, String secret){
		try
		{
			setKey(secret);
			Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
			cipher.init(Cipher.ENCRYPT_MODE, secretKey);
			return Base64.getEncoder().encodeToString(cipher.doFinal(strToEncrypt.getBytes("UTF-8")));
		}
		catch (Exception e)
		{
			System.out.println("Error while encrypting: " + e.toString());
		}
		return null;
	}
	public static String decrypt(String strToEncrypt, String secret) {
		try {
			setKey(secret);
			Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5PADDING");
			cipher.init(Cipher.DECRYPT_MODE, secretKey);
			return new String(cipher.doFinal(Base64.getDecoder().decode(strToEncrypt)));
		}catch (Exception e) {
			// TODO: handle exception
			System.out.println("Error while decrypting: " + e.toString());
		}
		return null;

	}

	public static void main(String[] args) {
		final String secretKey = "ssshhhhhhhhhhh!!!!";

		String originalString = "howtodoinjava.com";
		String encryptString = AesDemo.encrypt(originalString, secretKey);
		String decryptedString = AesDemo.decrypt(encryptString, secretKey);
		System.out.println("originalString== "+originalString);
		System.out.println("encryptString== "+encryptString);
		System.out.println("decryptedString== "+decryptedString);
	}
}

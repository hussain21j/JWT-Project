package com;

import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.security.Key;
import java.security.KeyStore;

import javax.crypto.KeyGenerator;

public class KeyGenerators {
	public static void main(String[] args) {
		String pathOfSignatureFile = "D:/PKI/consumer_pfx.p12";
		
		KeyGenerators keyGenerators = new KeyGenerators();
		//keyGenerators.createSignatureKeyStore(pathOfSignatureFile);
		keyGenerators.getPrivateKey(pathOfSignatureFile);
		
		
	}
	
	public void createSignatureKeyStore(String pathOfSignatureFile){
		try{
		    KeyStore keyStore = KeyStore.getInstance("PKCS12");
		    keyStore.load(null, null);
		     
		    KeyGenerator keyGen = KeyGenerator. getInstance("AES");
		    keyGen.init(128);
		    Key key = keyGen.generateKey();
		    keyStore.setKeyEntry("secret", key, "password".toCharArray(), null);
		     
		    keyStore.store(new FileOutputStream(pathOfSignatureFile), "password".toCharArray());
		    System.out.println("KeyStore fiel cretaed successfully on the location "+pathOfSignatureFile);
		} catch (Exception ex){
		    ex.printStackTrace();
		}
	}
	
	public void getPrivateKey(String pathOfSignatureFile){
		try{
		    KeyStore keyStore = KeyStore.getInstance("PKCS12");
		    keyStore.load(new FileInputStream(pathOfSignatureFile), "password".toCharArray());
		     
		    System.out.println("Type :"+keyStore.getType());
		    Key pvtKey = keyStore.getKey("private", "password".toCharArray());
		    System.out.println(pvtKey.toString());
		} catch (Exception ex){
		    ex.printStackTrace();
		}
	}
}

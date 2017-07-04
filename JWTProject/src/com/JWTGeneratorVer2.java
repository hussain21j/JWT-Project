package com;

import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.security.Key;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;

import org.jose4j.jwe.ContentEncryptionAlgorithmIdentifiers;
import org.jose4j.jwe.JsonWebEncryption;
import org.jose4j.jwe.KeyManagementAlgorithmIdentifiers;
import org.jose4j.jwk.EcJwkGenerator;
import org.jose4j.jwk.EllipticCurveJsonWebKey;
import org.jose4j.jws.AlgorithmIdentifiers;
import org.jose4j.jws.JsonWebSignature;
import org.jose4j.jwt.JwtClaims;
import org.jose4j.keys.EllipticCurves;
import org.jose4j.keys.RsaKeyUtil;
import org.jose4j.lang.JoseException;

import com.nimbusds.jose.RSAKey;

public class JWTGeneratorVer2 {
	public static void main(String[] args) throws JoseException, UnrecoverableKeyException, KeyStoreException,
			NoSuchAlgorithmException, CertificateException, FileNotFoundException, IOException {
		System.out.println(
				"***************************Preapre building the JWT*******************************************");
		/*
		 * variable to hold the Kid in Header, As per document this key will be
		 * used to identify the 3rd party public certificate
		 */
		String kid = "3rdPartyAppName_2018-09-11";
		/* variable to hold the algorithm used to secure JWS */
		String alg = AlgorithmIdentifiers.RSA_USING_SHA256;

		/* variable to hold the Set the issuer */
		String iss = "http://3rdParty.com";
		/*
		 * variable to hold the Set subject, as per the documentation this
		 * should have the id of the customer for which payload is applicable
		 */
		String sub = "1000";
		/* variable to hold the Set issued at */
		String iat;
		/* variable to hold the Set JWT ID */
		String jti = "consumer-1000-1";
		/* variable to hold the signed JWT */
		String signediInnerJwt;

		/* Setting the claims */
		JwtClaims claims = new JwtClaims();
		claims.setIssuer(iss);
		claims.setSubject(sub);
		claims.setIssuedAtToNow();
		claims.setJwtId(jti);

		System.out.println("Senders end :: " + claims.toJson());

		/*
		 * *********************************************
		 * ******************Signing*****************
		 ***********************************************/
		/*
		 * RsaJsonWebKey jsonSignKey = RsaJwkGenerator.generateJwk(2048);
		 * System.out.println("privagte key :"+jsonSignKey.getPrivateKey());
		 */

		/*
		 * Variable to hold the path of private key file with extension .p12,
		 * Update it as per file in system
		 */
		String pathOfSignatureFile = "D:/PKI/consumer_pfx.p12";

		/*
		 * Variable to hold the password of key file with extension .p12, Update
		 * it as per file in system
		 */
		String passwordOfP12PFXFile = "password";

		KeyStore keyStore = KeyStore.getInstance("PKCS12");
		keyStore.load(new FileInputStream(pathOfSignatureFile), "password".toCharArray());
		Key privatetKey = keyStore.getKey("consumer_selfsigned", passwordOfP12PFXFile.toCharArray());
		System.out.println(privatetKey.toString());

		/*
		 * A JWT is a JWS and/or a JWE with JSON claims as the payload. In this
		 * example it is a JWS so we create a JsonWebSignature object
		 */
		JsonWebSignature jws = new JsonWebSignature();

		/* The payload of the JWS is JSON content of the JWT Claims */
		jws.setPayload(claims.toJson());

		/* The JWT is signed using the private key */
		/* jws.setKey(jsonSignKey.getPrivateKey()); */
		jws.setKey(privatetKey);

		/*
		 * Set the signature algorithm on the JWT/JWS that will integrity
		 * protect the claims
		 */
		jws.setAlgorithmHeaderValue(alg);

		/* Set the Key ID (kid) header */
		jws.setKeyIdHeaderValue(kid);

		/*
		 * Sign the JWS and produce the compact serialization or the complete
		 * JWT/JWS representation, which is a string consisting of three dot
		 * ('.') separated base64url-encoded parts in the form
		 * Header.Payload.Signature If you wanted to encrypt it, you can simply
		 * set this jwt as the payload of a JsonWebEncryption object and set the
		 * cty (Content Type) header to "jwt".
		 */
		signediInnerJwt = jws.getCompactSerialization();
		System.out.println("Signed Iner JWT ::" + signediInnerJwt);

		/*
		 * *********************************************
		 * ******************Encrypting*****************
		 ***********************************************/

		/*
		 * Generate an EC key pair, which will be used for signing and
		 * verification of the JWT, wrapped in a JWK
		 */
		/*EllipticCurveJsonWebKey receiverJwk = EcJwkGenerator.generateJwk(EllipticCurves.P256);*/
		
		
		
		String certificatePath = "D:/PKI/producer/X509_Producer_certificate.cer";
		InputStream inStream = new FileInputStream(certificatePath); // The X509
		CertificateFactory cf = CertificateFactory.getInstance("X.509");
		X509Certificate cert = (X509Certificate) cf.generateCertificate(inStream);
		inStream.close();

		/* Give the JWK a Key ID (kid) */
		/*receiverJwk.setKeyId("receiversKey");*/

		/* The outer JWT is a JWE */
		JsonWebEncryption jwe = new JsonWebEncryption();

		/*
		 * The output of the ECDH-ES key agreement will encrypt a randomly
		 * generated content encryption key
		 */
		jwe.setAlgorithmHeaderValue(KeyManagementAlgorithmIdentifiers.ECDH_ES_A128KW);

		/*
		 * The content encryption key is used to encrypt the payload with a
		 * composite AES-CBC / HMAC SHA2 encryption algorithm
		 */
		String encAlg = ContentEncryptionAlgorithmIdentifiers.AES_128_CBC_HMAC_SHA_256;
		jwe.setEncryptionMethodHeaderParameter(encAlg);

		/* encrypt to the receiver using the producers public key */
		System.out.println("Public key :" + cert.getPublicKey());
		
		// Convert to JWK format
		/*RSAKey jwk = new RSAKe   Builder(publicKey).build();
		jwe.setKey(cert.getPublicKey());*/
		//jwe.setKeyIdHeaderValue(receiverJwk.getKeyId());

		/*
		 * A nested JWT requires that the cty (Content Type) header be set to
		 * "JWT" in the outer JWT
		 */
		// jwe.setContentTypeHeaderValue("application/jose+json");

		// The inner JWT is the payload of the outer JWT
		jwe.setPayload(signediInnerJwt);

		/*
		 * Produce the JWE compact serialization, which is the complete JWT/JWE
		 * representation, which is a string consisting of five dot ('.')
		 * separated base64url-encoded parts in the form
		 * Header.EncryptedKey.IV.Ciphertext.AuthenticationTag
		 */
		String finalJWT = jwe.getCompactSerialization();
		System.out.println("Signed and encrypted JWT :" + finalJWT);

	}
}

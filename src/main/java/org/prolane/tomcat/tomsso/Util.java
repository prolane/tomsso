package org.prolane.tomcat.tomsso;

import java.io.DataInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Date;
import java.util.logging.Level;
import java.util.logging.Logger;

import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.JWTCreationException;
import com.auth0.jwt.exceptions.JWTVerificationException;
import com.auth0.jwt.interfaces.DecodedJWT;


/**
 * Util class with static methods only.
 * 
 * This Util class uses a 3rd party library created by Auth0:
 * https://github.com/auth0/java-jwt
 *
 * @author G.T.C. (Gerard) Laan
 * http://www.prolane.org
 */
public final class Util {
	private static final Logger logger = Logger.getLogger(Util.class.getName());
	
	// Method for verifying JWT and returning the subject
	public static String getSubjectFromJwt(String token, String issuer, String publicKeyFileLoc) {
		File publicKeyFile = new File(publicKeyFileLoc);
		
		// Read the public key (DER file) from filesystem
        DataInputStream dis = null;
		try {
			dis = new DataInputStream(new FileInputStream(publicKeyFile));
		} catch (FileNotFoundException e) {
			logger.log(Level.SEVERE, "Public Key file was not found. Check the 'pubKeyFileLocation' attribute for this Valve. File was not found at: " + publicKeyFile.getAbsolutePath());
			e.printStackTrace();
		}
        byte[] publicKeyBytes = new byte[(int)publicKeyFile.length()];
        try {
			dis.readFully(publicKeyBytes);
			dis.close();
		} catch (IOException e) {
			e.printStackTrace();
		}
        
        // Create a RSAPublicKey instance out of public key file
        KeyFactory kf = null;
		try {
			kf = KeyFactory.getInstance("RSA");
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		}
        X509EncodedKeySpec publicKeySpec = new X509EncodedKeySpec(publicKeyBytes);
        RSAPublicKey rsaPublicKey = null;
        try {
        	rsaPublicKey = (RSAPublicKey)kf.generatePublic(publicKeySpec);
		} catch (InvalidKeySpecException e) {
			e.printStackTrace();
		}
		
        // Do the actual JWT verification
        // If successful, extract the 'subject' claim value, since this is the username (principal)
        DecodedJWT jwt = null;
        try {
            Algorithm algorithm = Algorithm.RSA256(rsaPublicKey);
            JWTVerifier verifier = JWT.require(algorithm)
                .withIssuer(issuer)
                .build();
            jwt = verifier.verify(token);
        } catch (JWTVerificationException e){
        	logger.log(Level.WARNING, 	"The provided JWT could not be validated, possibly because one of these causes:" + System.lineSeparator() + 
        								"1. The JWT signature does not match with the provided public key." + System.lineSeparator() + 
        								"2. The issuer of the JWT does not match the configured jwtIssuer." + System.lineSeparator() + 
        								"3. The expiration time of the JWT has passed and therefore the JWT will not be accepted for processing.");
        }
        
        // Return principal from JWT
        // TODO: Check what happens if no subject is present
        if (jwt != null) {
        	String sub = jwt.getSubject();
        	if (sub != null && sub != "") {
        		 logger.log(Level.FINE, "Subject '" + sub + "' has been extracted from JWT.");
        		return sub;
        	}
        }
        
        // If not successful, return null
		return null;
	} // End of 'getSubjectFromJwt' method
	
	
	public static String generateJwt(String subject, String issuer, int secondsBeforeExpiry, String privateKeyFileLoc) {
		String jwt = null;
		File privateKeyFile = new File(privateKeyFileLoc);
		
		// Read the private key (DER file) from filesystem
		DataInputStream dis = null;
        try {
			dis = new DataInputStream(new FileInputStream(privateKeyFileLoc));
		} catch (FileNotFoundException e) {
			logger.log(Level.SEVERE, "Private Key file was not found. Check the 'privateKeyFileLoc' attribute for this Valve. File was not found at: " + privateKeyFile.getAbsolutePath());
			e.printStackTrace();
		}
        byte[] privKeyBytes = new byte[(int)privateKeyFile.length()];
        try {
			dis.read(privKeyBytes);
			dis.close();
		} catch (IOException e) {
			e.printStackTrace();
		}
        
        // Create a RSAPrivateKey instance out of private key file
        KeyFactory kf = null;
		try {
			kf = KeyFactory.getInstance("RSA");
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		}
        PKCS8EncodedKeySpec privSpec = new PKCS8EncodedKeySpec(privKeyBytes);
        RSAPrivateKey privKey = null;
        try {
			privKey = (RSAPrivateKey)kf.generatePrivate(privSpec);
		} catch (InvalidKeySpecException e) {
			e.printStackTrace();
		}
		
        // Create JWT
        // First create Date object to set when JWT will expire
        Date expDateTime = new Date();
        expDateTime.setTime(expDateTime.getTime() + (secondsBeforeExpiry * 1000));
        try {
            Algorithm algorithm = Algorithm.RSA256(privKey);
            jwt = JWT.create()
                .withIssuer(issuer)
                .withSubject(subject)
                .withExpiresAt(expDateTime)
                .sign(algorithm);
        } catch (JWTCreationException exception){
        	logger.log(Level.WARNING, "Exception during the creation of JWT for subject '" + subject + "'.");
        }
        
        // Return the complete JWT String
		return jwt;
	}
}

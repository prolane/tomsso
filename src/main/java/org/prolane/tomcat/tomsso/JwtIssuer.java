package org.prolane.tomcat.tomsso;

import java.io.IOException;
import java.security.Principal;
import java.util.logging.Level;
import java.util.logging.Logger;

import javax.servlet.ServletException;
import javax.servlet.http.Cookie;

import org.apache.catalina.connector.Request;
import org.apache.catalina.connector.Response;
import org.apache.catalina.valves.ValveBase;


/**
 * An <b>Valve</b> implementation of distributed
 * Single Sign On (SSO) using JSON Web Tokens (JWT).
 * RFC 7519: "JSON Web Token (JWT)"
 * 
 * Use the JwtIssuer Valve to create the JWT after
 * successful authentication. The authentication should
 * be done by a Valve before this one.
 * 
 * This Valve uses a 3rd party library created by Auth0:
 * https://github.com/auth0/java-jwt
 * 
 * @author G.T.C. (Gerard) Laan
 * http://www.prolane.org
 */
public class JwtIssuer extends ValveBase {
	private String cookieName = "tomsso";
	private String privateKeyFileLoc = "privkey.der";
	private String jwtIssuer = "issuer-name";
	private int secondsBeforeExpiry = 86400; 
	
	private static final Logger logger = Logger.getLogger(JwtAuthenticator.class.getName());
	
	
	public void setCookieName(String cookieName) {
        this.cookieName = cookieName;
    }
	
	public void setPrivateKeyFileLoc(String privateKeyFileLoc) {
        this.privateKeyFileLoc = privateKeyFileLoc;
    }
	
	public void setJwtIssuer(String jwtIssuer) {
        this.jwtIssuer = jwtIssuer;
    }
	
	public void setSecondsBeforeExpiry(int secondsBeforeExpiry) {
		this.secondsBeforeExpiry = secondsBeforeExpiry;
	}
	
	
	@Override
	public void invoke(Request request, Response response) throws IOException, ServletException {
		// First of all, check if a JWT is already present in the request
		boolean jwtIssued = false;
		Cookie[] cookieArray = request.getCookies();
		if (cookieArray != null) {
			for (Cookie cookie : cookieArray) {
				if (cookie.getName().equals(cookieName)) {
					//TODO: Optionally verify the token
					jwtIssued = true;
					break;
				}
			}
		}
		
		if (!jwtIssued) {
			// Check if there is an authenticated principal
			// If so, we need the principal name as this is the JWT subject
			String jwtSubject = null;
			Principal principal = request.getPrincipal();
			if (principal != null) {
                jwtSubject = principal.getName();
                logger.log(Level.FINE, "Authenticated user found. Principal name is: '" + jwtSubject + "'");
            } else
            {
            	logger.log(Level.FINE, "No authenticated user found. JWT will not be generated.");
            }
	        
	        // Create the cookie with the JWT
	        if (jwtSubject != null) {
	        	String jwt = null;
	        	jwt = Util.generateJwt(jwtSubject, jwtIssuer, secondsBeforeExpiry, privateKeyFileLoc);
	        	if (jwt != null) {
	        		logger.log(Level.FINE, "JWT has been generated for principal '" + jwtSubject + "'");
	        		logger.log(Level.FINEST, "JWT: '" + jwt + "'");
	        		Cookie cookie = new Cookie(cookieName, jwt);
	        		response.addCookie(cookie);
	        	}
	        }
		} // End if !jwtIssued
		
        // Go to next Valve
        getNext().invoke(request, response);
	}
}

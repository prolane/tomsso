package org.prolane.tomcat.tomsso;

import java.io.IOException;
import java.security.Principal;
import java.util.logging.Level;
import java.util.logging.Logger;

import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.Cookie;

import org.apache.catalina.authenticator.AuthenticatorBase;
import org.apache.catalina.connector.Request;


/**
 * An <b>Authenticator</b> and <b>Valve</b> implementation of distributed
 * Single Sign On (SSO) using JSON Web Tokens (JWT).
 * RFC 7519: "JSON Web Token (JWT)"
 * 
 * This Authenticator uses a 3rd party library created by Auth0:
 * https://github.com/auth0/java-jwt
 *
 * @author G.T.C. (Gerard) Laan
 * http://www.prolane.org
 */
public class JwtAuthenticator extends AuthenticatorBase{
	private static final Logger logger = Logger.getLogger(JwtAuthenticator.class.getName());
	private static final String AUTH_TYPE = "JWT_CUSTOM_AUTH";
	
	private String cookieName = "tomsso";
	private String publicKeyFileLoc = "pubkey.der";
	private String jwtIssuer = "issuer-name";
	private int secondsBeforeExpiry = 86400;
	
	
	public void setCookieName(String cookieName) {
        this.cookieName = cookieName;
    }
	
	public void setPrivateKeyFileLoc(String publicKeyFileLoc) {
        this.publicKeyFileLoc = publicKeyFileLoc;
    }
	
	public void setJwtIssuer(String jwtIssuer) {
        this.jwtIssuer = jwtIssuer;
    }
	
	public void setSecondsBeforeExpiry(int secondsBeforeExpiry) {
		this.secondsBeforeExpiry = secondsBeforeExpiry;
	}
	
	
	@Override
    protected boolean doAuthenticate(Request request, HttpServletResponse response) throws IOException {
		// If authenticated before, no need to do anything
		if (checkForCachedAuthentication(request, response, true)) {
			logger.log(Level.FINE, "Principal already authenticated. Will not check JWT.");
			return true;
		}
		
		// Fetch JWT cookie from Request
		String jwt = null;
		Cookie[] cookieArray = request.getCookies();
		if (cookieArray != null) {
			for (Cookie cookie : cookieArray) {
				if (cookie.getName().equals(cookieName)) {
					jwt = cookie.getValue();
					break;
				}
			}
		}
		
		// Verify the JSON Web Token (JWT) to authenticate the user
		if (jwt != null && jwt != "") {
			// If verification is successful, the subject from the JWT is returned. 
			// The JTW subject is the equivalent of the Principal Name
			String principalName = Util.getSubjectFromJwt(jwt, jwtIssuer, secondsBeforeExpiry, publicKeyFileLoc);
			if (principalName != null) {
				// Create an authenticated user (Principal)
				Principal principal = context.getRealm().authenticate(principalName);
				if (principal != null) {
					// Register the authenticated Principal in the Request and Session
					register(request, response, principal, AUTH_TYPE, principalName, null);
					logger.log(Level.INFO, "Principal '" + principalName + "' successfully authenticated");
				    return true;
				}
			}
		}
		
		// When this point is reached, there was no JWT cookie.
		response.sendError(HttpServletResponse.SC_UNAUTHORIZED);
		logger.log(Level.WARNING, "Single Sign On Authentication was not successful, possibly because no JWT cookie was present in the request or because JWT verification failed.");
    	return false;
	}

	
	@Override
	protected String getAuthMethod() {
		return AUTH_TYPE;
	}

}

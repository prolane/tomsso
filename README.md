# TomSSO - Distributed Single Sign On (SSO) for Tomcat

TomSSO is an extension (3rd party lib) for Apache Tomcat. 

Out of the box Tomcat does have some SSO functionality which you can read about [here](https://tomcat.apache.org/tomcat-7.0-doc/config/host.html#Single_Sign_On). However, this only works for apps deployed on the same server (i.e. same JVM). With TomSSO it is possible to have multiple servers/jvm's in your environment, let a user authenticate at just one of these servers, and then this user will automatically be authenticated as soon as he hits one of the other servers. These servers could even be located at different hosting providers, therefore 'Distributed SSO for Tomcat'.

## Table of Contents
* [How does it work](#howdoesitwork)
* [How about authorization](#authorization)
* [How to get and install TomSSO](#howtoget)
* [Generate required RSA Keys](#rsakeys)
* [How to configure TomSSO](#configure)
* [Creating the JWT outside TomSSO](#jwtcreation)
* [Integration with Websphere Application Server (WAS) by leveraging LTPA](#ltpa)

## <a name="howdoesitwork"></a>How does it work
TomSSO is especially useful in an environment which consist of several separate Tomcat servers which together form a logical application for the user. For example, you might have one Tomcat server running your [CMS](https://en.wikipedia.org/wiki/Content_management_system) as the basis of your website. Users are able to login to view their private personalized content. Your website also has a community forum, but this runs on a different java app on a different Tomcat server. When an already authenticated user switches to the forum you don't want to ask them to enter their credentials again. You want Single Sign On. This is where TomSSO comes into place.

TomSSO will create a cookie as soon as a user has succesfully authenticated. The value of the cookie is a JSON Web Token ([JWT](https://tools.ietf.org/html/rfc7519)). JWT is a way to represent claims securely between parties. In the case of TomSSO the claim is a successful authenticated user. A Tomcat server receiving the JWT will know who this is (user/principal) and know this user has already been successfully authenticated by an other trusted party. 

This 'authenticated user assumption' can de done securely by establishing a trust relation between the two parties. The party asking for the user credentials needs to be supplied with a private key. When the JWT is generated it will be signed with the private key. The party receiving the JWT needs to be supplied with the related public key to verify the signature. If it is successfully verified the receiving party can safely assume the represented claim (user/principal) originates from a trusted party and the contents of the JWT has not been tampered with. 

The JWT does not necessarily has to be created by a Tomcat server with the TomSSO extension. It could very well be created by a different application in a different programming language in a different environment. As long as there is a trust relation between the two parties by using the asynchronous signing (private and public key) and the represented claims in the JWT match. Read more about creating the JWT outside of TomSSO over [here](#jwtcreation).

## <a name="authorization"></a>How about authorization
Authentication and authorization are two separate things. Authentication is about verifying **who** you are. In most cases we are talking about users. Authorization is about **what** you are allowed to do. What roles belong to the user.

The Tomcat internals also make this distinction. Authenticating a user is an isolated step in processing a request. This means when TomSSO verifies an incoming JWT successfully it will only tell Tomcat there is no need to ask for credentials and handover the username (i.e. tell Tomcat who the authenticated user is). TomSSO does not change the behaviour for authorization so this will work in the same way it has been working before. For instance, if you use the [JNDIRealm](http://tomcat.apache.org/tomcat-8.5-doc/realm-howto.html#JNDIRealm) Tomcat will use the username from the JWT and check the LDAP server for the required roles based on the Realm configuration.

## <a name="howtoget"></a>How to get and install TomSSO
### Getting TomSSO
There is no artifact repository yet where you can download the binary. Therefore you have to build the binary yourself with maven for now.

```shell
git clone https://github.com/prolane/tomsso.git
cd tomsso
mvn package
```
    
This will build the TomSSO jar file. It will be created over here:

	<tomsso_repo_dir>/target/tomsso-x.x.x.jar

TomSSO uses the [java-jwt](https://github.com/auth0/java-jwt) project from [Auth0](https://auth0.com/). The related dependencies can be found over here:

	<tomsso_repo_dir>/target/dependencies/*.jar

### Installing TomSSO
Copy the tomsso jar file and the jar files from the dependencies directory to the **lib** directory of your Tomcat installation. Restart Tomcat and you are good to go.

## <a name="rsakeys"></a>Generate required RSA Keys
TomSSO uses the RS256 (RSA with SHA-2 hash) algorithm for signing the JWT. Signing the JWT makes it possible for the receiving party to verifiy if the JWT has not been tampered with.

RS256 is an asymmetric algorithm. It uses a key pair: A private key and a public key. The party which actually verifies the identity of the user (e.g. by asking for credentials) needs to be supplied with the private key. The private key is secret and will be used to sign the JWT. The consumer of the JWT (receiving party) is supplied with the public key to verify the signature.

Generate private key 2048 bits. SHA256 default.
```shell
openssl genrsa -out rsa-privavte.pem 2048
```

Currently TomSSO requires the keys to be in **der** format. There will be an update in the future in order to handle the more popular **pem** format. For now, convert the private key to **der**.
```shell
openssl pkcs8 -topk8 -inform PEM -in rsa-privavte.pem -outform DER -nocrypt -out rsa-private.der
```

Create the public key in **der** format. (based on the private key).
```shell
openssl rsa -inform PEM -in rsa-privavte.pem -pubout -outform DER -out rsa-public.der
```

[OPTIONAL]
For anyone who would like to have the public in **pem** format.
```shell
openssl rsa -inform PEM -in rsa-privavte.pem -pubout -outform PEM -out rsa-public.pem
```


## <a name="configure"></a>How to configure TomSSO
There are two kind of parties when it comes to JWT.

 1. JWT Issuer => Tomcat server configured to issue a new JWT when a user successfully authenticated.
 2. JWT Authenticator => Tomcat server configured to receive a JWT (sent along as a cookie with an http request), verify the incoming JWT, and if verification is successful authenticate the user without asking for credentials (SSO).

How both of these cases should be configured is described below.

> Please note it is currently not supported to configure a Tomcat server with TomSSO to act as both a JWT issuer as well as JWT Authenticator. However, this is certainly under investigation and expected to be introduced in the near future.

### JWT Issuer
Add below configuration to the [**Context**](https://tomcat.apache.org/tomcat-8.5-doc/config/context.html) element, just like required for the standard [Tomcat authenticators](https://tomcat.apache.org/tomcat-8.5-doc/config/valve.html#Authentication).

First of all, add the Authenticator of your choice which will have to handle the actual authentication of the user, for example the [BasicAuthenticator](https://tomcat.apache.org/tomcat-8.5-doc/config/valve.html#Basic_Authenticator_Valve). After this Valve you add the TomSSO Valve.

```xml
<Valve className="org.apache.catalina.authenticator.BasicAuthenticator"/>
<Valve className="org.prolane.tomcat.tomsso.JwtIssuer" cookieName="tomsso" privateKeyFileLoc="/etc/tomcat8/keys/priv.der" jwtIssuer="mywebsite.com" secondsBeforeExpiry="3600" />
```

The **JwtIssuer** Valve supports the following configuration attributes:

| Attribute     | Description | Default Value  | Mandatory   |
| ------------- |-------------|----------------|-------------|
| className     | MUST be set to *org.prolane.tomcat.tomsso.JwtIssuer*  | N/A | yes
| cookieName    | Sets the name of the cookie created by TomSSO | tomsso | no
| privateKeyFileLoc   | Sets where the private key file is located on disk. Relative paths are supported.| privatekey.der | no
| jwtIssuer           | Identifies the principal that issues the JWT. The issuer value is validated by the JwtAuthenticator, i.e. the value set here should match the value set at the JwtAuthenticator. | tomsso-default| no
| secondsBeforeExpiry | Sets the expiration time after which the JWT MUST NOT be accepted for processing. This attribute is set in seconds. The default is a full day (24h). | 86400 | no


### JWT Authenticator
Add below configuration to the [**Context**](https://tomcat.apache.org/tomcat-8.5-doc/config/context.html) element, just like required for the standard [Tomcat authenticators](https://tomcat.apache.org/tomcat-8.5-doc/config/valve.html#Authentication).

Please mind the JwtAuthenticator MUST be the only Authenticator Valve present. Do NOT combine the JwtAuthenticator Valve with other Authenticators.

```xml
<Valve className="org.prolane.tomcat.tomsso.JwtAuthenticator" alwaysUseSession="true" cookieName="tomsso" publicKeyFileLoc="/etc/tomcat8/keys/pub.der" jwtIssuer="mywebsite.com" />
```

The **JWT Authenticator** Valve supports the following configuration attributes:

| Attribute     | Description | Default Value  | Mandatory   |
| ------------- |-------------|----------------|-------------|
| className     | MUST be set to *org.prolane.tomcat.tomsso.JwtAuthenticator*  | N/A | yes
| alwaysUseSession    | Always use the session to cache the authenticated principal. This may offer some performance benefits since this removes the need to verify the JWT on every request. However there will also be the performance cost of the session management. Setting this attribute to false does not necessarily mean a performance penalty since Tomcat will choose to cache the authenticated principal in most cases anyway. | false| no
| cookieName    | Sets the cookie name which should reflect the name of the incoming TomSSO cookie. | tomsso | no
| publicKeyFileLoc   | Sets where the public key file is located on disk. Relative paths are supported.| publickey.der | no
| jwtIssuer           | Identifies the principal that issued the JWT. The jwtIssuer value should match with the value configured at the party who issued the JWT. If not, validation of the JWT will fail. | tomsso-default| no

## <a name="jwtcreation"></a>Creating the JWT outside TomSSO
TO BE DOCUMENTED. COMING SOON!

## <a name="ltpa"></a>Integration with Websphere Application Server (WAS) by leveraging LTPA
TO BE DEVELOPED AND DOCUMENTED. COMING SOON!
package demo.jsr375;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSVerifier;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jwt.SignedJWT;

import javax.enterprise.context.ApplicationScoped;
import javax.json.Json;
import javax.json.JsonArray;
import javax.json.JsonObject;
import javax.json.JsonString;
import javax.security.enterprise.AuthenticationException;
import javax.security.enterprise.AuthenticationStatus;
import javax.security.enterprise.authentication.mechanism.http.HttpAuthenticationMechanism;
import javax.security.enterprise.authentication.mechanism.http.HttpMessageContext;
import javax.security.enterprise.identitystore.CredentialValidationResult;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.ws.rs.core.HttpHeaders;
import java.io.*;
import java.net.HttpURLConnection;
import java.net.URL;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.security.PublicKey;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.interfaces.RSAPublicKey;
import java.text.ParseException;
import java.util.Arrays;
import java.util.Base64;
import java.util.HashSet;
import java.util.List;
import java.util.logging.Level;
import java.util.logging.Logger;

@ApplicationScoped
public class OIDCAuthenticationMechanism implements HttpAuthenticationMechanism {

    private static Logger logger = Logger.getLogger(OIDCAuthenticationMechanism.class.getName());

    private String APPLICATION_REDIRECT_URL = "http://localhost:8001/";

    private String OIDC_BASE_URL = "http://localhost:8080/auth/realms/TestApplication/protocol/openid-connect/";

    private String OIDC_CODE_URL =
            OIDC_BASE_URL + "auth?response_type=code&client_id=jsr375app&" + "redirect_uri=";

    private String OIDC_TOKEN_URL = OIDC_BASE_URL + "token";

    private String APP_ID = "jsr375app";


    public AuthenticationStatus validateRequest(HttpServletRequest httpServletRequest,
                                                HttpServletResponse httpServletResponse,
                                                HttpMessageContext httpMessageContext) throws AuthenticationException {

        String authorizationHeader = httpServletRequest.getHeader(HttpHeaders.AUTHORIZATION);
        String code = httpServletRequest.getParameter("code");
        logger.info("Resource accessed " + httpServletRequest.getRequestURI());
        String redirectUrl = APPLICATION_REDIRECT_URL + httpServletRequest.getRequestURI();

        if (authorizationHeader == null && code == null) {
            try {
                httpServletResponse.sendRedirect(OIDC_CODE_URL + redirectUrl);
                return AuthenticationStatus.SUCCESS;
            } catch (IOException ex) {
                logger.log(Level.SEVERE, "Error redirecting");
                throw new AuthenticationException("Unknown Error");
            }
        }

        String token;
        if (authorizationHeader == null) {
            token = getToken(code, redirectUrl);
        } else {
            logger.info("Authorization header is " + authorizationHeader);
            String[] headerValues = authorizationHeader.split(" ");
            if (headerValues.length < 2) throw new AuthenticationException("Invalid Authorization Header");

            String type = headerValues[0];
            if ("Bearer".equals(type.trim()))
                token = Arrays.toString(Base64.getDecoder().decode(headerValues[1].trim()));
            else throw new AuthenticationException("Invalid Token Type");
        }

        try {
            SignedJWT jwt = SignedJWT.parse(token);
            PublicKey publicKey = getPublicKey();

            JWSVerifier verifier = new RSASSAVerifier((RSAPublicKey) publicKey);

            if (!jwt.verify(verifier)) throw new AuthenticationException("Invalid signature");

            CredentialValidationResult credentialValidationResults = getCredentialValidationResults(jwt);
            httpMessageContext.notifyContainerAboutLogin(credentialValidationResults);
        } catch (ParseException | JOSEException | CertificateException e) {
            logger.log(Level.SEVERE, "Error parsing token", token);
            throw new AuthenticationException("Invalid Token");
        }

        return AuthenticationStatus.SUCCESS;
    }

    static PublicKey getPublicKey() throws CertificateException {
        CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");

        String publicKey =
                "MIICrTCCAZUCBgF3M3R0XDANBgkqhkiG9w0BAQsFADAaMRgwFgYDVQQDDA9UZXN0QXBwbGljYXRpb24wHhcNMjEwMTI" +
                        "0MDgxMTQ1WhcNMzEwMTI0MDgxMzI1WjAaMRgwFgYDVQQDDA9UZXN0QXBwbGljYXRpb24wggEiMA0GCSqGSIb3DQEBAQ" +
                        "UAA4IBDwAwggEKAoIBAQCTVMtPxvlz8WRW8wpJwWKSa6MpJC1o3K1s9HjGuM6rFNY3eD0+7ZLMe2jT0xaBKBFVv7Ymu+" +
                        "XdDf9SYdUz2/NOyJfD3aVvTOITO36f1NlytxfcEYUcOvvnCVY2N+cY25+l0Sbl59fxqylT88ry2gdd2zmb0N4/CbfBqK" +
                        "VVqroTXW+wwUNWfPdz7HuhrMUCfE7dkpS60v0ERb5niDjFnlJXrohY0P8PcqvhcxY1QC8lyf5PoWNK91Po2SKNj17hth" +
                        "F59u//nyX4fsTxl/+iq4EgiyIkkD8S1kXDsiWjqJ3e2w0CgGr1LIYk4PGl2OyevhLg1daUye7Vzoja79PnkF6zAgMBAA" +
                        "EwDQYJKoZIhvcNAQELBQADggEBAEZd8Lp+oxLZLZnxHG9smBZXE8gMmBvrxV6maKMzsB5va+I9OcBsUTXwa6FtN1kR1S" +
                        "MTJbvMWQfxib/oLbLRhmykOLK9O/T9h4rUQFKY3iq5rR0WbSJvO7zClNKI43LRynRoSIfzbWGV25hnX7d4hqrc8W5P/d" +
                        "Q/4G+fKUpbbkLrH+dR9QiY6a5vFIzMZlOd6r80HZWBn6tx4D3Qd8iP9JO1MmKlWmVH8Hx8L18VgL3v1iBSnmJOJvGjDM" +
                        "herqIkVVVcRm2qpYYjdYKnOkLcmDjBHzK8WVU30NWHzSRsYXHDSpbGrt/j/BodCuXmVlPNXgqARwTp0RAlMHrbpzCLNsk=";

        Certificate certificate =
                certificateFactory.generateCertificate(new ByteArrayInputStream(Base64.getDecoder().decode(publicKey)));

        return certificate.getPublicKey();
    }

    private String getToken(String code, String redirectUrl) throws AuthenticationException {

        HttpURLConnection httpURLConnection = null;
        try {
            URL url = new URL(OIDC_TOKEN_URL);
            httpURLConnection = (HttpURLConnection) url.openConnection();
            httpURLConnection.setRequestMethod("POST");
            httpURLConnection.setDoOutput(true);
            httpURLConnection.setDoInput(true);
            String userpass = "jsr375app:81e10126-716e-4be5-b04a-274decb297ab";
            String basicAuth = "Basic " + new String(Base64.getEncoder().encode(userpass.getBytes()));
            logger.info("Authorization header is " + basicAuth);
            httpURLConnection.setRequestProperty("Authorization", basicAuth);

            StringBuilder encodedUrl = new StringBuilder("grant_type=authorization_code&code=");
            encodedUrl.append(code);
            encodedUrl.append("&redirect_uri=");
            encodedUrl.append(URLEncoder.encode(redirectUrl, StandardCharsets.UTF_8));

            logger.info("Encoded URL is " + encodedUrl);
            OutputStreamWriter outputStreamWriter = new OutputStreamWriter(httpURLConnection.getOutputStream());
            BufferedWriter bufferedWriter = new BufferedWriter(outputStreamWriter);
            bufferedWriter.write(String.valueOf(encodedUrl));
            bufferedWriter.flush();
            bufferedWriter.close();

            InputStream inputStream = httpURLConnection.getInputStream();
            byte[] results = inputStream.readAllBytes();

            JsonObject jsonObject = Json.createReader(new ByteArrayInputStream(results)).readObject();
            return jsonObject.getJsonString("access_token").getString();

        } catch (IOException e) {
            logger.log(Level.SEVERE, "Error connecting to OIDC server", e);
            throw new AuthenticationException("System Error");
        } finally {
            if (httpURLConnection != null) httpURLConnection.disconnect();
        }
    }

    private CredentialValidationResult getCredentialValidationResults(SignedJWT jwt) throws AuthenticationException {
        try {
            String tokenAsStr = jwt.getJWTClaimsSet().toString();
            logger.info("Token " + tokenAsStr);
            JsonObject account = Json.createReader(new StringReader(tokenAsStr))
                                                .readObject()
                                                .getJsonObject("resource_access")
                                                .getJsonObject(APP_ID);
            JsonArray roles = account.getJsonArray("roles");
            List<String> roleList = roles.getValuesAs(x -> ((JsonString) x).getString());
            return new CredentialValidationResult((String) jwt.getJWTClaimsSet().getClaim("name"),
                    new HashSet<>(roleList));
        } catch (ParseException e) {
            logger.log(Level.SEVERE, "Incorrect Token");
            throw new AuthenticationException("Incorrect Token");
        }
    }
}

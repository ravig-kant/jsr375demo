package demo.jsr375;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSVerifier;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jwt.SignedJWT;
import org.junit.Assert;
import org.junit.Test;

import javax.security.enterprise.AuthenticationException;
import java.io.IOException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.cert.CertificateException;
import java.security.interfaces.RSAPublicKey;
import java.text.ParseException;

public class TestOIDCAuthenticationMechanism {


    private static String token =
            "eyJhbGciOiJSUzI1NiIsInR5cCIgOiAiSldUIiwia2lkIiA6ICJkRmM1OUhkNHZjeFZJaGFyaW1CWkVYemcxd1NTMDYzUHR" +
            "yYm45dWZiYjNVIn0.eyJleHAiOjE2MTE1ODY1NDMsImlhdCI6MTYxMTU4NjI0MywiYXV0aF90aW1lIjoxNjExNTg2MjQzLC" +
            "JqdGkiOiJiZTliMzgzOS1lYTEzLTRjNWYtOGI0ZS05ZGQ0YjZjYTMzZmYiLCJpc3MiOiJodHRwOi8vbG9jYWxob3N0OjgwO" +
            "DAvYXV0aC9yZWFsbXMvVGVzdEFwcGxpY2F0aW9uIiwiYXVkIjoiYWNjb3VudCIsInN1YiI6ImZkNzYzYjZkLTE2MTEtNGYz" +
            "YS1hOWE4LTgxNmNkZWEyZDNjMyIsInR5cCI6IkJlYXJlciIsImF6cCI6ImpzcjM3NWFwcCIsInNlc3Npb25fc3RhdGUiOiI" +
            "2YzI4MDQ2MC0zNTc5LTQ2OTktOWEwNC1hZDc1ZmNjOGE1NzUiLCJhY3IiOiIxIiwicmVhbG1fYWNjZXNzIjp7InJvbGVzIj" +
            "pbIm9mZmxpbmVfYWNjZXNzIiwidW1hX2F1dGhvcml6YXRpb24iXX0sInJlc291cmNlX2FjY2VzcyI6eyJhY2NvdW50Ijp7I" +
            "nJvbGVzIjpbIm1hbmFnZS1hY2NvdW50IiwibWFuYWdlLWFjY291bnQtbGlua3MiLCJ2aWV3LXByb2ZpbGUiXX19LCJzY29w" +
            "ZSI6InByb2ZpbGUgZW1haWwiLCJlbWFpbF92ZXJpZmllZCI6ZmFsc2UsIm5hbWUiOiJUZXN0IiwicHJlZmVycmVkX3VzZXJ" +
            "uYW1lIjoidGVzdHVzZXIiLCJnaXZlbl9uYW1lIjoiVGVzdCIsImVtYWlsIjoidGVzdHVzZXJAdGVzdGRvbWFpbi5jb20ifQ" +
            ".L5MylBEMthtHyxwPxJ3HTK0ShIZazJt0sDKL275KUNKBYSxDYSQYHCO3U_IhDqNXLVny41uT1LbbvJEBQI9I3ocNtXeaVw" +
            "XoieSrru82sVFmBiUsoWotufHFRWGUEDk-gRGg_90oG8Uvgofzbuf6B4jTeyqmQFm_v1pcV6gu99iEOL2fsEo0pY8pjx4S9" +
            "s2qi_PIFnCh-BikfzHgg4VRXHizD6q_8vDgK_AmYLFrK8aPT6lvkhnmgBB4b-xpd9RojMBKDT8kgpVxYd3UpYztqMjmjNFI" +
            "B9hOAoNNCV1Lonuxalw0EtgWVgsNgCIz2EQ-X8td1XtDy0fY70oLHuG97A";

    @Test
    public void testGetPublicKey() throws CertificateException, NoSuchAlgorithmException,
            KeyStoreException, AuthenticationException, IOException, ParseException {

        PublicKey publicKey = OIDCAuthenticationMechanism.getPublicKey();

        SignedJWT jwt = SignedJWT.parse(token);
        JWSVerifier verifier = new RSASSAVerifier((RSAPublicKey) publicKey);
        try {
            jwt.verify(verifier);
        } catch (JOSEException e) {
            Assert.fail("Verification failed");
        }
    }
}

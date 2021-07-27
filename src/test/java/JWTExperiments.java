import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.JWTVerificationException;
import com.auth0.jwt.interfaces.RSAKeyProvider;
import org.junit.jupiter.api.Test;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class JWTExperiments {

    @Test
    void signTokenWithSymmetricHMAC() throws UnsupportedEncodingException {

        Algorithm algorithm = Algorithm.HMAC256("secret");

        String token = JWT.create()
                .withIssuer("auth0")
                .sign(algorithm);

        assertEquals(
                "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9." +
                        "eyJpc3MiOiJhdXRoMCJ9." +
                        "izVguZPRsBQ5Rqw6dhMvcIwy8_9lQnrO3vpxGwPCuzs",
                token);

        JWTVerifier verifier = JWT.require(algorithm)
                .withIssuer("auth0")
                .build();

        verifier.verify(token);

        assertThrows(JWTVerificationException.class, () -> verifier.verify(token + "x"));
    }

    @Test
    void signTokenWithAsymmetricRSA() throws IOException {

        /*
            Creating keys:

            // Create RSA-key in PKCS1 format (header "-----BEGIN RSA PRIVATE KEY-----")
            openssl genrsa -out private_key_in_pkcs1.pem 512

            // Convert to PKCS8 format (header "-----BEGIN PRIVATE KEY-----")
            openssl pkcs8 -topk8 -in private_key_in_pkcs1.pem -outform pem -nocrypt -out private_key_in_pkcs8.pem

            // Extract public key:
            openssl rsa -in private_key_in_pkcs8.pem -pubout > public.pub

         */

        String filepathPrivateKey = "src/test/resources/asymmetric_rsa/private_key_in_pkcs8.pem";
        String filepathPublicKey = "src/test/resources/asymmetric_rsa/public.pub";

        RSAPrivateKey privateKey = (RSAPrivateKey) PemUtils.readPrivateKeyFromFile(filepathPrivateKey, "RSA");
        RSAKeyProvider provider = mock(RSAKeyProvider.class);
        when(provider.getPrivateKeyId()).thenReturn("my-key-id");
        when(provider.getPrivateKey()).thenReturn(privateKey);
        when(provider.getPublicKeyById("my-key-id")).thenReturn(
                (RSAPublicKey) PemUtils.readPublicKeyFromFile(filepathPublicKey, "RSA"));

        Algorithm algorithm = Algorithm.RSA256(provider);

        String token = JWT.create()
                .withIssuer("auth0")
                .sign(algorithm);

        // Notice how the payload is similar to the test with HMAC signing above:
        assertEquals(
                "eyJraWQiOiJteS1rZXktaWQiLCJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9." +
                        "eyJpc3MiOiJhdXRoMCJ9." +
                        "bzF8jNol1SwVS93t6_02KuDFAmnj8FrBRx9lFqH-Ianlx0Ig0wsx3Xz_6g4HqFYzTKoWIPXvNf8hP1tJqP-h5g",
                token);

        JWTVerifier verifier = JWT.require(algorithm)
                .withIssuer("auth0")
                .build();

        verifier.verify(token);

        assertThrows(JWTVerificationException.class, () -> verifier.verify(token + "x"));
    }

    @Test
    void maliciousChangeInUnsignedTokenCannotBeValidated() {

        Algorithm algorithm = Algorithm.none();

        String originalToken = JWT.create()
                .withIssuer("auth0")
                .withClaim("role", "user")
                .sign(algorithm);

        assertEquals(
                "eyJ0eXAiOiJKV1QiLCJhbGciOiJub25lIn0.eyJyb2xlIjoidXNlciIsImlzcyI6ImF1dGgwIn0.", originalToken);

        String fakeToken = JWT.create()
                .withIssuer("auth0")
                .withClaim("role", "ADMIN")
                .sign(algorithm);

        // Note that header from the original token and the fake token are identical
        assertEquals(
                "eyJ0eXAiOiJKV1QiLCJhbGciOiJub25lIn0.eyJyb2xlIjoiQURNSU4iLCJpc3MiOiJhdXRoMCJ9.", fakeToken);

        JWTVerifier verifier = JWT.require(algorithm)
                .withIssuer("auth0")
                .build();

        verifier.verify(originalToken);
        verifier.verify(fakeToken);
    }

    @Test
    void creatingAnRSASignedAndRSAEncryptedJWT() throws IOException, NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException {

        /*
            According to https://stackoverflow.com/questions/34235875/should-jwt-web-token-be-encrypted, it is
            recommended to first sign the JWT and then encrypt it.
         */


        /*
            1. Creating keys for signing:

            // Create RSA-key in PKCS1 format (header "-----BEGIN RSA PRIVATE KEY-----")
            openssl genrsa -out signing_private_key_in_pkcs1.pem 512

            // Convert to PKCS8 format (header "-----BEGIN PRIVATE KEY-----")
            openssl pkcs8 -topk8 -in signing_private_key_in_pkcs1.pem -outform pem -nocrypt -out signing_private_key_in_pkcs8.pem

            // Extract public key:
            openssl rsa -in signing_private_key_in_pkcs8.pem -pubout > signing_public.pub

            These keys are used for signing. Hence, the creator of the JWT only publishes his public key for
            validation of the JWT that he signs with his private key.
         */

        // 2. Create JWT and sign it

        String filepathSigningPrivateKey = "src/test/resources/signedAndEncrypted/signing_private_key_in_pkcs8.pem";
        String filepathSigningPublicKey = "src/test/resources/signedAndEncrypted/signing_public.pub";

        RSAPrivateKey signingPrivateKey = (RSAPrivateKey) PemUtils.readPrivateKeyFromFile(filepathSigningPrivateKey, "RSA");
        RSAKeyProvider provider = mock(RSAKeyProvider.class);
        when(provider.getPrivateKeyId()).thenReturn("my-key-id");
        when(provider.getPrivateKey()).thenReturn(signingPrivateKey);
        when(provider.getPublicKeyById("my-key-id")).thenReturn(
                (RSAPublicKey) PemUtils.readPublicKeyFromFile(filepathSigningPublicKey, "RSA"));

        Algorithm algorithm = Algorithm.RSA256(provider);

        String signedToken = JWT.create()
                .withIssuer("auth0")
                .withClaim("name", "Bob")
                .sign(algorithm);

        assertEquals("eyJraWQiOiJteS1rZXktaWQiLCJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9." +
                        "eyJpc3MiOiJhdXRoMCIsIm5hbWUiOiJCb2IifQ." +
                        "XzRwsAUP2fscy6jYGk5tVGwnjTCA8pyCpsHYZayh4qRfdMbJ6fBasvg0yqx8QPjSnJDCzYoYaFPw5of-33G4dQ",
                signedToken);

        /*
            3. Creating keys for encryption:

            These keys are created by the receiver of the JWT. The sender uses the public key of the receiver to
            encrypt the JWT, so that only the receiver can decrypt it.

            The key length has to be sufficiently long, see https://stackoverflow.com/questions/10007147/getting-a-illegalblocksizeexception-data-must-not-be-longer-than-256-bytes-when

            // Create RSA-key in PKCS1 format (header "-----BEGIN RSA PRIVATE KEY-----")
            openssl genrsa -out encrypt_private_key_in_pkcs1.pem 2048

            // Convert to PKCS8 format (header "-----BEGIN PRIVATE KEY-----")
            openssl pkcs8 -topk8 -in encrypt_private_key_in_pkcs1.pem -outform pem -nocrypt -out encrypt_private_key_in_pkcs8.pem

            // Extract public key:
            openssl rsa -in encrypt_private_key_in_pkcs8.pem -pubout > encrypt_public.pub

            These keys are used for signing. Hence, the creator of the JWT only publishes his public key and keeps
            the secret key hidden.
         */


        // 4. Encrypt signed JWT (implementation from https://www.baeldung.com/java-rsa):

        String filepathEncryptPrivateKey = "src/test/resources/signedAndEncrypted/encrypt_private_key_in_pkcs8.pem";
        String filepathEncryptPublicKey = "src/test/resources/signedAndEncrypted/encrypt_public.pub";

        RSAPrivateKey encryptPrivateKey = (RSAPrivateKey) PemUtils.readPrivateKeyFromFile(
                filepathEncryptPrivateKey, "RSA");
        RSAPublicKey encryptPublicKey = (RSAPublicKey) PemUtils.readPublicKeyFromFile(
                filepathEncryptPublicKey, "RSA");

        Cipher encryptCipher = Cipher.getInstance("RSA");
        encryptCipher.init(Cipher.ENCRYPT_MODE, encryptPublicKey);

        byte[] secretMessageBytes = signedToken.getBytes(StandardCharsets.UTF_8);
        byte[] encryptedMessageBytes = encryptCipher.doFinal(secretMessageBytes);


        // 5. Decrypt signed JWT

        Cipher decryptCipher = Cipher.getInstance("RSA");
        decryptCipher.init(Cipher.DECRYPT_MODE, encryptPrivateKey);

        byte[] decryptedMessageBytes = decryptCipher.doFinal(encryptedMessageBytes);
        String decryptedSignedToken = new String(decryptedMessageBytes, StandardCharsets.UTF_8);

        assertEquals(signedToken, decryptedSignedToken);


        // 6. Verify JWT

        JWTVerifier verifier = JWT.require(algorithm)
                .withIssuer("auth0")
                .withClaim("name", "Bob")
                .build();

        verifier.verify(decryptedSignedToken);
    }
}

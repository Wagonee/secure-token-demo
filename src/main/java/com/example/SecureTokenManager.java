package com.example;

import com.nimbusds.jose.*;
import com.nimbusds.jose.crypto.RSADecrypter;
import com.nimbusds.jose.crypto.RSAEncrypter;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;

import java.text.ParseException;
import java.util.Date;
import java.util.UUID;

public class SecureTokenManager {

    public static void main(String[] args) throws JOSEException, ParseException {
        RSAKey jwsSigningKey = new RSAKeyGenerator(2048)
                .keyID("sender-signing-key")
                .generate();
        RSAKey jwsPublicKey = jwsSigningKey.toPublicJWK();

        RSAKey jweEncryptionKey = new RSAKeyGenerator(2048)
                .keyID("receiver-encryption-key")
                .generate();
        RSAKey jwePublicKey = jweEncryptionKey.toPublicJWK();

        JWTClaimsSet claimsSet = new JWTClaimsSet.Builder()
                .subject("user123")
                .issuer("https://my-auth-server.com")
                .claim("email", "user123@example.com")
                .claim("role", "admin")
                .expirationTime(new Date(new Date().getTime() + 60 * 1000 * 5))
                .jwtID(UUID.randomUUID().toString())
                .build();

        SignedJWT signedJWT = new SignedJWT(
                new JWSHeader.Builder(JWSAlgorithm.RS256).keyID(jwsSigningKey.getKeyID()).build(),
                claimsSet
        );
        signedJWT.sign(new RSASSASigner(jwsSigningKey));

        JWEObject jweObject = new JWEObject(
                new JWEHeader.Builder(JWEAlgorithm.RSA_OAEP_256, EncryptionMethod.A128GCM)
                        .contentType("JWT")
                        .keyID(jweEncryptionKey.getKeyID())
                        .build(),
                new Payload(signedJWT)
        );
        jweObject.encrypt(new RSAEncrypter(jwePublicKey));

        String securedToken = jweObject.serialize();
        System.out.println("Сгенерированный защищенный токен (JWE):");
        System.out.println(securedToken);
        System.out.println("\n-------------------------------------------------\n");


        JWEObject receivedJweObject = JWEObject.parse(securedToken);

        receivedJweObject.decrypt(new RSADecrypter(jweEncryptionKey));

        SignedJWT receivedSignedJWT = receivedJweObject.getPayload().toSignedJWT();

        boolean isSignatureValid = receivedSignedJWT.verify(new RSASSAVerifier(jwsPublicKey));

        if (isSignatureValid) {
            System.out.println("Подпись токена верна!");
            JWTClaimsSet receivedClaimsSet = receivedSignedJWT.getJWTClaimsSet();
            System.out.println("Токен успешно расшифрован и проверен!");
            System.out.println("Subject: " + receivedClaimsSet.getSubject());
            System.out.println("Email: " + receivedClaimsSet.getClaim("email"));
            System.out.println("Role: " + receivedClaimsSet.getClaim("role"));
            System.out.println("Expires at: " + receivedClaimsSet.getExpirationTime());
        } else {
            System.out.println("ВНИМАНИЕ! Подпись токена неверна! Токен мог быть подменен.");
        }
    }
}


package com.ecolytiq.jwt

import com.nimbusds.jose.*
import com.nimbusds.jose.crypto.*
import com.nimbusds.jose.jwk.ECKey
import com.nimbusds.jose.jwk.JWK
import com.nimbusds.jose.jwk.KeyUse
import com.nimbusds.jose.jwk.RSAKey
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator
import com.nimbusds.jwt.JWTClaimsSet
import com.nimbusds.jwt.SignedJWT
import java.nio.file.Files
import java.nio.file.Path
import java.time.Clock
import java.time.Instant
import java.util.*

object Utils {

    private fun generateRSAKeyPair(keyLength: Int = 2048, keyId: String, keyUse: KeyUse): RSAKey {
        return RSAKeyGenerator(keyLength).keyID(keyId).keyUse(keyUse).generate()
    }

    fun generateRSASigningKeyPair(keyLength: Int = 2048, keyId: String): RSAKey {
        return generateRSAKeyPair(keyLength = keyLength, keyId = keyId, keyUse = KeyUse.SIGNATURE)
    }

    fun generateRSAEncryptionKeyPair(keyLength: Int = 2048, keyId: String): RSAKey {
        return generateRSAKeyPair(keyLength = keyLength, keyId = keyId, keyUse = KeyUse.ENCRYPTION)
    }

    fun readRSAPem(path: Path): JWK {
        val pem = Files.readString(path)
        return RSAKey.parseFromPEMEncodedObjects(pem)
    }

    fun readECPem(path: Path): JWK {
        val pem = Files.readString(path)
        return ECKey.parseFromPEMEncodedObjects(pem)
    }

    fun readECKey(path: Path): ECKey {
        return readECPem(path) as ECKey
    }

    fun readRSAKey(path: Path): RSAKey {
        return readRSAPem(path) as RSAKey
    }

    fun createECToken(
        keyId: String,
        issuer: String,
        expirationAfterSeconds: Int,
        accountId: String,
        privateECKey: ECKey,
    ): String {
        val now = Instant.now(Clock.systemUTC())
        val expiration = now.plusSeconds(expirationAfterSeconds.toLong())
        val signedJWT = SignedJWT(
            JWSHeader.Builder(JWSAlgorithm.ES256).keyID(keyId).build(),
            JWTClaimsSet.Builder()
                .issueTime(Date(now.toEpochMilli()))
                .expirationTime(Date(expiration.toEpochMilli()))
                .claim("accountId", accountId)
                .issuer(issuer)
                .build(),
        )

        // Sign the JWT
        signedJWT.sign(ECDSASigner(privateECKey))
        return signedJWT.serialize()
    }

    fun createRSAOAEPToken(
        keyId: String,
        issuer: String,
        expirationAfterSeconds: Int,
        accountId: String,
        privateSigningKey: RSAKey,
        publicEncKey: RSAKey,
    ): String {
        val now = Instant.now(Clock.systemUTC())
        val expiration = now.plusSeconds(expirationAfterSeconds.toLong())
        val signedJWT = SignedJWT(
            JWSHeader.Builder(JWSAlgorithm.RS256).keyID(keyId).build(),
            JWTClaimsSet.Builder()
                .issueTime(Date(now.toEpochMilli()))
                .expirationTime(Date(expiration.toEpochMilli()))
                .claim("accountId", accountId)
                .issuer(issuer)
                .build(),
        )

        // Sign the JWT
        signedJWT.sign(RSASSASigner(privateSigningKey))

        val jweObject = JWEObject(
            JWEHeader.Builder(JWEAlgorithm.RSA_OAEP_256, EncryptionMethod.A256GCM)
                .contentType("JWT") // required to indicate nested JWT
                .build(),
            Payload(signedJWT),
        )

        // Encrypt with the recipient's public key
        jweObject.encrypt(RSAEncrypter(publicEncKey))

        return jweObject.serialize()
    }

    fun parseSignedToken(token: String): SignedJWT {
        return SignedJWT.parse(token)
    }

    fun parseEncryptedToken(token: String, privateKey: RSAKey): SignedJWT {
        val jweObject = JWEObject.parse(token)
        jweObject.decrypt(RSADecrypter(privateKey))
        return jweObject.payload.toSignedJWT()
    }

    fun extractKeyId(token: SignedJWT): String {
        return token.header.keyID
    }

    private fun extractIssuer(token: SignedJWT): String {
        return token.jwtClaimsSet.issuer
    }

    fun matchIssuer(token: SignedJWT, expectedIssuer: String): Boolean {
        return extractIssuer(token) == expectedIssuer
    }

    fun extractExpirationTime(token: SignedJWT): Date {
        return token.jwtClaimsSet.expirationTime
    }

    fun validateExpirationTime(token: SignedJWT): Boolean {
        return extractExpirationTime(token).after(Date())
    }

    fun verifyECSignature(token: SignedJWT, publicKey: ECKey): Boolean {
        val verifier = ECDSAVerifier(publicKey)
        return token.verify(verifier)
    }

    fun verifyRSASignature(token: SignedJWT, publicKey: RSAKey): Boolean {
        val verifier = RSASSAVerifier(publicKey)
        return token.verify(verifier)
    }

    fun verifyToken(token: SignedJWT, publicKey: ECKey, expectedIssuer: String): Boolean {
        return verifyECSignature(token, publicKey) && validateExpirationTime(token) && matchIssuer(
            token,
            expectedIssuer,
        ) && extractAccountId(token) != null
    }

    fun verifyToken(token: SignedJWT, publicKey: RSAKey, expectedIssuer: String): Boolean {
        return verifyRSASignature(token, publicKey) && validateExpirationTime(token) && matchIssuer(
            token,
            expectedIssuer,
        ) && extractAccountId(token) != null
    }

    fun extractAccountId(token: SignedJWT): String? {
        return token.jwtClaimsSet.getStringClaim("accountId")
    }
}

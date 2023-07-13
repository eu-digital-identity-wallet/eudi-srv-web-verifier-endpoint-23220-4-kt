package eu.europa.ec.eudi.verifier.endpoint

import com.nimbusds.jose.*
import com.nimbusds.jose.crypto.ECDHDecrypter
import com.nimbusds.jose.crypto.ECDHEncrypter
import com.nimbusds.jose.jwk.Curve
import com.nimbusds.jose.jwk.KeyUse
import com.nimbusds.jose.jwk.gen.ECKeyGenerator
import com.nimbusds.jwt.EncryptedJWT
import com.nimbusds.jwt.JWTClaimsSet
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.extension.ExtendWith
import org.springframework.boot.test.context.SpringBootTest
import org.springframework.test.context.junit.jupiter.SpringExtension
import java.security.interfaces.ECPrivateKey
import java.security.interfaces.ECPublicKey
import java.util.*

/**
 *
 */
@ExtendWith(SpringExtension::class)
@SpringBootTest
internal class JweTest {

    private fun ecdhEncrypt(alg: JWEAlgorithm, enc: EncryptionMethod, ecPublicKey: ECPublicKey, jwtClaims: JWTClaimsSet): String {
        // define JWE alg and enc
        // {
        //   "alg": "ECDH-ES",
        //   "enc": "A256GCM",
        //   "epk": { device ephemeral public key },
        //   "apu": "SKDevice",
        //  "apv": "SKReader"
        // }
        //val alg = JWEAlgorithm.ECDH_ES
        //val enc = EncryptionMethod.A256GCM

        // Request JWT encrypted with ECDH-ES
        val jweHeader = JWEHeader(alg, enc)
        println("header = ${jweHeader.toJSONObject()}")

        // Create the encrypted JWT object
        val encryptedJWT = EncryptedJWT(jweHeader, jwtClaims)

        // Create an encrypter with the specified public RSA key
        val encrypter: JWEEncrypter = ECDHEncrypter(ecPublicKey)

        // Do the actual encryption
        encryptedJWT.encrypt(encrypter)

        // Serialise to JWT compact form
        val jwtString: String = encryptedJWT.serialize()

        println("jwtString = ${jwtString}")
        return jwtString
    }

    private fun ecdhDecrypt(ecPrivateKey: ECPrivateKey, jwtString: String): JWTClaimsSet {

        val jwt = EncryptedJWT.parse(jwtString)
        val rsaDecrypter = ECDHDecrypter(ecPrivateKey)

        jwt.decrypt(rsaDecrypter)

        return jwt.jwtClaimsSet
    }

    @Test
    fun `Encrypting and Decrypt using ECDH`() {

        // (Verifier during initialisation of Transaction) generate key pair
        val alg = JWEAlgorithm.ECDH_ES
        val enc = EncryptionMethod.A256GCM
        val ecKeyGenerator = ECKeyGenerator(Curve.P_256)
            .keyUse(KeyUse.ENCRYPTION)
            .algorithm(JWEAlgorithm.ECDH_ES)
            .keyID("123")
        val ecKey = ecKeyGenerator.generate()
        println("ecKey private: ${ecKey.toJSONString()}")
        println("ecKey public : ${ecKey.toPublicJWK().toJSONString()}")
        val ecPublicKey = ecKey.toECPublicKey()
        val ecPrivateKey = ecKey.toECPrivateKey()

        // (Verifier, on the response of the request of the wallet to get the request object)
        // sends public key, alg and enc from verifier backend to wallet
        println("ecKey alg (authorization_signed_response_alg) : ${alg}")
        println("ecKey enc : ${enc}")
        println("ecKey ec public : ${ecPublicKey}")

        // (wallet) generate JWT with claims
        val now = Date()
        val jwtClaims: JWTClaimsSet = JWTClaimsSet.Builder()
            .issuer("Verifier")
            .subject("john doe")
            .audience(Arrays.asList("https://eudi.com", "https://eudi.org"))
            .expirationTime(Date(now.getTime() + 1000 * 60 * 10)) // expires in 10 minutes
            .notBeforeTime(now)
            .issueTime(now)
            .jwtID(UUID.randomUUID().toString())
            .claim("email", "john-doe@eudi.com")
            .build()
        println("plaintextJwtClaims: ${jwtClaims.toJSONObject()}");

        // (wallet) encrypts with public key (of the verifier backend)
        val encrypted = ecdhEncrypt(alg, enc, ecPublicKey, jwtClaims)
        println("encrypted = ${encrypted}")

        // (verifier backend) decrypt with private key
        val decryptedJwtClaimSet = ecdhDecrypt(ecPrivateKey, encrypted)
        println("decryptedJwtClaimSet = ${decryptedJwtClaimSet.toJSONObject()}")
    }

}

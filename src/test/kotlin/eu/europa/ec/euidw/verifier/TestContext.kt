package eu.europa.ec.euidw.verifier

import com.nimbusds.jose.crypto.RSASSAVerifier
import com.nimbusds.jose.jwk.KeyUse
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator
import eu.europa.ec.euidw.verifier.adapter.out.jose.SignRequestObjectNimbus
import eu.europa.ec.euidw.verifier.adapter.out.persistence.PresentationInMemoryRepo
import eu.europa.ec.euidw.verifier.application.port.`in`.InitTransaction
import eu.europa.ec.euidw.verifier.application.port.`in`.VerifierConfig
import eu.europa.ec.euidw.verifier.application.port.out.GeneratePresentationId
import eu.europa.ec.euidw.verifier.domain.PresentationId
import java.time.Clock
import java.time.LocalDate
import java.time.ZoneOffset
import java.util.*

object TestContext {
    val testDate = LocalDate.of(1974, 11, 2).atTime(10, 5, 33)
    val testClock = Clock.fixed(testDate.toInstant(ZoneOffset.UTC), ZoneOffset.UTC)
    val testPresentationId = PresentationId(UUID.randomUUID())
    val generatedPresentationId = GeneratePresentationId.fixed(testPresentationId)

    val rsaJwk = RSAKeyGenerator(2048)
        .keyUse(KeyUse.SIGNATURE) // indicate the intended use of the key (optional)
        .keyID(UUID.randomUUID().toString()) // give the key a unique ID (optional)
        .issueTime(Date()) // issued-at timestamp (optional)
        .generate()
    val singRequestObject = SignRequestObjectNimbus(rsaJwk)
    val singRequestObjectVerifier = RSASSAVerifier(rsaJwk.toRSAPublicKey())
    private val repo = PresentationInMemoryRepo()
    val loadPresentationById = repo.loadPresentationById
    val storePresentation = repo.storePresentation


    fun initTransaction(verifierConfig: VerifierConfig): InitTransaction =
        InitTransaction.live(
            generatedPresentationId,
            storePresentation,
            singRequestObject,
            verifierConfig,
            testClock
        )
}
package eu.europa.ec.euidw.verifier

import com.nimbusds.jose.jwk.KeyUse
import com.nimbusds.jose.jwk.RSAKey
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator
import eu.europa.ec.euidw.verifier.adapter.`in`.web.GetRequestObjectEndPoint
import eu.europa.ec.euidw.verifier.adapter.out.jose.SignRequestObjectNimbus
import eu.europa.ec.euidw.verifier.adapter.out.persistence.PresentationInMemoryRepo
import eu.europa.ec.euidw.verifier.application.port.`in`.*
import eu.europa.ec.euidw.verifier.application.port.out.GeneratePresentationId
import eu.europa.ec.euidw.verifier.application.port.out.jose.SignRequestObject
import eu.europa.ec.euidw.verifier.application.port.out.persistence.LoadPresentationById
import eu.europa.ec.euidw.verifier.application.port.out.persistence.StorePresentation
import org.springframework.boot.autoconfigure.SpringBootApplication
import org.springframework.boot.runApplication
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Lazy
import java.net.URL
import java.time.Clock
import java.util.*

@SpringBootApplication
class VerifierApplication {


    //
    // End points
    //

    @Bean
    fun getRequestObjectEndPoint(getRequestObject: GetRequestObject): GetRequestObjectEndPoint =
        GetRequestObjectEndPoint(getRequestObject)

    //
    // Use cases
    //

    @Bean
    fun initTransaction(
        generatePresentationId: GeneratePresentationId,
        storePresentation: StorePresentation,
        verifierConfig: VerifierConfig,
        clock: Clock
    ): InitTransaction =
        InitTransaction.live(generatePresentationId, storePresentation, verifierConfig, clock)

    @Bean
    fun getRequestObject(
        loadPresentationById: LoadPresentationById,
        signRequestObject: SignRequestObject,
        storePresentation: StorePresentation,
        verifierConfig: VerifierConfig,
        clock: Clock
    ): GetRequestObject =
        GetRequestObject.live(loadPresentationById, storePresentation, signRequestObject, verifierConfig, clock)

    @Bean
    fun getPresentationDefinition(loadPresentationById: LoadPresentationById): GetPresentationDefinition =
        GetPresentationDefinition.live(loadPresentationById)

    @Bean
    fun verifierConfig(): VerifierConfig {
        return VerifierConfig(
            clientId = "Verifier",
            clientIdScheme = "pre-registered",
            requestUriBuilder = { pid -> URL("https://foo") },
            presentationDefinitionOption = EncodeOption.byReference { pid -> URL("https://foo") },
            responseUriBuilder = { pid -> URL("https://foo") },
        )
    }

    //
    // JOSE
    //


    @Bean
    fun rsaJwk(): RSAKey =
        RSAKeyGenerator(2048)
            .keyUse(KeyUse.SIGNATURE) // indicate the intended use of the key (optional)
            .keyID(UUID.randomUUID().toString()) // give the key a unique ID (optional)
            .issueTime(Date()) // issued-at timestamp (optional)
            .generate()

    @Lazy
    @Bean
    fun signRequestObject(rsaKey: RSAKey): SignRequestObject =
        SignRequestObjectNimbus(rsaKey)

    //
    // Persistence
    //

    @Bean
    fun generatePresentationId(): GeneratePresentationId =
        GeneratePresentationId.random

    @Bean
    fun loadPresentationById(presentationInMemoryRepo: PresentationInMemoryRepo): LoadPresentationById =
        presentationInMemoryRepo.loadPresentationById

    @Bean
    fun storePresentation(presentationInMemoryRepo: PresentationInMemoryRepo): StorePresentation =
        presentationInMemoryRepo.storePresentation

    @Bean
    fun presentationInMemoryRepo(): PresentationInMemoryRepo =
        PresentationInMemoryRepo()

    @Bean
    fun clock(): Clock {
        return Clock.systemDefaultZone()
    }
}

fun main(args: Array<String>) {
    runApplication<VerifierApplication>(*args)
}

package eu.europa.ec.euidw.verifier

import eu.europa.ec.euidw.verifier.adapter.out.jose.SignRequestObjectNimbus
import eu.europa.ec.euidw.verifier.adapter.out.persistence.PresentationInMemoryRepo
import eu.europa.ec.euidw.verifier.application.port.`in`.GetRequestObject
import eu.europa.ec.euidw.verifier.application.port.`in`.PresentationRelatedUrlBuilder
import eu.europa.ec.euidw.verifier.application.port.`in`.VerifierConfig
import eu.europa.ec.euidw.verifier.application.port.out.jose.SignRequestObject
import eu.europa.ec.euidw.verifier.application.port.out.persistence.LoadPresentationById
import eu.europa.ec.euidw.verifier.application.port.out.persistence.StorePresentation
import org.springframework.boot.autoconfigure.SpringBootApplication
import org.springframework.boot.runApplication
import org.springframework.context.annotation.Bean
import java.net.URL

@SpringBootApplication
class VerifierApplication {


    //
    // End points
    //

    //
    // Use cases
    //
    @Bean
    fun getRequestObject(
        loadPresentationById: LoadPresentationById,
        signRequestObject: SignRequestObject,
        verifierConfig: VerifierConfig
    ): GetRequestObject =
        GetRequestObject.live(loadPresentationById, signRequestObject, verifierConfig)



    @Bean
    fun verifierConfig() : VerifierConfig {
        return VerifierConfig(
            clientId = "Verifier",
            clientIdScheme = "pre-registered",
            requestUriBuilder = { pid->URL("https://foo")},
            presentationDefinitionUriBuilder = { pid->URL("https://foo")},
            responseUriBuilder = { pid->URL("https://foo")},
        )
    }

    //
    // JOSE
    //
    @Bean
    fun signRequestObject(): SignRequestObject =
        SignRequestObjectNimbus(rsaJWK = TODO())

    //
    // Persistence
    //
    @Bean
    fun loadPresentationById(presentationInMemoryRepo: PresentationInMemoryRepo): LoadPresentationById =
        presentationInMemoryRepo.loadPresentationById

    @Bean
    fun storePresentation(presentationInMemoryRepo: PresentationInMemoryRepo): StorePresentation =
        presentationInMemoryRepo.storePresentation
    @Bean
    fun presentationInMemoryRepo() : PresentationInMemoryRepo =
        PresentationInMemoryRepo()
}

fun main(args: Array<String>) {
    runApplication<VerifierApplication>(*args)
}

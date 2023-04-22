package eu.europa.ec.euidw.verifier

import com.nimbusds.jose.jwk.KeyUse
import com.nimbusds.jose.jwk.RSAKey
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator
import eu.europa.ec.euidw.verifier.adapter.`in`.web.UIApi
import eu.europa.ec.euidw.verifier.adapter.`in`.web.WalletApi
import eu.europa.ec.euidw.verifier.adapter.out.cfg.GeneratePresentationIdNimbus
import eu.europa.ec.euidw.verifier.adapter.out.cfg.GenerateRequestIdNimbus
import eu.europa.ec.euidw.verifier.adapter.out.jose.SignRequestObjectNimbus
import eu.europa.ec.euidw.verifier.adapter.out.persistence.PresentationInMemoryRepo
import eu.europa.ec.euidw.verifier.application.port.`in`.GetPresentationDefinition
import eu.europa.ec.euidw.verifier.application.port.`in`.GetRequestObject
import eu.europa.ec.euidw.verifier.application.port.`in`.InitTransaction
import eu.europa.ec.euidw.verifier.application.port.out.cfg.GeneratePresentationId
import eu.europa.ec.euidw.verifier.application.port.out.cfg.GenerateRequestId
import eu.europa.ec.euidw.verifier.application.port.out.jose.SignRequestObject
import eu.europa.ec.euidw.verifier.application.port.out.persistence.LoadPresentationById
import eu.europa.ec.euidw.verifier.application.port.out.persistence.LoadPresentationByRequestId
import eu.europa.ec.euidw.verifier.application.port.out.persistence.StorePresentation
import eu.europa.ec.euidw.verifier.domain.EmbedOption
import eu.europa.ec.euidw.verifier.domain.VerifierConfig
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.context.annotation.Lazy
import org.springframework.core.env.Environment
import org.springframework.http.codec.ServerCodecConfigurer
import org.springframework.web.reactive.config.EnableWebFlux
import org.springframework.web.reactive.config.WebFluxConfigurer
import org.springframework.web.reactive.function.server.RouterFunction
import java.net.URL
import java.time.Clock
import java.util.*

@Configuration
@EnableWebFlux
class MyConfig : WebFluxConfigurer {

    override fun configureHttpMessageCodecs(configurer: ServerCodecConfigurer) {
        configurer.defaultCodecs().enableLoggingRequestDetails(true)
    }


}

@Configuration
class VerifierContext(environment: Environment) {

    val verifierConfig = environment.verifierConfig()

    //
    // End points
    //

    @Bean
    fun route(webApi: WalletApi, uiApi: UIApi): RouterFunction<*> = webApi.route.and(uiApi.route)

    @Bean
    fun webApi(getRequestObject: GetRequestObject, getPresentationDefinition: GetPresentationDefinition): WalletApi =
        WalletApi(getRequestObject, getPresentationDefinition)

    @Bean
    fun uiApi(initTransaction: InitTransaction): UIApi = UIApi(initTransaction)

    //
    // Use cases
    //

    @Bean
    fun initTransaction(
        generatePresentationId: GeneratePresentationId,
        generateRequestId: GenerateRequestId,
        storePresentation: StorePresentation,
        signRequestObject: SignRequestObject,
        clock: Clock
    ): InitTransaction =
        InitTransaction.live(
            generatePresentationId,
            generateRequestId,
            storePresentation,
            signRequestObject,
            verifierConfig,
            clock
        )

    @Bean
    fun getRequestObject(
        loadPresentationByRequestId: LoadPresentationByRequestId,
        signRequestObject: SignRequestObject,
        storePresentation: StorePresentation,
        clock: Clock
    ): GetRequestObject =
        GetRequestObject.live(loadPresentationByRequestId, storePresentation, signRequestObject, verifierConfig, clock)

    @Bean
    fun getPresentationDefinition(loadPresentationByRequestId: LoadPresentationByRequestId): GetPresentationDefinition =
        GetPresentationDefinition.live(loadPresentationByRequestId)


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
    fun generatePresentationId(): GeneratePresentationId = GeneratePresentationIdNimbus(64)

    @Bean
    fun generateRequestId(): GenerateRequestId = GenerateRequestIdNimbus(64)

    @Bean
    fun loadPresentationById(presentationInMemoryRepo: PresentationInMemoryRepo): LoadPresentationById =
        presentationInMemoryRepo.loadPresentationById

    @Bean
    fun loadPresentationByRequestId(presentationInMemoryRepo: PresentationInMemoryRepo): LoadPresentationByRequestId =
        presentationInMemoryRepo.loadPresentationByRequestId

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

private fun Environment.verifierConfig(): VerifierConfig {

    return VerifierConfig(
        clientId = getProperty("verifier.clientId") ?: "verifier",
        clientIdScheme = getProperty("verifier.clientIdScheme") ?: "pre-registered",
        requestJarOption = EmbedOption.byReference { _ -> URL("https://foo") },
        presentationDefinitionEmbedOption = EmbedOption.byReference { _ -> URL("https://foo") },
        responseUriBuilder = { _ -> URL("https://foo") },
    )

}
/*
 * Copyright (c) 2023 European Commission
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package eu.europa.ec.eudi.verifier.endpoint

import com.nimbusds.jose.jwk.KeyUse
import com.nimbusds.jose.jwk.RSAKey
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator
import eu.europa.ec.eudi.verifier.endpoint.EmbedOptionEnum.ByReference
import eu.europa.ec.eudi.verifier.endpoint.EmbedOptionEnum.ByValue
import eu.europa.ec.eudi.verifier.endpoint.adapter.input.timer.ScheduleTimeoutPresentations
import eu.europa.ec.eudi.verifier.endpoint.adapter.input.web.StaticContent
import eu.europa.ec.eudi.verifier.endpoint.adapter.input.web.VerifierApi
import eu.europa.ec.eudi.verifier.endpoint.adapter.input.web.WalletApi
import eu.europa.ec.eudi.verifier.endpoint.adapter.out.cfg.GeneratePresentationIdNimbus
import eu.europa.ec.eudi.verifier.endpoint.adapter.out.cfg.GenerateRequestIdNimbus
import eu.europa.ec.eudi.verifier.endpoint.adapter.out.jose.GenerateEphemeralEncryptionKeyPairNimbus
import eu.europa.ec.eudi.verifier.endpoint.adapter.out.jose.ParseJarmOptionNimbus
import eu.europa.ec.eudi.verifier.endpoint.adapter.out.jose.SignRequestObjectNimbus
import eu.europa.ec.eudi.verifier.endpoint.adapter.out.jose.VerifyJarmEncryptedJwtNimbus
import eu.europa.ec.eudi.verifier.endpoint.adapter.out.persistence.PresentationInMemoryRepo
import eu.europa.ec.eudi.verifier.endpoint.domain.*
import eu.europa.ec.eudi.verifier.endpoint.port.input.*
import eu.europa.ec.eudi.verifier.endpoint.port.out.cfg.GeneratePresentationId
import eu.europa.ec.eudi.verifier.endpoint.port.out.cfg.GenerateRequestId
import eu.europa.ec.eudi.verifier.endpoint.port.out.jose.GenerateEphemeralEncryptionKeyPair
import eu.europa.ec.eudi.verifier.endpoint.port.out.jose.SignRequestObject
import eu.europa.ec.eudi.verifier.endpoint.port.out.jose.VerifyJarmJwtSignature
import eu.europa.ec.eudi.verifier.endpoint.port.out.persistence.LoadIncompletePresentationsOlderThan
import eu.europa.ec.eudi.verifier.endpoint.port.out.persistence.LoadPresentationById
import eu.europa.ec.eudi.verifier.endpoint.port.out.persistence.LoadPresentationByRequestId
import eu.europa.ec.eudi.verifier.endpoint.port.out.persistence.StorePresentation
import org.springframework.beans.factory.annotation.Qualifier
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.context.annotation.Lazy
import org.springframework.core.env.Environment
import org.springframework.http.codec.ServerCodecConfigurer
import org.springframework.scheduling.annotation.EnableScheduling
import org.springframework.web.reactive.config.EnableWebFlux
import org.springframework.web.reactive.config.WebFluxConfigurer
import org.springframework.web.reactive.function.server.RouterFunction
import java.time.Clock
import java.time.Duration
import java.util.*

@Configuration
@EnableWebFlux
class MyConfig : WebFluxConfigurer {
    override fun configureHttpMessageCodecs(configurer: ServerCodecConfigurer) {
        configurer.defaultCodecs().enableLoggingRequestDetails(true)
    }
}

@Configuration
@EnableScheduling
class ScheduleSupport

@Configuration
class VerifierContext(environment: Environment) {

    val verifierConfig = environment.verifierConfig()

    //
    // End points
    //

    @Bean
    fun route(webApi: WalletApi, verifierApi: VerifierApi, staticContent: StaticContent): RouterFunction<*> =
        webApi.route.and(verifierApi.route).and(staticContent.route)

    @Bean
    fun webApi(
        getRequestObject: GetRequestObject,
        getPresentationDefinition: GetPresentationDefinition,
        postWalletResponse: PostWalletResponse,
        rsaKey: RSAKey,
    ): WalletApi =
        WalletApi(getRequestObject, getPresentationDefinition, postWalletResponse, rsaKey)

    @Bean
    fun verifierApi(
        initTransaction: InitTransaction,
        getWalletResponse: GetWalletResponse,
    ): VerifierApi = VerifierApi(initTransaction, getWalletResponse)

    @Bean
    fun staticApi(): StaticContent = StaticContent()

    //
    // Scheduled
    //
    @Bean
    fun scheduleTimeoutPresentations(timeoutPresentations: TimeoutPresentations): ScheduleTimeoutPresentations =
        ScheduleTimeoutPresentations(timeoutPresentations)

    //
    // Use cases
    //

    @Bean
    fun initTransaction(
        generatePresentationId: GeneratePresentationId,
        generateRequestId: GenerateRequestId,
        storePresentation: StorePresentation,
        signRequestObject: SignRequestObject,
        clock: Clock,
        generateEphemeralEncryptionKeyPair: GenerateEphemeralEncryptionKeyPair,
        @Qualifier("requestJarByReference") requestJarByReference: EmbedOption.ByReference<RequestId>,
        @Qualifier("presentationDefinitionByReference") presentationDefinitionByReference: EmbedOption.ByReference<RequestId>,
    ): InitTransaction = InitTransactionLive(
        generatePresentationId,
        generateRequestId,
        storePresentation,
        signRequestObject,
        verifierConfig,
        clock,
        generateEphemeralEncryptionKeyPair,
        requestJarByReference,
        presentationDefinitionByReference,
    )

    @Bean
    fun getRequestObject(
        loadPresentationByRequestId: LoadPresentationByRequestId,
        signRequestObject: SignRequestObject,
        storePresentation: StorePresentation,
        clock: Clock,
    ): GetRequestObject = GetRequestObjectLive(
        loadPresentationByRequestId,
        storePresentation,
        signRequestObject,
        verifierConfig,
        clock,
    )

    @Bean
    fun getPresentationDefinition(
        loadPresentationByRequestId: LoadPresentationByRequestId,
    ): GetPresentationDefinition =
        GetPresentationDefinitionLive(loadPresentationByRequestId)

    @Bean
    fun timeoutPresentations(
        loadIncompletePresentationsOlderThan: LoadIncompletePresentationsOlderThan,
        storePresentation: StorePresentation,
        clock: Clock,
    ): TimeoutPresentations = TimeoutPresentationsLive(
        loadIncompletePresentationsOlderThan,
        storePresentation,
        verifierConfig.maxAge,
        clock,
    )

    @Bean
    fun postAuthorisationResponse(
        loadPresentationByRequestId: LoadPresentationByRequestId,
        storePresentation: StorePresentation,
        verifyJarmJwtSignature: VerifyJarmJwtSignature,
        clock: Clock,
    ): PostWalletResponse = PostWalletResponseLive(
        loadPresentationByRequestId,
        storePresentation,
        verifyJarmJwtSignature,
        clock,
        verifierConfig,
    )

    @Bean
    fun generateEphemeralKey(): GenerateEphemeralEncryptionKeyPair = GenerateEphemeralEncryptionKeyPairNimbus

    @Bean
    fun getWalletResponse(
        loadPresentationById: LoadPresentationById,
    ): GetWalletResponse =
        GetWalletResponseLive(loadPresentationById)

    //
    // JOSE
    //

    @Bean
    fun rsaJwk(clock: Clock): RSAKey =
        RSAKeyGenerator(2048)
            .keyUse(KeyUse.SIGNATURE) // indicate the intended use of the key (optional)
            .keyID(UUID.randomUUID().toString()) // give the key a unique ID (optional)
            .issueTime(Date.from(clock.instant())) // issued-at timestamp (optional)
            .generate()

    @Lazy
    @Bean
    fun signRequestObject(rsaKey: RSAKey): SignRequestObject =
        SignRequestObjectNimbus(rsaKey)

    @Bean
    fun verifyJarmJwtSignature(): VerifyJarmJwtSignature = VerifyJarmEncryptedJwtNimbus

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
    fun loadIncompletePresentationsOlderThan(presentationInMemoryRepo: PresentationInMemoryRepo): LoadIncompletePresentationsOlderThan =
        presentationInMemoryRepo.loadIncompletePresentationsOlderThan

    @Bean
    fun presentationInMemoryRepo(): PresentationInMemoryRepo =
        PresentationInMemoryRepo()

    @Bean
    fun clock(): Clock {
        return Clock.systemDefaultZone()
    }

    @Bean
    @Qualifier("requestJarByReference")
    fun requestJarByReference(environment: Environment): EmbedOption.ByReference<RequestId> =
        WalletApi.requestJwtByReference(environment.publicUrl())

    @Bean
    @Qualifier("presentationDefinitionByReference")
    fun presentationDefinitionByReference(environment: Environment): EmbedOption.ByReference<RequestId> =
        WalletApi.presentationDefinitionByReference(environment.publicUrl())
}

private enum class EmbedOptionEnum {
    ByValue,
    ByReference,
}

private fun Environment.verifierConfig(): VerifierConfig {
    val clientId = getProperty("verifier.clientId", "verifier")
    val clientIdScheme = getProperty("verifier.clientIdScheme", "pre-registered")
    val publicUrl = publicUrl()
    val requestJarOption = getProperty("verifier.requestJwt.embed", EmbedOptionEnum::class.java).let {
        when (it) {
            ByValue -> EmbedOption.ByValue
            ByReference, null -> WalletApi.requestJwtByReference(publicUrl())
        }
    }
    val responseModeOption =
        getProperty("verifier.response.mode", ResponseModeOption::class.java) ?: ResponseModeOption.DirectPostJwt

    val presentationDefinitionEmbedOption =
        getProperty("verifier.presentationDefinition.embed", EmbedOptionEnum::class.java).let {
            when (it) {
                ByReference -> WalletApi.presentationDefinitionByReference(publicUrl)
                ByValue, null -> EmbedOption.ByValue
            }
        }
    val maxAge = getProperty("verifier.maxAge", Duration::class.java) ?: Duration.ofSeconds(60)

    return VerifierConfig(
        clientId = clientId,
        clientIdScheme = clientIdScheme,
        requestJarOption = requestJarOption,
        presentationDefinitionEmbedOption = presentationDefinitionEmbedOption,
        responseUriBuilder = { WalletApi.directPost(publicUrl) },
        responseModeOption = responseModeOption,
        maxAge = maxAge,
        clientMetaData = clientMetaData(publicUrl),
    )
}

private fun Environment.clientMetaData(publicUrl: String): ClientMetaData {
    val jwkOption = getProperty("verifier.jwk.embed", EmbedOptionEnum::class.java).let {
        when (it) {
            ByReference -> WalletApi.publicJwkSet(publicUrl)
            ByValue, null -> EmbedOption.ByValue
        }
    }

    val authorizationSignedResponseAlg =
        getProperty("verifier.clientMetadata.authorizationSignedResponseAlg", String::class.java) ?: null
    val authorizationEncryptedResponseAlg =
        getProperty("verifier.clientMetadata.authorizationEncryptedResponseAlg", String::class.java) ?: null
    val authorizationEncryptedResponseEnc =
        getProperty("verifier.clientMetadata.authorizationEncryptedResponseEnc", String::class.java) ?: null

    val defaultJarmOption = ParseJarmOptionNimbus(null, "ECDH-ES", "A256GCM")!!

    return ClientMetaData(
        jwkOption = jwkOption,
        idTokenSignedResponseAlg = "RS256",
        idTokenEncryptedResponseAlg = "RS256",
        idTokenEncryptedResponseEnc = "A128CBC-HS256",
        subjectSyntaxTypesSupported = listOf(
            "urn:ietf:params:oauth:jwk-thumbprint",
            "did:example",
            "did:key",
        ),
        jarmOption = ParseJarmOptionNimbus.invoke(
            authorizationSignedResponseAlg,
            authorizationEncryptedResponseAlg,
            authorizationEncryptedResponseEnc,
        ) ?: defaultJarmOption,
    )
}

/**
 * Gets the public URL of the Verifier endpoint. Corresponds to `verifier.publicUrl` property.
 */
private fun Environment.publicUrl(): String = getProperty("verifier.publicUrl", "http://localhost:8080")

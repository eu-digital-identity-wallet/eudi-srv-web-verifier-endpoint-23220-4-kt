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

import com.nimbusds.jose.JWSAlgorithm
import com.nimbusds.jose.jwk.*
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator
import com.nimbusds.jose.util.Base64
import com.nimbusds.jose.util.X509CertUtils
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
import org.springframework.context.ApplicationContext
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.core.env.Environment
import org.springframework.http.codec.ServerCodecConfigurer
import org.springframework.scheduling.annotation.EnableScheduling
import org.springframework.web.reactive.config.EnableWebFlux
import org.springframework.web.reactive.config.WebFluxConfigurer
import org.springframework.web.reactive.function.server.RouterFunction
import java.security.KeyStore
import java.security.cert.X509Certificate
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
class VerifierContext {

    //
    // Config
    //
    @Bean
    fun verifierConfig(context: ApplicationContext): VerifierConfig = context.verifierConfig()

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
        verifierConfig: VerifierConfig,
    ): WalletApi =
        WalletApi(
            getRequestObject,
            getPresentationDefinition,
            postWalletResponse,
            verifierConfig.clientIdScheme.jarSigning.key,
        )

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
        verifierConfig: VerifierConfig,
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
        verifierConfig: VerifierConfig,
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
        verifierConfig: VerifierConfig,
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
        verifierConfig: VerifierConfig,
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
    fun signRequestObject(verifierConfig: VerifierConfig): SignRequestObject = SignRequestObjectNimbus()

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

private enum class SigningKeyEnum {
    GenerateRandom,
    LoadFromKeystore,
}

private fun ApplicationContext.jarSigningConfig(): SigningConfig {
    val key = run {
        fun loadFromKeystore(): JWK {
            val keystoreResource =
                getResource(environment.getRequiredProperty("verifier.jar.signing.key.keystore"))
            val keystoreType =
                environment.getProperty("verifier.jar.signing.key.keystore.type", KeyStore.getDefaultType())
            val keystorePassword =
                environment.getProperty("verifier.jar.signing.key.keystore.password")?.takeIf { it.isNotBlank() }
            val keyAlias =
                environment.getRequiredProperty("verifier.jar.signing.key.alias")
            val keyPassword =
                environment.getProperty("verifier.jar.signing.key.password")?.takeIf { it.isNotBlank() }

            return keystoreResource.inputStream.use {
                val keystore = KeyStore.getInstance(keystoreType)
                keystore.load(it, keystorePassword?.toCharArray())

                val jwk = JWK.load(keystore, keyAlias, keyPassword?.toCharArray())
                val chain = keystore.getCertificateChain(keyAlias)
                    .orEmpty()
                    .map { certificate -> certificate as X509Certificate }
                    .toList()

                when {
                    chain.isNotEmpty() -> jwk.withCertificateChain(chain)
                    else -> jwk
                }
            }
        }

        fun generateRandom(): RSAKey =
            RSAKeyGenerator(4096, false)
                .keyUse(KeyUse.SIGNATURE) // indicate the intended use of the key (optional)
                .keyID(UUID.randomUUID().toString()) // give the key a unique ID (optional)
                .issueTime(Date.from(getBean(Clock::class.java).instant())) // issued-at timestamp (optional)
                .generate()

        when (environment.getProperty("verifier.jar.signing.key", SigningKeyEnum::class.java)) {
            SigningKeyEnum.LoadFromKeystore -> loadFromKeystore()
            null, SigningKeyEnum.GenerateRandom -> generateRandom()
        }
    }

    val algorithm = environment.getProperty("verifier.jar.signing.algorithm", "RS256").let(JWSAlgorithm::parse)

    return SigningConfig(key, algorithm)
}

private fun ApplicationContext.verifierConfig(): VerifierConfig {
    val clientIdScheme = run {
        val clientId = environment.getProperty("verifier.clientId", "verifier")
        val jarSigning = jarSigningConfig()

        val factory =
            when (val clientIdScheme = environment.getProperty("verifier.clientIdScheme", "pre-registered")) {
                "pre-registered" -> ClientIdScheme::PreRegistered
                "x509_san_dns" -> ClientIdScheme::X509SanDns
                "x509_san_uri" -> ClientIdScheme::X509SanUri
                else -> error("Unknown clientIdScheme '$clientIdScheme'")
            }
        factory(clientId, jarSigning)
    }

    val publicUrl = environment.publicUrl()
    val requestJarOption = environment.getProperty("verifier.requestJwt.embed", EmbedOptionEnum::class.java).let {
        when (it) {
            ByValue -> EmbedOption.ByValue
            ByReference, null -> WalletApi.requestJwtByReference(environment.publicUrl())
        }
    }
    val responseModeOption =
        environment.getProperty("verifier.response.mode", ResponseModeOption::class.java)
            ?: ResponseModeOption.DirectPostJwt

    val presentationDefinitionEmbedOption =
        environment.getProperty("verifier.presentationDefinition.embed", EmbedOptionEnum::class.java).let {
            when (it) {
                ByReference -> WalletApi.presentationDefinitionByReference(publicUrl)
                ByValue, null -> EmbedOption.ByValue
            }
        }
    val maxAge = environment.getProperty("verifier.maxAge", Duration::class.java) ?: Duration.ofSeconds(60)

    return VerifierConfig(
        clientIdScheme = clientIdScheme,
        requestJarOption = requestJarOption,
        presentationDefinitionEmbedOption = presentationDefinitionEmbedOption,
        responseUriBuilder = { WalletApi.directPost(publicUrl) },
        responseModeOption = responseModeOption,
        maxAge = maxAge,
        clientMetaData = environment.clientMetaData(publicUrl),
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

/**
 * Converts this [X509Certificate] list to a [Base64] PEM encoded list.
 */
private fun List<X509Certificate>.toBase64PEMEncoded(): List<Base64> =
    this.map { X509CertUtils.toPEMString(it) }.map { Base64.encode(it) }

/**
 * Creates a copy of this [JWK] and sets the provided [X509Certificate] certificate chain.
 * For the operation to succeed the following must hold true:
 * 1. [chain] cannot be empty
 * 2. the leaf certificate of the [chain] must match the leaf certificate of this [JWK]
 */
private fun JWK.withCertificateChain(chain: List<X509Certificate>): JWK {
    require(this.parsedX509CertChain.isNotEmpty()) { "jwk must has a leaf certificate" }
    require(chain.isNotEmpty()) { "chain cannot be empty" }
    require(
        this.parsedX509CertChain.first() == chain.first(),
    ) { "leaf certificate of provided chain does not match leaf certificate of jwk" }

    val encodedChain = chain.toBase64PEMEncoded()
    return when (this) {
        is RSAKey -> RSAKey.Builder(this).x509CertChain(encodedChain).build()
        is ECKey -> ECKey.Builder(this).x509CertChain(encodedChain).build()
        is OctetKeyPair -> OctetKeyPair.Builder(this).x509CertChain(encodedChain).build()
        is OctetSequenceKey -> OctetSequenceKey.Builder(this).x509CertChain(encodedChain).build()
        else -> error("Unexpected JWK type '${this.keyType.value}'/'${this.javaClass}'")
    }
}

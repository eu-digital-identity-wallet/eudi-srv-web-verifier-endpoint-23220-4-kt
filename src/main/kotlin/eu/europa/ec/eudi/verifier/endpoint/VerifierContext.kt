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

import arrow.core.*
import com.nimbusds.jose.EncryptionMethod
import com.nimbusds.jose.JWEAlgorithm
import com.nimbusds.jose.JWSAlgorithm
import com.nimbusds.jose.jwk.*
import com.nimbusds.jose.jwk.gen.ECKeyGenerator
import com.nimbusds.jose.util.Base64
import eu.europa.ec.eudi.sdjwt.vc.DefaultHttpClientFactory
import eu.europa.ec.eudi.sdjwt.vc.KtorHttpClientFactory
import eu.europa.ec.eudi.verifier.endpoint.EmbedOptionEnum.ByReference
import eu.europa.ec.eudi.verifier.endpoint.EmbedOptionEnum.ByValue
import eu.europa.ec.eudi.verifier.endpoint.adapter.input.timer.ScheduleDeleteOldPresentations
import eu.europa.ec.eudi.verifier.endpoint.adapter.input.timer.ScheduleTimeoutPresentations
import eu.europa.ec.eudi.verifier.endpoint.adapter.input.web.*
import eu.europa.ec.eudi.verifier.endpoint.adapter.out.cert.X5CShouldBe
import eu.europa.ec.eudi.verifier.endpoint.adapter.out.cfg.GenerateRequestIdNimbus
import eu.europa.ec.eudi.verifier.endpoint.adapter.out.cfg.GenerateTransactionIdNimbus
import eu.europa.ec.eudi.verifier.endpoint.adapter.out.jose.CreateJarNimbus
import eu.europa.ec.eudi.verifier.endpoint.adapter.out.jose.GenerateEphemeralEncryptionKeyPairNimbus
import eu.europa.ec.eudi.verifier.endpoint.adapter.out.jose.ParseJarmOptionNimbus
import eu.europa.ec.eudi.verifier.endpoint.adapter.out.jose.VerifyJarmEncryptedJwtNimbus
import eu.europa.ec.eudi.verifier.endpoint.adapter.out.json.jsonSupport
import eu.europa.ec.eudi.verifier.endpoint.adapter.out.mso.DeviceResponseValidator
import eu.europa.ec.eudi.verifier.endpoint.adapter.out.mso.DocumentValidator
import eu.europa.ec.eudi.verifier.endpoint.adapter.out.mso.IssuerSignedItemsShouldBe
import eu.europa.ec.eudi.verifier.endpoint.adapter.out.mso.ValidityInfoShouldBe
import eu.europa.ec.eudi.verifier.endpoint.adapter.out.persistence.PresentationInMemoryRepo
import eu.europa.ec.eudi.verifier.endpoint.adapter.out.presentation.ValidateSdJwtVcOrMsoMdocVerifiablePresentation
import eu.europa.ec.eudi.verifier.endpoint.adapter.out.sdjwtvc.SdJwtVcValidator
import eu.europa.ec.eudi.verifier.endpoint.adapter.out.sdjwtvc.StatusListTokenValidator
import eu.europa.ec.eudi.verifier.endpoint.adapter.out.x509.ParsePemEncodedX509CertificateChainWithNimbus
import eu.europa.ec.eudi.verifier.endpoint.domain.*
import eu.europa.ec.eudi.verifier.endpoint.port.input.*
import eu.europa.ec.eudi.verifier.endpoint.port.out.cfg.CreateQueryWalletResponseRedirectUri
import eu.europa.ec.eudi.verifier.endpoint.port.out.cfg.GenerateResponseCode
import io.ktor.client.*
import io.ktor.client.engine.apache.*
import io.ktor.client.plugins.contentnegotiation.*
import io.ktor.serialization.kotlinx.json.*
import kotlinx.serialization.ExperimentalSerializationApi
import kotlinx.serialization.json.Json
import org.apache.http.conn.ssl.NoopHostnameVerifier
import org.apache.http.conn.ssl.TrustSelfSignedStrategy
import org.apache.http.ssl.SSLContextBuilder
import org.slf4j.LoggerFactory
import org.springframework.boot.web.codec.CodecCustomizer
import org.springframework.context.support.BeanDefinitionDsl.BeanSupplierContext
import org.springframework.context.support.beans
import org.springframework.core.env.Environment
import org.springframework.core.env.getProperty
import org.springframework.core.io.DefaultResourceLoader
import org.springframework.core.io.FileSystemResource
import org.springframework.http.codec.json.KotlinSerializationJsonDecoder
import org.springframework.http.codec.json.KotlinSerializationJsonEncoder
import org.springframework.security.config.web.server.ServerHttpSecurity
import org.springframework.security.config.web.server.invoke
import org.springframework.web.cors.CorsConfiguration
import org.springframework.web.cors.reactive.CorsConfigurationSource
import java.security.KeyStore
import java.security.cert.X509Certificate
import java.time.Clock
import java.time.Duration
import java.util.*

private val log = LoggerFactory.getLogger(VerifierApplication::class.java)

@OptIn(ExperimentalSerializationApi::class)
internal fun beans(clock: Clock) = beans {
    bean { clock }

    val trustedIssuers: KeyStore? by lazy {
        env.getProperty("trustedIssuers.keystore.path")
            ?.takeIf { it.isNotBlank() }
            ?.let { keystorePath ->
                val keystoreType = env.getRequiredProperty("trustedIssuers.keystore.type")
                val keystorePassword = env.getProperty("trustedIssuers.keystore.password")
                    ?.takeIf { it.isNotBlank() }
                    ?.toCharArray()

                log.info("Loading trusted issuers' certificates from '$keystorePath'")
                DefaultResourceLoader().getResource(keystorePath)
                    .inputStream
                    .use {
                        KeyStore.getInstance(keystoreType)
                            .apply {
                                load(it, keystorePassword)
                            }
                    }
            }
    }

    //
    // JOSE
    //
    bean { CreateJarNimbus() }
    bean { VerifyJarmEncryptedJwtNimbus }

    //
    // Persistence
    //
    bean { GenerateTransactionIdNimbus(64) }
    bean { GenerateRequestIdNimbus(64) }
    with(PresentationInMemoryRepo()) {
        bean { loadPresentationById }
        bean { loadPresentationByRequestId }
        bean { storePresentation }
        bean { loadIncompletePresentationsOlderThan }
        bean { loadPresentationEvents }
        bean { publishPresentationEvent }
        bean { deletePresentationsInitiatedBefore }
    }

    bean { CreateQueryWalletResponseRedirectUri.Simple }

    //
    // Ktor
    //
    profile("self-signed") {
        log.warn("Using Ktor HttpClients that trust self-signed certificates and perform no hostname verification")
        bean<KtorHttpClientFactory> {
            {
                HttpClient(Apache) {
                    install(ContentNegotiation) {
                        json(jsonSupport)
                    }
                    expectSuccess = true
                    engine {
                        followRedirects = true
                        customizeClient {
                            setSSLContext(
                                SSLContextBuilder.create()
                                    .loadTrustMaterial(TrustSelfSignedStrategy.INSTANCE)
                                    .build(),
                            )
                            setSSLHostnameVerifier(NoopHostnameVerifier.INSTANCE)
                        }
                    }
                }
            }
        }
    }
    profile("!self-signed") {
        bean<KtorHttpClientFactory> {
            DefaultHttpClientFactory
        }
    }

    // X509
    bean { ParsePemEncodedX509CertificateChainWithNimbus }

    //
    // Use cases
    //
    bean {
        InitTransactionLive(
            ref(),
            ref(),
            ref(),
            ref(),
            ref(),
            ref(),
            ref(),
            WalletApi.requestJwtByReference(env.publicUrl()),
            WalletApi.presentationDefinitionByReference(env.publicUrl()),
            ref(),
            ref(),
            ref(),
        )
    }

    bean { RetrieveRequestObjectLive(ref(), ref(), ref(), ref(), ref(), ref(), ref()) }

    bean { GetPresentationDefinitionLive(ref(), ref(), ref()) }
    bean {
        TimeoutPresentationsLive(
            ref(),
            ref(),
            ref<VerifierConfig>().maxAge,
            ref(),
            ref(),
        )
    }
    bean {
        val maxAge = Duration.parse(env.getProperty("verifier.presentations.cleanup.maxAge", "P10D"))
        require(!maxAge.isZero && !maxAge.isNegative) { "'verifier.presentations.cleanup.maxAge' cannot be zero or negative" }

        DeleteOldPresentationsLive(ref(), maxAge, ref())
    }

    bean { GenerateResponseCode.Random }
    bean { PostWalletResponseLive(ref(), ref(), ref(), ref(), ref(), ref(), ref(), ref(), ref()) }
    bean { GenerateEphemeralEncryptionKeyPairNimbus }
    bean { GetWalletResponseLive(ref(), ref(), ref()) }
    bean { GetPresentationEventsLive(ref(), ref()) }
    bean(::GetClientMetadataLive)

    if (env.getProperty("verifier.validation.sdJwtVc.statusCheck.enabled", true)) {
        log.info("Enabling Status List Token validations")
        bean(::StatusListTokenValidator)
    }

    // Default DeviceResponseValidator
    bean<DeviceResponseValidator> {
        val x5cShouldBe = trustedIssuers?.let { X5CShouldBe.fromKeystore(it) } ?: X5CShouldBe.Ignored
        deviceResponseValidator(x5cShouldBe)
    }

    // Default SdJwtVcValidator
    bean<SdJwtVcValidator> {
        val x5CShouldBe = trustedIssuers?.let {
            X5CShouldBe.fromKeystore(it) {
                isRevocationEnabled = false
            }
        } ?: X5CShouldBe.Ignored
        sdJwtVcValidator(x5CShouldBe)
    }

    bean {
        ValidateMsoMdocDeviceResponse(
            ref(),
            ref(),
            deviceResponseValidatorFactory = { trustedIssuers ->
                trustedIssuers?.let { deviceResponseValidator(it) } ?: ref()
            },
        )
    }
    bean {
        ValidateSdJwtVc(
            sdJwtVcValidatorFactory = { trustedIssuers ->
                trustedIssuers?.let { sdJwtVcValidator(it) } ?: ref()
            },
            ref(),
        )
    }

    bean {
        ValidateSdJwtVcOrMsoMdocVerifiablePresentation(
            config = ref(),
            sdJwtVcValidatorFactory = { trustedIssuers ->
                trustedIssuers?.let { sdJwtVcValidator(it) } ?: ref()
            },
            deviceResponseValidatorFactory = { trustedIssuers ->
                trustedIssuers?.let { deviceResponseValidator(it) } ?: ref()
            },
        )
    }

    //
    // Scheduled
    //
    bean(::ScheduleTimeoutPresentations)
    bean(::ScheduleDeleteOldPresentations)

    //
    // Config
    //
    bean { verifierConfig(env, ref()) }

    //
    // End points
    //

    bean {
        val walletApi = WalletApi(
            ref(),
            ref(),
            ref(),
            ref<VerifierConfig>().verifierId.jarSigning.key,
        )
        val verifierApi = VerifierApi(ref(), ref(), ref(), ref())
        val staticContent = StaticContent()
        val swaggerUi = SwaggerUi(
            publicResourcesBasePath = env.getRequiredProperty("spring.webflux.static-path-pattern").removeSuffix("/**"),
            webJarResourcesBasePath = env.getRequiredProperty("spring.webflux.webjars-path-pattern")
                .removeSuffix("/**"),
        )
        val utilityApi = UtilityApi(ref(), ref())
        walletApi.route
            .and(verifierApi.route)
            .and(staticContent.route)
            .and(swaggerUi.route)
            .and(utilityApi.route)
    }

    //
    // Other
    //
    bean {
        CodecCustomizer {
            val json = Json {
                explicitNulls = false
                ignoreUnknownKeys = true
            }

            it.defaultCodecs().kotlinSerializationJsonDecoder(KotlinSerializationJsonDecoder(json))
            it.defaultCodecs().kotlinSerializationJsonEncoder(KotlinSerializationJsonEncoder(json))
            it.defaultCodecs().enableLoggingRequestDetails(true)
        }
    }
    bean {
        val http = ref<ServerHttpSecurity>()
        http {
            cors { // cross-origin resource sharing configuration
                configurationSource = CorsConfigurationSource {
                    CorsConfiguration().apply {
                        fun getOptionalList(name: String): NonEmptyList<String>? =
                            env.getOptionalList(name = name, filter = { it.isNotBlank() }, transform = { it.trim() })

                        allowedOrigins = getOptionalList("cors.origins")
                        allowedOriginPatterns = getOptionalList("cors.originPatterns")
                        allowedMethods = getOptionalList("cors.methods")
                        run {
                            val headers = getOptionalList("cors.headers")
                            allowedHeaders = headers
                            exposedHeaders = headers
                        }
                        allowCredentials = env.getProperty<Boolean>("cors.credentials")
                        maxAge = env.getProperty<Long>("cors.maxAge")
                    }
                }
            }
            csrf { disable() } // cross-site request forgery disabled
        }
    }
}

private fun BeanSupplierContext.deviceResponseValidator(trustedIssuers: X5CShouldBe): DeviceResponseValidator {
    val docValidator = DocumentValidator(
        clock = ref(),
        issuerSignedItemsShouldBe = IssuerSignedItemsShouldBe.Verified,
        validityInfoShouldBe = ValidityInfoShouldBe.NotExpired,
        x5CShouldBe = trustedIssuers,
    )
    log.info(
        "Created DocumentValidator using: \n\t" +
            "IssuerSignedItemsShouldBe: '${IssuerSignedItemsShouldBe.Verified}', \n\t" +
            "ValidityInfoShouldBe: '${ValidityInfoShouldBe.NotExpired}', and \n\t" +
            "X5CShouldBe '$trustedIssuers'",
    )
    return DeviceResponseValidator(docValidator)
}

private fun BeanSupplierContext.sdJwtVcValidator(trustedIssuers: X5CShouldBe): SdJwtVcValidator =
    SdJwtVcValidator(
        trustedIssuers = trustedIssuers,
        audience = ref<VerifierConfig>().verifierId,
        provider<StatusListTokenValidator>().ifAvailable,
    )

private enum class EmbedOptionEnum {
    ByValue,
    ByReference,
}

private enum class SigningKeyEnum {
    GenerateRandom,
    LoadFromKeystore,
}

private const val keystoreDefaultLocation = "/keystore.jks"

private fun jarSigningConfig(environment: Environment, clock: Clock): SigningConfig {
    val key = run {
        fun loadFromKeystore(): JWK {
            val keystoreResource = run {
                val keystoreLocation = environment.getRequiredProperty("verifier.jar.signing.key.keystore")
                log.info("Will try to load Keystore from: '{}'", keystoreLocation)
                val keystoreResource = DefaultResourceLoader().getResource(keystoreLocation)
                    .some()
                    .filter { it.exists() }
                    .recover {
                        log.warn(
                            "Could not find Keystore at '{}'. Fallback to '{}'",
                            keystoreLocation,
                            keystoreDefaultLocation,
                        )
                        FileSystemResource(keystoreDefaultLocation)
                            .some()
                            .filter { it.exists() }
                            .bind()
                    }
                    .getOrNull()
                checkNotNull(keystoreResource) { "Could not load Keystore either from '$keystoreLocation' or '$keystoreDefaultLocation'" }
            }

            val keystoreType =
                environment.getProperty("verifier.jar.signing.key.keystore.type", KeyStore.getDefaultType())
            val keystorePassword =
                environment.getProperty("verifier.jar.signing.key.keystore.password")?.takeIf { it.isNotBlank() }
            val keyAlias =
                environment.getRequiredProperty("verifier.jar.signing.key.alias")
            val keyPassword =
                environment.getProperty("verifier.jar.signing.key.password")?.takeIf { it.isNotBlank() }

            return keystoreResource.inputStream.use { inputStream ->
                val keystore = KeyStore.getInstance(keystoreType)
                keystore.load(inputStream, keystorePassword?.toCharArray())

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

        fun generateRandom(): ECKey =
            ECKeyGenerator(Curve.P_256)
                .keyUse(KeyUse.SIGNATURE) // indicate the intended use of the key (optional)
                .keyID(UUID.randomUUID().toString()) // give the key a unique ID (optional)
                .issueTime(Date.from(clock.instant())) // issued-at timestamp (optional)
                .generate()

        when (environment.getProperty("verifier.jar.signing.key", SigningKeyEnum::class.java)) {
            SigningKeyEnum.LoadFromKeystore -> loadFromKeystore()
            null, SigningKeyEnum.GenerateRandom -> generateRandom()
        }
    }

    val algorithm = environment.getProperty("verifier.jar.signing.algorithm", "ES256").let(JWSAlgorithm::parse)

    return SigningConfig(key, algorithm)
}

private fun verifierConfig(environment: Environment, clock: Clock): VerifierConfig {
    val verifierId = run {
        val originalClientId = environment.getProperty("verifier.originalClientId", "verifier")
        val jarSigning = jarSigningConfig(environment, clock)

        val factory =
            when (val clientIdScheme = environment.getProperty("verifier.clientIdScheme", "pre-registered")) {
                "pre-registered" -> VerifierId::PreRegistered
                "x509_san_dns" -> VerifierId::X509SanDns
                "x509_san_uri" -> VerifierId::X509SanUri
                else -> error("Unknown clientIdScheme '$clientIdScheme'")
            }
        factory(originalClientId, jarSigning)
    }

    val publicUrl = environment.publicUrl()
    val requestJarOption = environment.getProperty("verifier.requestJwt.embed", EmbedOptionEnum::class.java).let {
        when (it) {
            ByValue -> EmbedOption.ByValue
            ByReference, null -> WalletApi.requestJwtByReference(environment.publicUrl())
        }
    }
    val requestUriMethod = environment.getProperty<RequestUriMethod>("verifier.requestJwt.requestUriMethod") ?: RequestUriMethod.Get
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
    val maxAge = environment.getProperty("verifier.maxAge", Duration::class.java) ?: Duration.ofMinutes(5)

    val transactionDataHashAlgorithm = environment.getProperty("verifier.transactionData.hashAlgorithm", "sha-256")
        .let { configured ->
            val hashAlgorithm = HashAlgorithm.entries.firstOrNull { supported -> supported.ianaName == configured }
            requireNotNull(hashAlgorithm) {
                "'verifier.transactionData.hashAlgorithm' must be one of '${HashAlgorithm.entries.map { it.ianaName }}'"
            }
        }

    return VerifierConfig(
        verifierId = verifierId,
        requestJarOption = requestJarOption,
        requestUriMethod = requestUriMethod,
        presentationDefinitionEmbedOption = presentationDefinitionEmbedOption,
        responseUriBuilder = WalletApi.directPost(publicUrl),
        responseModeOption = responseModeOption,
        maxAge = maxAge,
        clientMetaData = environment.clientMetaData(),
        transactionDataHashAlgorithm = transactionDataHashAlgorithm,
    )
}

private fun Environment.clientMetaData(): ClientMetaData {
    val authorizationSignedResponseAlg =
        getProperty("verifier.clientMetadata.authorizationSignedResponseAlg")
    val authorizationEncryptedResponseAlg =
        getProperty("verifier.clientMetadata.authorizationEncryptedResponseAlg")
    val authorizationEncryptedResponseEnc =
        getProperty("verifier.clientMetadata.authorizationEncryptedResponseEnc")

    val defaultJarmOption = ParseJarmOptionNimbus(null, JWEAlgorithm.ECDH_ES.name, EncryptionMethod.A256GCM.name)
    checkNotNull(defaultJarmOption)

    val vpFormats = VpFormats(
        VpFormat.SdJwtVc(
            sdJwtAlgorithms = getOptionalList(
                name = "verifier.clientMetadata.vpFormats.sdJwtVc.sdJwtAlgorithms",
                filter = { it.isNotBlank() },
            )?.distinct()?.map { JWSAlgorithm.parse(it) } ?: nonEmptyListOf(JWSAlgorithm.ES256),

            kbJwtAlgorithms = getOptionalList(
                name = "verifier.clientMetadata.vpFormats.sdJwtVc.kbJwtAlgorithms",
                filter = { it.isNotBlank() },
            )?.distinct()?.map { JWSAlgorithm.parse(it) } ?: nonEmptyListOf(JWSAlgorithm.ES256),
        ),

        VpFormat.MsoMdoc(
            algorithms = getOptionalList(
                name = "verifier.clientMetadata.vpFormats.msoMdoc.algorithms",
                filter = { it.isNotBlank() },
            )?.distinct()?.map { JWSAlgorithm.parse(it) } ?: nonEmptyListOf(JWSAlgorithm.ES256),
        ),
    )

    return ClientMetaData(
        idTokenSignedResponseAlg = JWSAlgorithm.RS256.name,
        idTokenEncryptedResponseAlg = JWEAlgorithm.RSA_OAEP_256.name,
        idTokenEncryptedResponseEnc = EncryptionMethod.A128CBC_HS256.name,
        subjectSyntaxTypesSupported = listOf(
            "urn:ietf:params:oauth:jwk-thumbprint",
        ),
        jarmOption = ParseJarmOptionNimbus.invoke(
            authorizationSignedResponseAlg,
            authorizationEncryptedResponseAlg,
            authorizationEncryptedResponseEnc,
        ) ?: defaultJarmOption,
        vpFormats = vpFormats,
    )
}

/**
 * Gets the public URL of the Verifier endpoint. Corresponds to `verifier.publicUrl` property.
 */
private fun Environment.publicUrl(): String = getProperty("verifier.publicUrl", "http://localhost:8080")

/**
 * Creates a copy of this [JWK] and sets the provided [X509Certificate] certificate chain.
 * For the operation to succeed, the following must hold true:
 * 1. [chain] cannot be empty
 * 2. The leaf certificate of the [chain] must match the leaf certificate of this [JWK]
 */
private fun JWK.withCertificateChain(chain: List<X509Certificate>): JWK {
    require(this.parsedX509CertChain.isNotEmpty()) { "jwk must has a leaf certificate" }
    require(chain.isNotEmpty()) { "chain cannot be empty" }
    require(
        this.parsedX509CertChain.first() == chain.first(),
    ) { "leaf certificate of provided chain does not match leaf certificate of jwk" }

    val encodedChain = chain.map { Base64.encode(it.encoded) }
    return when (this) {
        is RSAKey -> RSAKey.Builder(this).x509CertChain(encodedChain).build()
        is ECKey -> ECKey.Builder(this).x509CertChain(encodedChain).build()
        is OctetKeyPair -> OctetKeyPair.Builder(this).x509CertChain(encodedChain).build()
        is OctetSequenceKey -> OctetSequenceKey.Builder(this).x509CertChain(encodedChain).build()
        else -> error("Unexpected JWK type '${this.keyType.value}'/'${this.javaClass}'")
    }
}

/**
 * Gets the value of a property that contains a comma-separated list. A list is returned when it contains values.
 *
 * @receiver the configured Spring [Environment] from which to load the property
 * @param name the property to load
 * @param filter optional filter to apply to the list value
 * @param transform optional mapping to apply to the list values
 */
private fun Environment.getOptionalList(
    name: String,
    filter: (String) -> Boolean = { true },
    transform: (String) -> String = { it },
): NonEmptyList<String>? =
    this.getProperty(name)
        ?.split(",")
        ?.filter { filter(it) }
        ?.map { transform(it) }
        ?.toNonEmptyListOrNull()

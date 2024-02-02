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
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator
import com.nimbusds.jose.util.Base64
import com.nimbusds.jose.util.X509CertUtils
import eu.europa.ec.eudi.verifier.endpoint.EmbedOptionEnum.ByReference
import eu.europa.ec.eudi.verifier.endpoint.EmbedOptionEnum.ByValue
import eu.europa.ec.eudi.verifier.endpoint.adapter.input.timer.ScheduleTimeoutPresentations
import eu.europa.ec.eudi.verifier.endpoint.adapter.input.web.StaticContent
import eu.europa.ec.eudi.verifier.endpoint.adapter.input.web.VerifierApi
import eu.europa.ec.eudi.verifier.endpoint.adapter.input.web.WalletApi
import eu.europa.ec.eudi.verifier.endpoint.adapter.out.cfg.GenerateRequestIdNimbus
import eu.europa.ec.eudi.verifier.endpoint.adapter.out.cfg.GenerateTransactionIdNimbus
import eu.europa.ec.eudi.verifier.endpoint.adapter.out.jose.GenerateEphemeralEncryptionKeyPairNimbus
import eu.europa.ec.eudi.verifier.endpoint.adapter.out.jose.ParseJarmOptionNimbus
import eu.europa.ec.eudi.verifier.endpoint.adapter.out.jose.SignRequestObjectNimbus
import eu.europa.ec.eudi.verifier.endpoint.adapter.out.jose.VerifyJarmEncryptedJwtNimbus
import eu.europa.ec.eudi.verifier.endpoint.adapter.out.persistence.PresentationInMemoryRepo
import eu.europa.ec.eudi.verifier.endpoint.domain.*
import eu.europa.ec.eudi.verifier.endpoint.port.input.*
import eu.europa.ec.eudi.verifier.endpoint.port.out.cfg.CreateQueryWalletResponseRedirectUri
import eu.europa.ec.eudi.verifier.endpoint.port.out.cfg.GenerateResponseCode
import kotlinx.serialization.ExperimentalSerializationApi
import kotlinx.serialization.json.Json
import org.slf4j.LoggerFactory
import org.springframework.boot.web.codec.CodecCustomizer
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
    //
    // JOSE
    //
    bean { SignRequestObjectNimbus() }
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
    }

    bean { CreateQueryWalletResponseRedirectUri.Simple }

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
            clock,
            ref(),
            WalletApi.requestJwtByReference(env.publicUrl()),
            WalletApi.presentationDefinitionByReference(env.publicUrl()),
            ref(),
        )
    }

    bean { GetRequestObjectLive(ref(), ref(), ref(), ref(), clock) }

    bean { GetPresentationDefinitionLive(ref()) }
    bean {
        TimeoutPresentationsLive(
            ref(),
            ref(),
            ref<VerifierConfig>().maxAge,
            clock,
        )
    }

    bean { GenerateResponseCode.Random }
    bean { PostWalletResponseLive(ref(), ref(), ref(), clock, ref(), ref(), ref()) }
    bean { GenerateEphemeralEncryptionKeyPairNimbus }
    bean { GetWalletResponseLive(ref()) }
    bean { GetJarmJwksLive(ref()) }

    //
    // Scheduled
    //
    bean { ScheduleTimeoutPresentations(ref()) }

    //
    // Config
    //
    bean { verifierConfig(env, clock) }

    //
    // End points
    //

    bean {
        val walletApi = WalletApi(
            ref(),
            ref(),
            ref(),
            ref(),
            ref<VerifierConfig>().clientIdScheme.jarSigning.key,
        )
        val verifierApi = VerifierApi(ref(), ref())
        val staticContent = StaticContent()
        walletApi.route.and(verifierApi.route).and(staticContent.route)
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
                        log.warn("Could not find Keystore at '{}'. Fallback to '{}'", keystoreLocation, keystoreDefaultLocation)
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

        fun generateRandom(): RSAKey =
            RSAKeyGenerator(4096, false)
                .keyUse(KeyUse.SIGNATURE) // indicate the intended use of the key (optional)
                .keyID(UUID.randomUUID().toString()) // give the key a unique ID (optional)
                .issueTime(Date.from(clock.instant())) // issued-at timestamp (optional)
                .generate()

        when (environment.getProperty("verifier.jar.signing.key", SigningKeyEnum::class.java)) {
            SigningKeyEnum.LoadFromKeystore -> loadFromKeystore()
            null, SigningKeyEnum.GenerateRandom -> generateRandom()
        }
    }

    val algorithm = environment.getProperty("verifier.jar.signing.algorithm", "RS256").let(JWSAlgorithm::parse)

    return SigningConfig(key, algorithm)
}

private fun verifierConfig(environment: Environment, clock: Clock): VerifierConfig {
    val clientIdScheme = run {
        val clientId = environment.getProperty("verifier.clientId", "verifier")
        val jarSigning = jarSigningConfig(environment, clock)

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
            ByReference -> WalletApi.jarmJwksByReference(publicUrl)
            ByValue, null -> EmbedOption.ByValue
        }
    }

    val authorizationSignedResponseAlg =
        getProperty("verifier.clientMetadata.authorizationSignedResponseAlg")
    val authorizationEncryptedResponseAlg =
        getProperty("verifier.clientMetadata.authorizationEncryptedResponseAlg")
    val authorizationEncryptedResponseEnc =
        getProperty("verifier.clientMetadata.authorizationEncryptedResponseEnc")

    val defaultJarmOption = ParseJarmOptionNimbus(null, JWEAlgorithm.ECDH_ES.name, EncryptionMethod.A256GCM.name)
    checkNotNull(defaultJarmOption)

    return ClientMetaData(
        jwkOption = jwkOption,
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

    val encodedChain = chain.toBase64PEMEncoded()
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

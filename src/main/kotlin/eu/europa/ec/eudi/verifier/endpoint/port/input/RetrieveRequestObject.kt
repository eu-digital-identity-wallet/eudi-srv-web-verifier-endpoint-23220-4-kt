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
package eu.europa.ec.eudi.verifier.endpoint.port.input

import arrow.core.Either
import arrow.core.getOrElse
import arrow.core.raise.Raise
import arrow.core.raise.either
import arrow.core.raise.ensure
import arrow.core.toNonEmptyListOrNull
import com.nimbusds.jose.EncryptionMethod
import com.nimbusds.jose.JWEAlgorithm
import com.nimbusds.jose.jwk.JWK
import com.nimbusds.jose.jwk.JWKSet
import eu.europa.ec.eudi.sdjwt.SdJwtVcSpec
import eu.europa.ec.eudi.sdjwt.vc.KtorHttpClientFactory
import eu.europa.ec.eudi.verifier.endpoint.adapter.out.json.decodeAs
import eu.europa.ec.eudi.verifier.endpoint.adapter.out.json.jsonSupport
import eu.europa.ec.eudi.verifier.endpoint.adapter.out.metadata.MsoMdocFormatTO
import eu.europa.ec.eudi.verifier.endpoint.adapter.out.metadata.SdJwtVcFormatTO
import eu.europa.ec.eudi.verifier.endpoint.adapter.out.utils.getOrThrow
import eu.europa.ec.eudi.verifier.endpoint.domain.*
import eu.europa.ec.eudi.verifier.endpoint.port.out.jose.CreateJar
import eu.europa.ec.eudi.verifier.endpoint.port.out.persistence.LoadPresentationByRequestId
import eu.europa.ec.eudi.verifier.endpoint.port.out.persistence.PresentationEvent
import eu.europa.ec.eudi.verifier.endpoint.port.out.persistence.PublishPresentationEvent
import eu.europa.ec.eudi.verifier.endpoint.port.out.persistence.StorePresentation
import io.ktor.client.*
import io.ktor.client.request.*
import io.ktor.client.statement.*
import kotlinx.serialization.Required
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.JsonObject
import java.time.Clock
import kotlin.reflect.KClass

/**
 * Method used to invoke GetRequestObject.
 */
sealed interface RetrieveRequestObjectMethod {
    data object Get : RetrieveRequestObjectMethod
    data class Post(val walletMetadata: String?, val walletNonce: String?) : RetrieveRequestObjectMethod
}

/**
 * Errors that can be produced by GetRequestObject
 */
sealed interface RetrieveRequestObjectError {
    data object PresentationNotFound : RetrieveRequestObjectError
    data class InvalidState(val expected: KClass<out Presentation>, val actual: KClass<out Presentation>) : RetrieveRequestObjectError
    data class InvalidRequestUriMethod(val expected: RequestUriMethod) : RetrieveRequestObjectError
    data class UnparsableWalletMetadata(val message: String, val cause: Throwable? = null) : RetrieveRequestObjectError
    data class UnsupportedWalletMetadata(val message: String, val cause: Throwable? = null) : RetrieveRequestObjectError
    data class InvalidWalletMetadata(val message: String, val cause: Throwable? = null) : RetrieveRequestObjectError
}

/**
 * Given a [RequestId] it returns a RFC9101 Request Object
 * encoded as JWT, if the [Presentation] is input state [Presentation.Requested].
 * In this case, the [Presentation] is updated to [Presentation.RequestObjectRetrieved]
 * input order to guarantee that only once the Request Object can be retrieved by
 * the wallet
 */
fun interface RetrieveRequestObject {
    suspend operator fun invoke(
        requestId: RequestId,
        method: RetrieveRequestObjectMethod,
    ): Either<RetrieveRequestObjectError, Jwt>
}

class RetrieveRequestObjectLive(
    private val loadPresentationByRequestId: LoadPresentationByRequestId,
    private val storePresentation: StorePresentation,
    private val createJar: CreateJar,
    private val verifierConfig: VerifierConfig,
    private val clock: Clock,
    private val publishPresentationEvent: PublishPresentationEvent,
    private val clientFactory: KtorHttpClientFactory,
) : RetrieveRequestObject {

    private val walletMetadataValidator = WalletMetadataValidator(verifierConfig, clientFactory)

    override suspend operator fun invoke(
        requestId: RequestId,
        method: RetrieveRequestObjectMethod,
    ): Either<RetrieveRequestObjectError, Jwt> =
        either {
            when (val presentation = loadPresentationByRequestId(requestId)) {
                null -> raise(RetrieveRequestObjectError.PresentationNotFound)
                else -> found(presentation, method).bind()
            }
        }

    private suspend fun found(
        presentation: Presentation,
        method: RetrieveRequestObjectMethod,
    ): Either<RetrieveRequestObjectError, Jwt> =
        either {
            ensure(presentation is Presentation.Requested) {
                RetrieveRequestObjectError.InvalidState(Presentation.Requested::class, presentation::class)
            }

            suspend fun updatePresentationAndCreateJar(
                encryptionRequirement: EncryptionRequirement,
            ): Pair<Presentation.RequestObjectRetrieved, Jwt> {
                val jar = createJar(
                    verifierConfig,
                    clock,
                    presentation,
                    method.walletNonceOrNull,
                    encryptionRequirement,
                ).getOrThrow()
                val updatedPresentation = presentation.retrieveRequestObject(clock).getOrThrow()
                storePresentation(updatedPresentation)
                return updatedPresentation to jar
            }

            suspend fun log(p: Presentation.RequestObjectRetrieved, jwt: Jwt) {
                val event = PresentationEvent.RequestObjectRetrieved(p.id, p.requestObjectRetrievedAt, jwt)
                publishPresentationEvent(event)
            }

            ensure(method is RetrieveRequestObjectMethod.Get || RequestUriMethod.Post == presentation.requestUriMethod) {
                RetrieveRequestObjectError.InvalidRequestUriMethod(presentation.requestUriMethod)
            }

            val walletMetadata = method.walletMetadataOrNull?.let { parseWalletMetadata(it).bind() }
            val encryptionRequirement = walletMetadata?.validate(presentation)?.bind() ?: EncryptionRequirement.NotRequired

            val (updatePresentation, jar) = updatePresentationAndCreateJar(encryptionRequirement)
            log(updatePresentation, jar)
            jar
        }.onLeft { error ->
            val cause = when (error) {
                RetrieveRequestObjectError.PresentationNotFound -> null
                is RetrieveRequestObjectError.InvalidState ->
                    "Presentation should be in state ${error.expected.simpleName} but is in ${error.actual.simpleName}"
                is RetrieveRequestObjectError.InvalidRequestUriMethod ->
                    "Invalid request_uri_method used, expected ${error.expected}"
                is RetrieveRequestObjectError.UnparsableWalletMetadata ->
                    "Wallet metadata could not be parsed, reason: ${error.cause?.message ?: "n/a"}"
                is RetrieveRequestObjectError.UnsupportedWalletMetadata ->
                    "Wallet metadata contains unsupported values, reason: ${error.message}, ${error.cause?.message ?: "n/a"}"
                is RetrieveRequestObjectError.InvalidWalletMetadata ->
                    "Wallet metadata is not valid, reason: ${error.message}, ${error.cause?.message ?: "n/a"}"
            }

            cause?.let {
                val event = PresentationEvent.FailedToRetrieveRequestObject(presentation.id, clock.instant(), it)
                publishPresentationEvent(event)
            }
        }

    private suspend fun WalletMetadataTO.validate(
        presentation: Presentation.Requested,
    ): Either<RetrieveRequestObjectError, EncryptionRequirement> =
        walletMetadataValidator.validate(this, presentation)
}

/**
 * Validator for Wallet Metadata.
 */
private class WalletMetadataValidator(private val verifierConfig: VerifierConfig, private val clientFactory: KtorHttpClientFactory) {

    suspend fun validate(
        metadata: WalletMetadataTO,
        presentation: Presentation.Requested,
    ): Either<RetrieveRequestObjectError, EncryptionRequirement> = either {
//        ensureWalletSupportPresentationDefinitionUriIfRequired(metadata, presentation)
        ensureWalletSupportsRequiredVpFormats(metadata, presentation)
        ensureWalletSupportsVerifierClientIdScheme(metadata)
        ensureVerifierSupportsWalletJarSigningAlgorithms(metadata)
        ensureWalletSupportsRequiredResponseType(metadata, presentation)
        ensureWalletSupportsRequiredResponseMode(metadata, presentation)
        encryptionRequirement(metadata)
    }

    private fun Raise<RetrieveRequestObjectError>.ensureWalletSupportsRequiredVpFormats(
        metadata: WalletMetadataTO,
        presentation: Presentation.Requested,
    ) {
        val walletSupportedVpFormats = metadata.vpFormatsSupported.toVpFormats().getOrElse {
            raise(RetrieveRequestObjectError.UnsupportedWalletMetadata("Wallet metadata contains malformed VpFormats", it))
        }.groupBy { it::class }
        val verifierSupportedVpFormats = verifierConfig.clientMetaData.vpFormats
        val queryRequiredVpFormats = when (val query = presentation.type.presentationQueryOrNull) {
            is PresentationQuery.ByDigitalCredentialsQueryLanguage -> query.query.vpFormats(verifierSupportedVpFormats)
            null -> emptyList()
        }.groupBy { it::class }
        val walletSupportsAllRequiredVpFormats = queryRequiredVpFormats.map { (vpFormatType, vpFormats) ->
            val walletSupported = walletSupportedVpFormats[vpFormatType].orEmpty()
            vpFormats.all { required -> walletSupported.any { supported -> supported.supports(required) } }
        }.foldRight(true, Boolean::and)
        ensure(walletSupportsAllRequiredVpFormats) {
            RetrieveRequestObjectError.UnsupportedWalletMetadata("Wallet does not support all required VpFormats")
        }
    }

    private fun Raise<RetrieveRequestObjectError>.ensureWalletSupportsVerifierClientIdScheme(metadata: WalletMetadataTO) {
        val clientIdScheme = verifierConfig.verifierId.clientIdScheme
        val supportedClientIdSchemes = metadata.clientIdSchemesSupported ?: OpenId4VPSpec.DEFAULT_CLIENT_ID_SCHEMES_SUPPORTED
        ensure(clientIdScheme in supportedClientIdSchemes) {
            RetrieveRequestObjectError.UnsupportedWalletMetadata("Wallet does not support Client Id Scheme '$clientIdScheme'")
        }
    }

    private fun Raise<RetrieveRequestObjectError>.ensureVerifierSupportsWalletJarSigningAlgorithms(metadata: WalletMetadataTO) {
        val jarSigningAlgorithm = verifierConfig.verifierId.jarSigning.algorithm.name
        ensure(jarSigningAlgorithm in metadata.signingAlgorithmsSupported.orEmpty()) {
            RetrieveRequestObjectError.UnsupportedWalletMetadata(
                "Wallet does not support JAR Signing Algorithms '$jarSigningAlgorithm'",
            )
        }
    }

    private fun Raise<RetrieveRequestObjectError>.ensureWalletSupportsRequiredResponseType(
        metadata: WalletMetadataTO,
        presentation: Presentation.Requested,
    ) {
        val responseType = presentation.type.responseType
        ensure(responseType in metadata.responseTypesSupported) {
            RetrieveRequestObjectError.UnsupportedWalletMetadata("Wallet does not support Response Type '$responseType'")
        }
    }

    private fun Raise<RetrieveRequestObjectError>.ensureWalletSupportsRequiredResponseMode(
        metadata: WalletMetadataTO,
        presentation: Presentation.Requested,
    ) {
        val responseMode = presentation.responseMode.name()
        val supportedResponseModes = metadata.responseModesSupported ?: RFC8414.DEFAULT_RESPONSE_MODES_SUPPORTED
        ensure(responseMode in supportedResponseModes) {
            RetrieveRequestObjectError.UnsupportedWalletMetadata("Wallet does not support Response Mode '$responseMode'")
        }
    }

    private suspend fun Raise<RetrieveRequestObjectError>.encryptionRequirement(metadata: WalletMetadataTO): EncryptionRequirement {
        ensure((null == metadata.jwks && null == metadata.jwksUri) || ((null != metadata.jwks) xor (null != metadata.jwksUri))) {
            RetrieveRequestObjectError.InvalidWalletMetadata(
                "Either none of or only one of '${RFC8414.JWKS}', '${RFC8414.JWKS_URI}' must be provided",
            )
        }

        val jwks = metadata.jwks?.toJwks()?.bind() ?: metadata.jwksUri?.let { clientFactory().use { client -> client.getJwks(it).bind() } }
        return if (null == jwks) {
            EncryptionRequirement.NotRequired
        } else {
            val walletSupportedEncryptionAlgorithms = metadata.encryptionAlgorithmsSupported.orEmpty().map { JWEAlgorithm.parse(it) }
            val walletSupportedEncryptionMethods = metadata.encryptionMethodsSupported.orEmpty().map { EncryptionMethod.parse(it) }

            EncryptionRequirement.Required.create(
                jwks.keys,
                walletSupportedEncryptionAlgorithms,
                walletSupportedEncryptionMethods,
            ).bind()
        }
    }
}

/**
 * Transfer object for Wallet metadata.
 */
@Serializable
private data class WalletMetadataTO(
    @SerialName(OpenId4VPSpec.PRESENTATION_DEFINITION_URI_SUPPORTED)
    val presentationDefinitionUriSupported: Boolean? = OpenId4VPSpec.DEFAULT_PRESENTATION_DEFINITION_URI_SUPPORTED,

    @Required
    @SerialName(OpenId4VPSpec.VP_FORMATS_SUPPORTED)
    val vpFormatsSupported: JsonObject,

    @SerialName(OpenId4VPSpec.CLIENT_ID_SCHEMES_SUPPORTED)
    val clientIdSchemesSupported: List<String>? = OpenId4VPSpec.DEFAULT_CLIENT_ID_SCHEMES_SUPPORTED,

    @SerialName(RFC8414.JWKS)
    val jwks: JsonObject? = null,

    @SerialName(RFC8414.JWKS_URI)
    val jwksUri: String? = null,

    @SerialName(JarmSpec.AUTHORIZATION_ENCRYPTION_ALGORITHMS_SUPPORTED)
    val encryptionAlgorithmsSupported: List<String>? = null,

    @SerialName(JarmSpec.AUTHORIZATION_ENCRYPTION_METHODS_SUPPORTED)
    val encryptionMethodsSupported: List<String>? = null,

    @SerialName(RFC9101.REQUEST_OBJECT_SIGNING_ALGORITHMS_SUPPORTED)
    val signingAlgorithmsSupported: List<String>? = null,

    @Required
    @SerialName(RFC8414.RESPONSE_TYPES_SUPPORTED)
    val responseTypesSupported: List<String>,

    @SerialName(RFC8414.RESPONSE_MODES_SUPPORTED)
    val responseModesSupported: List<String>? = RFC8414.DEFAULT_RESPONSE_MODES_SUPPORTED,
)

private fun parseWalletMetadata(serialized: String): Either<RetrieveRequestObjectError.UnparsableWalletMetadata, WalletMetadataTO> =
    Either.catch {
        jsonSupport.decodeFromString<WalletMetadataTO>(serialized)
    }.mapLeft { RetrieveRequestObjectError.UnparsableWalletMetadata("Wallet Metadata cannot be parsed", it) }

private val RetrieveRequestObjectMethod.walletMetadataOrNull: String?
    get() = when (this) {
        RetrieveRequestObjectMethod.Get -> null
        is RetrieveRequestObjectMethod.Post -> walletMetadata
    }

private val RetrieveRequestObjectMethod.walletNonceOrNull: String?
    get() = when (this) {
        RetrieveRequestObjectMethod.Get -> null
        is RetrieveRequestObjectMethod.Post -> walletNonce
    }

private val VerifierId.clientIdScheme: String
    get() = when (this) {
        is VerifierId.PreRegistered -> OpenId4VPSpec.CLIENT_ID_SCHEME_PRE_REGISTERED
        is VerifierId.X509SanDns -> OpenId4VPSpec.CLIENT_ID_SCHEME_X509_SAN_DNS
        is VerifierId.X509SanUri -> OpenId4VPSpec.CLIENT_ID_SCHEME_X509_SAN_URI
    }

private val PresentationType.responseType: String
    get() = when (this) {
        is PresentationType.IdTokenRequest -> "id_token"
        is PresentationType.VpTokenRequest -> "vp_token"
        is PresentationType.IdAndVpToken -> "vp_token id_token"
    }

private fun ResponseModeOption.name(): String =
    when (this) {
        ResponseModeOption.DirectPost -> OpenId4VPSpec.DIRECT_POST
        ResponseModeOption.DirectPostJwt -> OpenId4VPSpec.DIRECT_POST_JWT
    }

private fun JsonObject.toVpFormats(): Either<Throwable, List<VpFormat>> =
    Either.catch {
        mapNotNull { (identifier, serializedProperties) ->
            when (identifier) {
                SdJwtVcSpec.MEDIA_SUBTYPE_DC_SD_JWT ->
                    serializedProperties.decodeAs<SdJwtVcFormatTO>()
                        .getOrThrow()
                        .let { properties ->
                            VpFormat.SdJwtVc(
                                sdJwtAlgorithms = properties.sdJwtAlgorithms.toNonEmptyListOrNull()!!,
                                kbJwtAlgorithms = properties.kbJwtAlgorithms.toNonEmptyListOrNull()!!,
                            )
                        }

                OpenId4VPSpec.FORMAT_MSO_MDOC ->
                    serializedProperties.decodeAs<MsoMdocFormatTO>()
                        .getOrThrow()
                        .let { properties -> VpFormat.MsoMdoc(properties.algorithms.toNonEmptyListOrNull()!!) }

                else -> null
            }
        }.distinct()
    }

private fun DCQL.vpFormats(supported: VpFormats): List<VpFormat> =
    credentials.mapNotNull {
        when (it.format.value) {
            SdJwtVcSpec.MEDIA_SUBTYPE_DC_SD_JWT -> supported.sdJwtVc
            OpenId4VPSpec.FORMAT_MSO_MDOC -> supported.msoMdoc
            else -> null
        }
    }.distinct()

private fun VpFormat.supports(other: VpFormat): Boolean =
    when (this) {
        is VpFormat.SdJwtVc ->
            other is VpFormat.SdJwtVc &&
                sdJwtAlgorithms.intersect(other.sdJwtAlgorithms).isNotEmpty() &&
                kbJwtAlgorithms.intersect(other.kbJwtAlgorithms).isNotEmpty()

        is VpFormat.MsoMdoc ->
            other is VpFormat.MsoMdoc &&
                algorithms.intersect(other.algorithms).isNotEmpty()
    }

private fun JsonObject.toJwks(): Either<RetrieveRequestObjectError.InvalidWalletMetadata, JWKSet> =
    Either.catch {
        JWKSet.parse(jsonSupport.encodeToString(this))
    }.mapLeft { RetrieveRequestObjectError.InvalidWalletMetadata("Cannot convert JsonObject to JWKS", it) }

private suspend fun HttpClient.getJwks(jwksLocation: String): Either<RetrieveRequestObjectError.InvalidWalletMetadata, JWKSet> =
    Either.catch {
        JWKSet.parse(get(jwksLocation).bodyAsText())
    }.mapLeft { RetrieveRequestObjectError.InvalidWalletMetadata("Unable to fetch encryption JWKS", it) }

private fun EncryptionRequirement.Required.Companion.create(
    jwks: List<JWK>,
    algorithms: List<JWEAlgorithm>,
    methods: List<EncryptionMethod>,
): Either<RetrieveRequestObjectError, EncryptionRequirement.Required> =
    either {
        ensure(jwks.isNotEmpty()) { RetrieveRequestObjectError.InvalidWalletMetadata("Missing encryption keys") }
        ensure(algorithms.isNotEmpty()) { RetrieveRequestObjectError.InvalidWalletMetadata("Missing encryption algorithms") }
        ensure(methods.isNotEmpty()) { RetrieveRequestObjectError.InvalidWalletMetadata("Missing encryption methods") }

        val encryptionRequirement = jwks.filter { it.isSupportedEncryptionJwk() }
            .firstNotNullOfOrNull { encryptionKey ->
                val encryptionKeySupportedEncryptionAlgorithms = encryptionKey.supportedEncryptionAlgorithms.intersect(algorithms.toSet())
                    .sortedBy { encryptionAlgorithm -> encryptionAlgorithmPreferenceMap[encryptionAlgorithm] }
                val encryptionKeySupportedEncryptionMethods = encryptionKey.supportedEncryptionMethods.intersect(methods.toSet())
                    .sortedBy { encryptionMethod -> encryptionMethodPreferenceMap[encryptionMethod] }
                if (encryptionKeySupportedEncryptionAlgorithms.isNotEmpty() && encryptionKeySupportedEncryptionMethods.isNotEmpty()) {
                    EncryptionRequirement.Required(
                        encryptionKey.toPublicJWK(),
                        encryptionKeySupportedEncryptionAlgorithms.first(),
                        encryptionKeySupportedEncryptionMethods.first(),
                    )
                } else null
            }

        encryptionRequirement
            ?: raise(RetrieveRequestObjectError.UnsupportedWalletMetadata("Wallet Metadata contains unsupported encryption parameters"))
    }

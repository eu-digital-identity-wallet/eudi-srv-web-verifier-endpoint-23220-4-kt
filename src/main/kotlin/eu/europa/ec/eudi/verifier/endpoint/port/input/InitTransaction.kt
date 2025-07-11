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
@file:OptIn(ExperimentalSerializationApi::class)

package eu.europa.ec.eudi.verifier.endpoint.port.input

import arrow.core.*
import arrow.core.raise.either
import arrow.core.raise.ensure
import com.eygraber.uri.Uri
import com.eygraber.uri.toURI
import com.nimbusds.jose.JWSAlgorithm
import eu.europa.ec.eudi.sdjwt.SdJwtVcSpec
import eu.europa.ec.eudi.verifier.endpoint.adapter.out.json.decodeAs
import eu.europa.ec.eudi.verifier.endpoint.adapter.out.utils.getOrThrow
import eu.europa.ec.eudi.verifier.endpoint.domain.*
import eu.europa.ec.eudi.verifier.endpoint.port.out.cfg.CreateQueryWalletResponseRedirectUri
import eu.europa.ec.eudi.verifier.endpoint.port.out.cfg.GenerateRequestId
import eu.europa.ec.eudi.verifier.endpoint.port.out.cfg.GenerateTransactionId
import eu.europa.ec.eudi.verifier.endpoint.port.out.jose.CreateJar
import eu.europa.ec.eudi.verifier.endpoint.port.out.jose.GenerateEphemeralEncryptionKeyPair
import eu.europa.ec.eudi.verifier.endpoint.port.out.persistence.PresentationEvent
import eu.europa.ec.eudi.verifier.endpoint.port.out.persistence.PublishPresentationEvent
import eu.europa.ec.eudi.verifier.endpoint.port.out.persistence.StorePresentation
import eu.europa.ec.eudi.verifier.endpoint.port.out.qrcode.GenerateQrCode
import eu.europa.ec.eudi.verifier.endpoint.port.out.qrcode.Pixels.Companion.pixels
import eu.europa.ec.eudi.verifier.endpoint.port.out.qrcode.by
import eu.europa.ec.eudi.verifier.endpoint.port.out.x509.ParsePemEncodedX509CertificateChain
import kotlinx.serialization.*
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.add
import kotlinx.serialization.json.buildJsonArray
import java.net.URI
import java.net.URL
import java.security.cert.X509Certificate
import java.time.Clock

/**
 * Represent the kind of [Presentation] process
 * a caller wants to initiate
 * It could be either a request (to the wallet) to present
 * an id_token, a vp_token or both
 */
@Serializable
enum class PresentationTypeTO {
    @SerialName("id_token")
    IdTokenRequest,

    @SerialName("vp_token")
    VpTokenRequest,

    @SerialName("vp_token id_token")
    IdAndVpTokenRequest,
}

/**
 * Specifies what kind of id_token to request
 */
@Serializable
enum class IdTokenTypeTO {
    @SerialName("subject_signed_id_token")
    SubjectSigned,

    @SerialName("attester_signed_id_token")
    AttesterSigned,
}

/**
 * Specifies request_uri_method for a request
 */
@Serializable
enum class RequestUriMethodTO {
    @SerialName(OpenId4VPSpec.REQUEST_URI_METHOD_GET)
    Get,

    @SerialName(OpenId4VPSpec.REQUEST_URI_METHOD_POST)
    Post,
}

/**
 * Specifies the response_mode for a request
 */
@Serializable
enum class ResponseModeTO {
    @SerialName(OpenId4VPSpec.DIRECT_POST)
    DirectPost,

    @SerialName(OpenId4VPSpec.DIRECT_POST_JWT)
    DirectPostJwt,
}

/**
 * Specifies whether a property of a request will be provided by value or by reference.
 */
@Serializable
enum class EmbedModeTO {
    @SerialName("by_value")
    ByValue,

    @SerialName("by_reference")
    ByReference,
}

@Serializable
data class InitTransactionTO(
    @SerialName("type") val type: PresentationTypeTO = PresentationTypeTO.IdAndVpTokenRequest,
    @SerialName("id_token_type") val idTokenType: IdTokenTypeTO? = null,
    @SerialName("dcql_query") val dcqlQuery: DCQL? = null,
    @SerialName("nonce") val nonce: String? = null,
    @SerialName("response_mode") val responseMode: ResponseModeTO? = null,
    @SerialName("jar_mode") val jarMode: EmbedModeTO? = null,
    @SerialName("request_uri_method") val requestUriMethod: RequestUriMethodTO? = null,
    @SerialName("wallet_response_redirect_uri_template") val redirectUriTemplate: String? = null,
    @SerialName("transaction_data") val transactionData: List<JsonObject>? = null,
    @SerialName("issuer_chain") val issuerChain: String? = null,
    @SerialName("authorization_request_scheme") val authorizationRequestScheme: String? = null,
    @Transient val output: Output = Output.Json,
)

/**
 * Possible validation errors of caller's input
 */
enum class ValidationError {
    MissingPresentationQuery,
    MultiplePresentationQueries,
    MissingNonce,
    InvalidWalletResponseTemplate,
    InvalidTransactionData,
    UnsupportedFormat,
    InvalidIssuerChain,
    InvalidAuthorizationRequestScheme,
}

enum class Output {
    Json,
    QrCode,
}

sealed interface InitTransactionResponse {
    /**
     * The return value of successfully [initializing][InitTransaction] a [Presentation] as a QR Code
     *
     */
    @JvmInline
    value class QrCode(val qrCode: ByteArray) : InitTransactionResponse

    /**
     * The return value of successfully [initializing][InitTransaction] a [Presentation] as a JSON
     *
     */
    @Serializable
    data class JwtSecuredAuthorizationRequestTO(
        @Required @SerialName("transaction_id") val transactionId: String,
        @Required @SerialName("client_id") val clientId: ClientId,
        @SerialName("request") val request: String?,
        @SerialName("request_uri") val requestUri: String?,
        @SerialName("request_uri_method") val requestUriMethod: RequestUriMethodTO?,
    ) : InitTransactionResponse {
        companion object {

            fun byValue(
                transactionId: String,
                clientId: ClientId,
                request: String,
            ): JwtSecuredAuthorizationRequestTO = JwtSecuredAuthorizationRequestTO(transactionId, clientId, request, null, null)

            fun byReference(
                transactionId: String,
                clientId: ClientId,
                requestUri: URL,
                requestUriMethod: RequestUriMethodTO,
            ): JwtSecuredAuthorizationRequestTO = JwtSecuredAuthorizationRequestTO(
                transactionId,
                clientId,
                null,
                requestUri.toExternalForm(),
                requestUriMethod,
            )
        }
    }
}

/**
 * This is a use case that initializes the [Presentation] process.
 *
 * The caller may define via [InitTransactionTO] what kind of transaction wants to initiate
 * This is represented by [PresentationTypeTO].
 *
 * Use case will initialize a [Presentation] process
 */
fun interface InitTransaction {

    suspend operator fun invoke(
        initTransactionTO: InitTransactionTO,
    ): Either<ValidationError, InitTransactionResponse>
}

/**
 * The default implementation of the use case
 */
class InitTransactionLive(
    private val generateTransactionId: GenerateTransactionId,
    private val generateRequestId: GenerateRequestId,
    private val storePresentation: StorePresentation,
    private val createJar: CreateJar,
    private val verifierConfig: VerifierConfig,
    private val clock: Clock,
    private val generateEphemeralEncryptionKeyPair: GenerateEphemeralEncryptionKeyPair,
    private val requestJarByReference: EmbedOption.ByReference<RequestId>,
    private val presentationDefinitionByReference: EmbedOption.ByReference<RequestId>,
    private val createQueryWalletResponseRedirectUri: CreateQueryWalletResponseRedirectUri,
    private val publishPresentationEvent: PublishPresentationEvent,
    private val parsePemEncodedX509CertificateChain: ParsePemEncodedX509CertificateChain,
    private val generateQrCode: GenerateQrCode,
) : InitTransaction {

    override suspend fun invoke(
        initTransactionTO: InitTransactionTO,
    ): Either<ValidationError, InitTransactionResponse> = either {
        // validate input
        val (nonce, type) = initTransactionTO.toDomain(
            verifierConfig.transactionDataHashAlgorithm,
            verifierConfig.clientMetaData.vpFormats,
        ).bind()

        // if response mode is direct post jwt then generate ephemeral key
        val responseMode = responseMode(initTransactionTO)
        val newEphemeralEcPublicKey = ephemeralEncryptionKeyPair(responseMode)

        val getWalletResponseMethod = getWalletResponseMethod(initTransactionTO).bind()
        val issuerChain = issuerChain(initTransactionTO).bind()

        // Initialize presentation
        val requestedPresentation = Presentation.Requested(
            id = generateTransactionId(),
            initiatedAt = clock.instant(),
            requestId = generateRequestId(),
            type = type,
            nonce = nonce,
            jarmEncryptionEphemeralKey = newEphemeralEcPublicKey,
            responseMode = responseMode,
            getWalletResponseMethod = getWalletResponseMethod,
            requestUriMethod = requestUriMethod(initTransactionTO),
            issuerChain = issuerChain,
        )

        // create the request, which may update the presentation
        val (updatedPresentation, request) = createRequest(requestedPresentation, jarMode(initTransactionTO))

        val response = when (initTransactionTO.output) {
            Output.Json -> request
            Output.QrCode -> {
                val scheme = authorizationRequestScheme(initTransactionTO).bind()
                val authorizationRequest = createAuthorizationRequestUri(scheme, request)
                InitTransactionResponse.QrCode(
                    generateQrCode(authorizationRequest.toString(), size = (250.pixels by 250.pixels)).getOrThrow(),
                )
            }
        }

        storePresentation(updatedPresentation)
        logTransactionInitialized(updatedPresentation, request)

        response
    }

    private fun ephemeralEncryptionKeyPair(responseModeOption: ResponseModeOption): EphemeralEncryptionKeyPairJWK? =
        when (responseModeOption) {
            ResponseModeOption.DirectPost -> null
            ResponseModeOption.DirectPostJwt ->
                when (val jarmOption = verifierConfig.clientMetaData.jarmOption) {
                    is JarmOption.Signed -> error("Misconfiguration")
                    is JarmOption.Encrypted -> jarmOption
                    is JarmOption.SignedAndEncrypted -> jarmOption.encrypted
                }.run { generateEphemeralEncryptionKeyPair(this).getOrThrow() }
        }

    /**
     * Creates a request and depending on the case updates also the [requestedPresentation]
     *
     * If the [requestJarOption] or the verifier has been configured to use request parameter then
     * presentation will be updated to [Presentation.RequestObjectRetrieved].
     *
     * Otherwise, [requestedPresentation] will remain as is
     */
    private fun createRequest(
        requestedPresentation: Presentation.Requested,
        requestJarOption: EmbedOption<RequestId>,
    ): Pair<Presentation, InitTransactionResponse.JwtSecuredAuthorizationRequestTO> =
        when (requestJarOption) {
            is EmbedOption.ByValue -> {
                val jwt = createJar(
                    verifierConfig,
                    clock,
                    requestedPresentation,
                    null,
                    EncryptionRequirement.NotRequired,
                ).getOrThrow()

                val requestObjectRetrieved = requestedPresentation.retrieveRequestObject(clock).getOrThrow()
                requestObjectRetrieved to InitTransactionResponse.JwtSecuredAuthorizationRequestTO.byValue(
                    requestedPresentation.id.value,
                    verifierConfig.verifierId.clientId,
                    jwt,
                )
            }

            is EmbedOption.ByReference -> {
                val requestUri = requestJarOption.buildUrl(requestedPresentation.requestId)
                val requestUriMethod = when (requestedPresentation.requestUriMethod) {
                    RequestUriMethod.Get -> RequestUriMethodTO.Get
                    RequestUriMethod.Post -> RequestUriMethodTO.Post
                }
                requestedPresentation to InitTransactionResponse.JwtSecuredAuthorizationRequestTO.byReference(
                    requestedPresentation.id.value,
                    verifierConfig.verifierId.clientId,
                    requestUri,
                    requestUriMethod,
                )
            }
        }

    private fun getWalletResponseMethod(initTransactionTO: InitTransactionTO): Either<ValidationError, GetWalletResponseMethod> = either {
        initTransactionTO.redirectUriTemplate
            ?.let { template ->
                with(createQueryWalletResponseRedirectUri) {
                    ensure(template.validTemplate()) { ValidationError.InvalidWalletResponseTemplate }
                }
                GetWalletResponseMethod.Redirect(template)
            } ?: GetWalletResponseMethod.Poll
    }

    /**
     * Gets the [ResponseModeOption] for the provided [InitTransactionTO].
     * If none has been provided, falls back to [VerifierConfig.responseModeOption].
     */
    private fun responseMode(initTransaction: InitTransactionTO): ResponseModeOption =
        when (initTransaction.responseMode) {
            ResponseModeTO.DirectPost -> ResponseModeOption.DirectPost
            ResponseModeTO.DirectPostJwt -> ResponseModeOption.DirectPostJwt
            null -> verifierConfig.responseModeOption
        }

    /**
     * Gets the JAR [EmbedOption] for the provided [InitTransactionTO].
     * If none has been provided, falls back to [VerifierConfig.requestJarOption].
     */
    private fun jarMode(initTransaction: InitTransactionTO): EmbedOption<RequestId> =
        when (initTransaction.jarMode) {
            EmbedModeTO.ByValue -> EmbedOption.ByValue
            EmbedModeTO.ByReference -> requestJarByReference
            null -> verifierConfig.requestJarOption
        }

    /**
     * Gets the JAR [RequestUriMethod] for the provided [InitTransactionTO].
     * If none has been provided, falls back to [VerifierConfig.requestUriMethod].
     */
    private fun requestUriMethod(initTransaction: InitTransactionTO): RequestUriMethod =
        when (initTransaction.requestUriMethod) {
            RequestUriMethodTO.Get -> RequestUriMethod.Get
            RequestUriMethodTO.Post -> RequestUriMethod.Post
            null -> verifierConfig.requestUriMethod
        }

    private suspend fun logTransactionInitialized(p: Presentation, request: InitTransactionResponse.JwtSecuredAuthorizationRequestTO) {
        val event = PresentationEvent.TransactionInitialized(p.id, p.initiatedAt, request)
        publishPresentationEvent(event)
    }

    private fun issuerChain(initTransaction: InitTransactionTO): Either<ValidationError, NonEmptyList<X509Certificate>?> =
        Either.catch {
            initTransaction.issuerChain?.let { parsePemEncodedX509CertificateChain(it).getOrThrow() }
        }.mapLeft { ValidationError.InvalidIssuerChain }

    /**
     * Gets a [String] containing the authorization Request Scheme for the provided [InitTransactionTO].
     * If none has been provided, falls back to [VerifierConfig.authorizationRequestScheme].
     */
    private fun authorizationRequestScheme(initTransaction: InitTransactionTO): Either<ValidationError, String> = either {
        val scheme = initTransaction.authorizationRequestScheme
            .takeUnless { it.isNullOrBlank() } ?: verifierConfig.authorizationRequestScheme
        ensure(!scheme.endsWith("://")) { ValidationError.InvalidAuthorizationRequestScheme }
        scheme
    }
}

internal fun InitTransactionTO.toDomain(
    transactionDataHashAlgorithm: HashAlgorithm,
    vpFormats: VpFormats,
): Either<ValidationError, Pair<Nonce, PresentationType>> = either {
    fun requiredIdTokenType() =
        idTokenType?.toDomain()?.let { listOf(it) } ?: emptyList()

    fun requiredPresentationQuery(): PresentationQuery =
        when {
            dcqlQuery != null -> {
                ensure(
                    dcqlQuery.formatsAre(
                        SdJwtVcSpec.MEDIA_SUBTYPE_VC_SD_JWT,
                        SdJwtVcSpec.MEDIA_SUBTYPE_DC_SD_JWT,
                        OpenId4VPSpec.FORMAT_MSO_MDOC,
                    ),
                ) {
                    ValidationError.UnsupportedFormat
                }

                PresentationQuery(dcqlQuery)
            }
            else -> raise(
                ValidationError.MultiplePresentationQueries,
            )
        }
    fun requiredNonce(): Nonce {
        ensure(!nonce.isNullOrBlank()) { ValidationError.MissingNonce }
        return Nonce(nonce)
    }

    fun optionalTransactionData(query: PresentationQuery): NonEmptyList<TransactionData>? {
        val credentialIds: List<String> by lazy {
            when (query) {
                is PresentationQuery -> query.query.credentials.map { it.id.value }
            }
        }

        val hashAlgorithms: JsonArray by lazy {
            buildJsonArray {
                add(transactionDataHashAlgorithm.ianaName)
            }
        }

        return transactionData?.map {
            TransactionData.validate(JsonObject(it + ("transaction_data_hashes_alg" to hashAlgorithms)), credentialIds)
                .flatMap { transactionData ->
                    Either.catch {
                        when (transactionData.type) {
                            QesAuthorization.TYPE -> QesAuthorization.serializer()
                            QCertCreationAcceptance.TYPE -> QCertCreationAcceptance.serializer()
                            else -> null
                        }?.let { deserializer -> it.decodeAs(deserializer) }
                        transactionData
                    }
                }
                .getOrElse { raise(ValidationError.InvalidTransactionData) }
        }?.toNonEmptyListOrNull()
    }

    val presentationType = when (type) {
        PresentationTypeTO.IdTokenRequest ->
            PresentationType.IdTokenRequest(requiredIdTokenType())
        PresentationTypeTO.VpTokenRequest -> {
            val query = requiredPresentationQuery()
            PresentationType.VpTokenRequest(query, optionalTransactionData(query))
        }

        PresentationTypeTO.IdAndVpTokenRequest -> {
            val idTokenTypes = requiredIdTokenType()
            val query = requiredPresentationQuery()
            PresentationType.IdAndVpToken(idTokenTypes, query, optionalTransactionData(query))
        }
    }

    val nonce = requiredNonce()

    nonce to presentationType
}

private fun DCQL.formatsAre(vararg supportedFormats: String): Boolean = credentials.all { it.format.value in supportedFormats }

private fun IdTokenTypeTO.toDomain(): IdTokenType = when (this) {
    IdTokenTypeTO.SubjectSigned -> IdTokenType.SubjectSigned
    IdTokenTypeTO.AttesterSigned -> IdTokenType.AttesterSigned
}

private fun VpFormat.SdJwtVc.supports(sdJwtAlgorithms: List<JWSAlgorithm>, kbJwtAlgorithms: List<JWSAlgorithm>): Boolean =
    this.sdJwtAlgorithms.intersect(sdJwtAlgorithms.toSet()).isNotEmpty() &&
        this.kbJwtAlgorithms.intersect(kbJwtAlgorithms.toSet()).isNotEmpty()

private fun VpFormat.MsoMdoc.supports(algorithms: List<JWSAlgorithm>): Boolean =
    this.algorithms.intersect(algorithms.toSet()).isNotEmpty()

private fun createAuthorizationRequestUri(
    scheme: String,
    authorizationRequest: InitTransactionResponse.JwtSecuredAuthorizationRequestTO,
): URI =
    Uri.Builder().apply {
        scheme(scheme)
        authority("")
        appendQueryParameter(OpenId4VPSpec.CLIENT_ID, authorizationRequest.clientId)
        authorizationRequest.request?.let { appendQueryParameter(OpenId4VPSpec.REQUEST, it) }
        authorizationRequest.requestUri?.let { appendQueryParameter(OpenId4VPSpec.REQUEST_URI, it) }
        authorizationRequest.requestUriMethod?.let {
            val requestUriMethod = when (it) {
                RequestUriMethodTO.Get -> OpenId4VPSpec.REQUEST_URI_METHOD_GET
                RequestUriMethodTO.Post -> OpenId4VPSpec.REQUEST_URI_METHOD_GET
            }
            appendQueryParameter(OpenId4VPSpec.REQUEST_URI_METHOD, requestUriMethod)
        }
    }.build().toURI()

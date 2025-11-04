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
import arrow.core.raise.ensureNotNull
import com.eygraber.uri.Uri
import com.eygraber.uri.toURI
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
    @SerialName(OpenId4VPSpec.RESPONSE_MODE_DIRECT_POST)
    DirectPost,

    @SerialName(OpenId4VPSpec.RESPONSE_MODE_DIRECT_POST_JWT)
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
    @SerialName(OpenId4VPSpec.DCQL_QUERY) val dcqlQuery: DCQL? = null,
    @SerialName(OpenId4VPSpec.NONCE) val nonce: String? = null,
    @SerialName(RFC6749.RESPONSE_MODE) val responseMode: ResponseModeTO? = null,
    @SerialName("jar_mode") val jarMode: EmbedModeTO? = null,
    @SerialName(OpenId4VPSpec.REQUEST_URI_METHOD) val requestUriMethod: RequestUriMethodTO? = null,
    @SerialName("wallet_response_redirect_uri_template") val redirectUriTemplate: String? = null,
    @SerialName(OpenId4VPSpec.TRANSACTION_DATA) val transactionData: List<JsonObject>? = null,
    @SerialName("issuer_chain") val issuerChain: String? = null,
    @SerialName("authorization_request_scheme") val authorizationRequestScheme: String? = null,
    @SerialName("authorization_request_uri") val authorizationRequestUri: String? = null,
    @Transient val output: Output = Output.Json,
)

/**
 * Possible validation errors of caller's input
 */
enum class ValidationError {
    MissingPresentationQuery,
    MissingNonce,
    InvalidWalletResponseTemplate,
    InvalidTransactionData,
    UnsupportedFormat,
    InvalidIssuerChain,
    ContainsBothAuthorizationRequestUriAndAuthorizationRequestScheme,
    InvalidAuthorizationRequestUri,
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
    data class QrCode(
        val qrCode: ByteArray,
        val transactionId: String,
        val authorizationRequestUri: String,
    ) : InitTransactionResponse

    /**
     * The return value of successfully [initializing][InitTransaction] a [Presentation] as a JSON
     *
     */
    @Serializable
    data class JwtSecuredAuthorizationRequestTO(
        @Required @SerialName("transaction_id") val transactionId: String,
        @Required @SerialName(RFC6749.CLIENT_ID) val clientId: ClientId,
        @SerialName(RFC9101.REQUEST) val request: String?,
        @SerialName(RFC9101.REQUEST_URI) val requestUri: String?,
        @SerialName(OpenId4VPSpec.REQUEST_URI_METHOD) val requestUriMethod: RequestUriMethodTO?,
        @SerialName("authorization_request_uri") val authorizationRequestUri: String,
    ) : InitTransactionResponse {
        companion object {

            fun byValue(
                transactionId: String,
                clientId: ClientId,
                request: String,
                authorizationRequestUri: URI,
            ): JwtSecuredAuthorizationRequestTO = JwtSecuredAuthorizationRequestTO(
                transactionId,
                clientId,
                request,
                null,
                null,
                authorizationRequestUri.toString(),
            )

            fun byReference(
                transactionId: String,
                clientId: ClientId,
                requestUri: URL,
                requestUriMethod: RequestUriMethodTO,
                authorizationRequestUri: URI,
            ): JwtSecuredAuthorizationRequestTO = JwtSecuredAuthorizationRequestTO(
                transactionId,
                clientId,
                null,
                requestUri.toExternalForm(),
                requestUriMethod,
                authorizationRequestUri.toString(),
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
            verifierConfig.clientMetaData.vpFormatsSupported,
        ).bind()

        // if response mode is direct post jwt then generate ephemeral key
        val responseMode = responseMode(initTransactionTO)

        val getWalletResponseMethod = getWalletResponseMethod(initTransactionTO).bind()
        val issuerChain = issuerChain(initTransactionTO).bind()

        // Initialize presentation
        val requestedPresentation = Presentation.Requested(
            id = generateTransactionId(),
            initiatedAt = clock.now(),
            query = type.query,
            transactionData = type.transactionData,
            requestId = generateRequestId(),
            nonce = nonce,
            responseMode = responseMode,
            getWalletResponseMethod = getWalletResponseMethod,
            requestUriMethod = requestUriMethod(initTransactionTO),
            issuerChain = issuerChain,
        )

        // create the request, which may update the presentation
        val (updatedPresentation, request) = createRequest(
            requestedPresentation,
            jarMode(initTransactionTO),
            authorizationRequestUri(initTransactionTO).bind(),
        )

        val response = when (initTransactionTO.output) {
            Output.Json -> request
            Output.QrCode -> {
                InitTransactionResponse.QrCode(
                    generateQrCode(request.authorizationRequestUri, size = (250.pixels by 250.pixels)).getOrThrow(),
                    request.transactionId,
                    request.authorizationRequestUri,
                )
            }
        }

        storePresentation(updatedPresentation)
        logTransactionInitialized(updatedPresentation, request)

        response
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
        authorizationRequestUri: Uri,
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
                    createAuthorizationRequestUri(
                        authorizationRequestUri,
                        verifierConfig.verifierId.clientId,
                        request = jwt,
                    ),
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
                    createAuthorizationRequestUri(
                        authorizationRequestUri,
                        verifierConfig.verifierId.clientId,
                        requestUri = requestUri,
                        requestUriMethod = requestUriMethod,
                    ),
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
     * Gets the [ResponseMode] for the provided [InitTransactionTO].
     */
    private fun responseMode(initTransaction: InitTransactionTO): ResponseMode {
        val responseModeOption = when (initTransaction.responseMode) {
            ResponseModeTO.DirectPost -> ResponseModeOption.DirectPost
            ResponseModeTO.DirectPostJwt -> ResponseModeOption.DirectPostJwt
            null -> verifierConfig.responseModeOption
        }

        return when (responseModeOption) {
            ResponseModeOption.DirectPost -> ResponseMode.DirectPost
            ResponseModeOption.DirectPostJwt -> {
                val responseEncryptionKey = generateEphemeralEncryptionKeyPair().getOrThrow()
                ResponseMode.DirectPostJwt(responseEncryptionKey)
            }
        }
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
     * Gets a [Uri] containing the authorization Request Uri for the provided [InitTransactionTO].
     * If none has been provided, falls back to [VerifierConfig.authorizationRequestUri].
     *
     * This method considers both [InitTransactionTO.authorizationRequestUri] and [InitTransactionTO.authorizationRequestScheme].
     */
    private fun authorizationRequestUri(initTransaction: InitTransactionTO): Either<ValidationError, Uri> =
        either {
            when {
                null != initTransaction.authorizationRequestUri && null != initTransaction.authorizationRequestScheme ->
                    raise(ValidationError.ContainsBothAuthorizationRequestUriAndAuthorizationRequestScheme)

                null != initTransaction.authorizationRequestUri -> {
                    ensure(initTransaction.authorizationRequestUri.isNotBlank()) {
                        ValidationError.InvalidAuthorizationRequestUri
                    }
                    runCatching { Uri.parse(initTransaction.authorizationRequestUri) }.getOrElse {
                        raise(ValidationError.InvalidAuthorizationRequestUri)
                    }
                }

                null != initTransaction.authorizationRequestScheme -> {
                    ensure(initTransaction.authorizationRequestScheme.isNotBlank()) {
                        ValidationError.InvalidAuthorizationRequestScheme
                    }
                    ensure(!initTransaction.authorizationRequestScheme.endsWith("://")) {
                        ValidationError.InvalidAuthorizationRequestScheme
                    }
                    runCatching { Uri.parse("${initTransaction.authorizationRequestScheme}://") }.getOrElse {
                        raise(ValidationError.InvalidAuthorizationRequestScheme)
                    }
                }

                else -> verifierConfig.authorizationRequestUri
            }
        }
}

internal fun InitTransactionTO.toDomain(
    transactionDataHashAlgorithm: HashAlgorithm,
    vpFormatsSupported: VpFormatsSupported,
): Either<ValidationError, Pair<Nonce, VpTokenRequest>> = either {
    fun requiredQuery(): DCQL {
        ensureNotNull(dcqlQuery) { ValidationError.MissingPresentationQuery }
        ensure(
            dcqlQuery.credentials.value.all {
                val format = it.format
                vpFormatsSupported.supports(format)
            },
        ) { ValidationError.UnsupportedFormat }

        return dcqlQuery
    }

    fun requiredNonce(): Nonce {
        ensure(!nonce.isNullOrBlank()) { ValidationError.MissingNonce }
        return Nonce(nonce)
    }

    fun optionalTransactionData(query: DCQL): NonEmptyList<TransactionData>? {
        val credentialIds: List<String> by lazy {
            query.credentials.ids.map { it.value }
        }

        val hashAlgorithms: JsonArray by lazy {
            buildJsonArray {
                add(transactionDataHashAlgorithm.ianaName)
            }
        }

        return transactionData?.map {
            TransactionData.validate(JsonObject(it + (OpenId4VPSpec.TRANSACTION_DATA_HASH_ALGORITHMS to hashAlgorithms)), credentialIds)
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

    val query = requiredQuery()
    val presentationType = VpTokenRequest(query, optionalTransactionData(query))
    val nonce = requiredNonce()

    nonce to presentationType
}

private fun createAuthorizationRequestUri(
    authorizationRequestUri: Uri,
    clientId: ClientId,
    request: Jwt? = null,
    requestUri: URL? = null,
    requestUriMethod: RequestUriMethodTO? = null,
): URI =
    authorizationRequestUri.buildUpon().apply {
        appendQueryParameter(RFC6749.CLIENT_ID, clientId)
        request?.let { appendQueryParameter(RFC9101.REQUEST, it) }
        requestUri?.let { appendQueryParameter(RFC9101.REQUEST_URI, it.toExternalForm()) }
        requestUriMethod?.let {
            val requestUriMethod = when (it) {
                RequestUriMethodTO.Get -> OpenId4VPSpec.REQUEST_URI_METHOD_GET
                RequestUriMethodTO.Post -> OpenId4VPSpec.REQUEST_URI_METHOD_GET
            }
            appendQueryParameter(OpenId4VPSpec.REQUEST_URI_METHOD, requestUriMethod)
        }
    }.build().toURI()

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

import arrow.core.Either
import arrow.core.NonEmptyList
import arrow.core.raise.either
import arrow.core.raise.ensure
import arrow.core.toNonEmptyListOrNull
import com.nimbusds.jose.JWSAlgorithm
import eu.europa.ec.eudi.prex.PresentationDefinition
import eu.europa.ec.eudi.sdjwt.SdJwtVcSpec
import eu.europa.ec.eudi.verifier.endpoint.adapter.out.json.decodeAs
import eu.europa.ec.eudi.verifier.endpoint.adapter.out.metadata.MsoMdocFormatTO
import eu.europa.ec.eudi.verifier.endpoint.adapter.out.metadata.SdJwtVcFormatTO
import eu.europa.ec.eudi.verifier.endpoint.domain.*
import eu.europa.ec.eudi.verifier.endpoint.port.out.cfg.CreateQueryWalletResponseRedirectUri
import eu.europa.ec.eudi.verifier.endpoint.port.out.cfg.GenerateRequestId
import eu.europa.ec.eudi.verifier.endpoint.port.out.cfg.GenerateTransactionId
import eu.europa.ec.eudi.verifier.endpoint.port.out.jose.GenerateEphemeralEncryptionKeyPair
import eu.europa.ec.eudi.verifier.endpoint.port.out.jose.SignRequestObject
import eu.europa.ec.eudi.verifier.endpoint.port.out.persistence.PresentationEvent
import eu.europa.ec.eudi.verifier.endpoint.port.out.persistence.PublishPresentationEvent
import eu.europa.ec.eudi.verifier.endpoint.port.out.persistence.StorePresentation
import kotlinx.serialization.ExperimentalSerializationApi
import kotlinx.serialization.Required
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.add
import kotlinx.serialization.json.buildJsonArray
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
 * Specifies the response_mode for a request
 */
@Serializable
enum class ResponseModeTO {
    @SerialName("direct_post")
    DirectPost,

    @SerialName("direct_post.jwt")
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
    @SerialName("presentation_definition") val presentationDefinition: PresentationDefinition? = null,
    @SerialName("dcql_query") val dcqlQuery: DCQL? = null,
    @SerialName("nonce") val nonce: String? = null,
    @SerialName("response_mode") val responseMode: ResponseModeTO? = null,
    @SerialName("jar_mode") val jarMode: EmbedModeTO? = null,
    @SerialName("presentation_definition_mode") val presentationDefinitionMode: EmbedModeTO? = null,
    @SerialName("wallet_response_redirect_uri_template") val redirectUriTemplate: String? = null,
    @SerialName("transaction_data") val transactionData: List<JsonObject>? = null,
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
}

/**
 * The return value of successfully [initializing][InitTransaction] a [Presentation]
 *
 */
@Serializable
data class JwtSecuredAuthorizationRequestTO(
    @Required @SerialName("transaction_id") val transactionId: String,
    @Required @SerialName("client_id") val clientId: ClientId,
    @SerialName("request") val request: String? = null,
    @SerialName("request_uri") val requestUri: String?,
)

/**
 * This is a use case that initializes the [Presentation] process.
 *
 * The caller may define via [InitTransactionTO] what kind of transaction wants to initiate
 * This is represented by [PresentationTypeTO].
 *
 * Use case will initialize a [Presentation] process
 */
fun interface InitTransaction {

    suspend operator fun invoke(initTransactionTO: InitTransactionTO): Either<ValidationError, JwtSecuredAuthorizationRequestTO>
}

/**
 * The default implementation of the use case
 */
class InitTransactionLive(
    private val generateTransactionId: GenerateTransactionId,
    private val generateRequestId: GenerateRequestId,
    private val storePresentation: StorePresentation,
    private val signRequestObject: SignRequestObject,
    private val verifierConfig: VerifierConfig,
    private val clock: Clock,
    private val generateEphemeralEncryptionKeyPair: GenerateEphemeralEncryptionKeyPair,
    private val requestJarByReference: EmbedOption.ByReference<RequestId>,
    private val presentationDefinitionByReference: EmbedOption.ByReference<RequestId>,
    private val createQueryWalletResponseRedirectUri: CreateQueryWalletResponseRedirectUri,
    private val publishPresentationEvent: PublishPresentationEvent,

) : InitTransaction {

    override suspend fun invoke(initTransactionTO: InitTransactionTO): Either<ValidationError, JwtSecuredAuthorizationRequestTO> = either {
        // validate input
        val (nonce, type) = initTransactionTO.toDomain(
            verifierConfig.transactionDataHashAlgorithm,
            verifierConfig.clientMetaData.vpFormats,
        ).bind()

        // if response mode is direct post jwt then generate ephemeral key
        val responseMode = responseMode(initTransactionTO)
        val newEphemeralEcPublicKey = ephemeralEncryptionKeyPair(responseMode)
        val getWalletResponseMethod = getWalletResponseMethod(initTransactionTO).bind()

        // Initialize presentation
        val requestedPresentation = Presentation.Requested(
            id = generateTransactionId(),
            initiatedAt = clock.instant(),
            requestId = generateRequestId(),
            type = type,
            nonce = nonce,
            ephemeralEcPrivateKey = newEphemeralEcPublicKey,
            responseMode = responseMode,
            presentationDefinitionMode = presentationDefinitionMode(initTransactionTO),
            getWalletResponseMethod = getWalletResponseMethod,
        )
        // create request, which may update presentation
        val (updatedPresentation, request) = createRequest(requestedPresentation, jarMode(initTransactionTO))

        storePresentation(updatedPresentation)
        logTransactionInitialized(updatedPresentation, request)
        request
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
    ): Pair<Presentation, JwtSecuredAuthorizationRequestTO> =
        when (requestJarOption) {
            is EmbedOption.ByValue -> {
                val jwt = signRequestObject(verifierConfig, clock, requestedPresentation).getOrThrow()
                val requestObjectRetrieved = requestedPresentation.retrieveRequestObject(clock).getOrThrow()
                requestObjectRetrieved to JwtSecuredAuthorizationRequestTO(
                    requestedPresentation.id.value,
                    verifierConfig.verifierId.clientId,
                    jwt,
                    null,
                )
            }

            is EmbedOption.ByReference -> {
                val requestUri = requestJarOption.buildUrl(requestedPresentation.requestId).toExternalForm()
                requestedPresentation to JwtSecuredAuthorizationRequestTO(
                    requestedPresentation.id.value,
                    verifierConfig.verifierId.clientId,
                    null,
                    requestUri,
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
     * Gets the PresentationDefinition [EmbedOption] for the provided [InitTransactionTO].
     * If none has been provided, falls back to [VerifierConfig.presentationDefinitionEmbedOption].
     */
    private fun presentationDefinitionMode(initTransaction: InitTransactionTO): EmbedOption<RequestId> =
        when (initTransaction.presentationDefinitionMode) {
            EmbedModeTO.ByValue -> EmbedOption.ByValue
            EmbedModeTO.ByReference -> presentationDefinitionByReference
            null -> verifierConfig.presentationDefinitionEmbedOption
        }

    private suspend fun logTransactionInitialized(p: Presentation, request: JwtSecuredAuthorizationRequestTO) {
        val event = PresentationEvent.TransactionInitialized(p.id, p.initiatedAt, request)
        publishPresentationEvent(event)
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
            presentationDefinition != null && dcqlQuery == null -> {
                ensure(vpFormats.supportsFormats(presentationDefinition)) { ValidationError.UnsupportedFormat }
                PresentationQuery.ByPresentationDefinition(presentationDefinition)
            }
            presentationDefinition == null && dcqlQuery != null -> {
                ensure(
                    dcqlQuery.formatsAre(
                        SdJwtVcSpec.MEDIA_SUBTYPE_VC_SD_JWT,
                        SdJwtVcSpec.MEDIA_SUBTYPE_DC_SD_JWT,
                        OpenId4VPSpec.FORMAT_MSO_MDOC,
                    ),
                ) {
                    ValidationError.UnsupportedFormat
                }

                PresentationQuery.ByDigitalCredentialsQueryLanguage(dcqlQuery)
            }
            presentationDefinition == null && dcqlQuery == null -> raise(ValidationError.MissingPresentationQuery)
            else -> raise(ValidationError.MultiplePresentationQueries)
        }

    fun requiredNonce(): Nonce {
        ensure(!nonce.isNullOrBlank()) { ValidationError.MissingNonce }
        return Nonce(nonce)
    }

    fun optionalTransactionData(query: PresentationQuery): NonEmptyList<TransactionData>? {
        val credentialIds: List<String> by lazy {
            when (query) {
                is PresentationQuery.ByPresentationDefinition -> query.presentationDefinition.inputDescriptors.map { it.id.value }
                is PresentationQuery.ByDigitalCredentialsQueryLanguage -> query.query.credentials.map { it.id.value }
            }
        }

        val hashAlgorithms: JsonArray by lazy {
            buildJsonArray {
                add(transactionDataHashAlgorithm.ianaName)
            }
        }

        return transactionData?.map {
            TransactionData.validate(JsonObject(it + ("transaction_data_hashes_alg" to hashAlgorithms)), credentialIds)
                .applyCatching {
                    when (type) {
                        QesAuthorization.TYPE -> QesAuthorization.serializer()
                        QCertCreationAcceptance.TYPE -> QCertCreationAcceptance.serializer()
                        else -> null
                    }?.let { deserializer -> decodeAs(deserializer) }
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

private fun VpFormats.supportsFormats(presentationDefinition: PresentationDefinition): Boolean =
    presentationDefinition.inputDescriptors.all { inputDescriptor ->
        val format = inputDescriptor.format ?: presentationDefinition.format
        format?.let {
            it.jsonObject().all { (identifier, serializedProperties) ->
                when (identifier) {
                    SdJwtVcSpec.MEDIA_SUBTYPE_VC_SD_JWT, SdJwtVcSpec.MEDIA_SUBTYPE_DC_SD_JWT ->
                        serializedProperties.decodeAs<SdJwtVcFormatTO>()
                            .map { properties -> sdJwtVc.supports(properties.sdJwtAlgorithms, properties.kbJwtAlgorithms) }
                            .getOrElse { false }

                    OpenId4VPSpec.FORMAT_MSO_MDOC ->
                        serializedProperties.decodeAs<MsoMdocFormatTO>()
                            .map { properties -> msoMdoc.supports(properties.algorithms) }
                            .getOrElse { false }

                    else -> false
                }
            }
        } ?: true
    }

private fun DCQL.formatsAre(vararg supportedFormats: String): Boolean = credentials.all { it.format.value in supportedFormats }

private fun IdTokenTypeTO.toDomain(): IdTokenType = when (this) {
    IdTokenTypeTO.SubjectSigned -> IdTokenType.SubjectSigned
    IdTokenTypeTO.AttesterSigned -> IdTokenType.AttesterSigned
}

private inline fun <reified T> Result<T>.applyCatching(block: T.() -> Unit): Result<T> =
    if (isFailure) {
        this
    } else {
        runCatching {
            val value = getOrThrow()
            value.block()
            value
        }
    }

private fun VpFormat.SdJwtVc.supports(sdJwtAlgorithms: List<JWSAlgorithm>, kbJwtAlgorithms: List<JWSAlgorithm>): Boolean =
    this.sdJwtAlgorithms.toSet().intersect(sdJwtAlgorithms.toSet()).isNotEmpty() &&
        this.kbJwtAlgorithms.toSet().intersect(kbJwtAlgorithms.toSet()).isNotEmpty()

private fun VpFormat.MsoMdoc.supports(algorithms: List<JWSAlgorithm>): Boolean =
    this.algorithms.toSet().intersect(algorithms.toSet()).isNotEmpty()

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
import arrow.core.raise.either
import arrow.core.raise.ensure
import arrow.core.toNonEmptyListOrNull
import eu.europa.ec.eudi.prex.PresentationDefinition
import eu.europa.ec.eudi.sdjwt.SdJwtVcSpec
import eu.europa.ec.eudi.verifier.endpoint.adapter.out.json.decodeAs
import eu.europa.ec.eudi.verifier.endpoint.adapter.out.json.jsonSupport
import eu.europa.ec.eudi.verifier.endpoint.adapter.out.metadata.MsoMdocFormatTO
import eu.europa.ec.eudi.verifier.endpoint.adapter.out.metadata.SdJwtVcFormatTO
import eu.europa.ec.eudi.verifier.endpoint.adapter.out.metadata.supports
import eu.europa.ec.eudi.verifier.endpoint.domain.*
import eu.europa.ec.eudi.verifier.endpoint.port.out.jose.SignRequestObject
import eu.europa.ec.eudi.verifier.endpoint.port.out.persistence.LoadPresentationByRequestId
import eu.europa.ec.eudi.verifier.endpoint.port.out.persistence.PresentationEvent
import eu.europa.ec.eudi.verifier.endpoint.port.out.persistence.PublishPresentationEvent
import eu.europa.ec.eudi.verifier.endpoint.port.out.persistence.StorePresentation
import kotlinx.serialization.Required
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.JsonObject
import java.time.Clock

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
    data object InvalidState : RetrieveRequestObjectError
    data object InvalidRequestUriMethod : RetrieveRequestObjectError
    data class UnparsableWalletMetadata(val cause: Throwable) : RetrieveRequestObjectError
    data class UnsupportedWalletMetadata(val message: String, val cause: Throwable? = null) : RetrieveRequestObjectError
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
    private val signRequestObject: SignRequestObject,
    private val verifierConfig: VerifierConfig,
    private val clock: Clock,
    private val publishPresentationEvent: PublishPresentationEvent,
) : RetrieveRequestObject {

    override suspend operator fun invoke(
        requestId: RequestId,
        method: RetrieveRequestObjectMethod,
    ): Either<RetrieveRequestObjectError, Jwt> =
        either {
            when (val presentation = loadPresentationByRequestId(requestId)) {
                null -> raise(RetrieveRequestObjectError.PresentationNotFound)
                is Presentation.Requested -> found(presentation, method).bind()
                else -> raise(invalidState(presentation))
            }
        }

    private suspend fun found(
        presentation: Presentation.Requested,
        method: RetrieveRequestObjectMethod,
    ): Either<RetrieveRequestObjectError, Jwt> =
        either {
            suspend fun requestObjectOf(): Pair<Presentation.RequestObjectRetrieved, Jwt> {
                val jwt = signRequestObject(verifierConfig, clock, presentation, method.walletNonceOrNull).getOrThrow()
                val updatedPresentation = presentation.retrieveRequestObject(clock).getOrThrow()
                storePresentation(updatedPresentation)
                return updatedPresentation to jwt
            }

            suspend fun log(p: Presentation.RequestObjectRetrieved, jwt: Jwt) {
                val event = PresentationEvent.RequestObjectRetrieved(p.id, p.requestObjectRetrievedAt, jwt)
                publishPresentationEvent(event)
            }

            ensure(method is RetrieveRequestObjectMethod.Get || RequestUriMethod.Post == presentation.requestUriMethod) {
                RetrieveRequestObjectError.InvalidRequestUriMethod
            }

            val walletMetadata = runCatching {
                method.walletMetadataOrNull?.let {
                    jsonSupport.decodeFromString<WalletMetadataTO>(it)
                }
            }.getOrElse { raise(RetrieveRequestObjectError.UnparsableWalletMetadata(it)) }
            walletMetadata?.validate(presentation)?.bind()

            val (updatePresentation, jwt) = requestObjectOf()
            log(updatePresentation, jwt)
            jwt
        }

    private fun WalletMetadataTO.validate(
        presentation: Presentation.Requested,
    ): Either<RetrieveRequestObjectError.UnsupportedWalletMetadata, Unit> =
        either {
            val requiresPresentationDefinitionByReference =
                presentation.presentationDefinitionMode is EmbedOption.ByReference && null != presentation.type.presentationDefinitionOrNull
            if (requiresPresentationDefinitionByReference) {
                val supportsPresentationDefinitionByReference = presentationDefinitionUriSupported ?: true
                ensure(supportsPresentationDefinitionByReference) {
                    RetrieveRequestObjectError.UnsupportedWalletMetadata(
                        "Wallet does not support fetching PresentationDefinition by reference",
                    )
                }
            }

            val walletSupportedVpFormats = vpFormatsSupported.toVpFormats().getOrElse {
                raise(RetrieveRequestObjectError.UnsupportedWalletMetadata("Wallet metadata contains malformed VpFormats", it))
            }.groupBy { it::class }
            val verifierSupportedVpFormats = verifierConfig.clientMetaData.vpFormats
            val queryRequiredVpFormats = when (val query = presentation.type.presentationQueryOrNull) {
                is PresentationQuery.ByPresentationDefinition -> query.presentationDefinition.vpFormats(verifierSupportedVpFormats)
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

            val clientIdScheme = verifierConfig.verifierId.clientIdScheme
            val supportedClientIdSchemes = clientIdSchemesSupported ?: listOf(OpenId4VPSpec.CLIENT_ID_SCHEME_PRE_REGISTERED)
            ensure(clientIdScheme in supportedClientIdSchemes) {
                RetrieveRequestObjectError.UnsupportedWalletMetadata("Wallet does not support Client Id Scheme '$clientIdScheme'")
            }

            // TODO Encryption parameters validation

            val jarSigningAlgorithm = verifierConfig.verifierId.jarSigning.algorithm.name
            ensure(jarSigningAlgorithm in signingAlgorithmsSupported.orEmpty()) {
                RetrieveRequestObjectError.UnsupportedWalletMetadata(
                    "Wallet does not support JAR Signing Algorithms '$jarSigningAlgorithm'",
                )
            }

            val responseType = presentation.type.responseType
            if (null != responseTypesSupported) {
                ensure(responseType in responseTypesSupported) {
                    RetrieveRequestObjectError.UnsupportedWalletMetadata("Wallet does not support Response Type '$responseType'")
                }
            }

            val responseMode = presentation.responseMode.name()
            val supportedResponseModes = responseModesSupported
                ?: listOf(RFC8414.RESPONSE_MODE_QUERY, RFC8414.RESPONSE_MODE_FRAGMENT)
            ensure(responseMode in supportedResponseModes) {
                RetrieveRequestObjectError.UnsupportedWalletMetadata("Wallet does not support Response Mode '$responseMode'")
            }
        }

    private suspend fun invalidState(presentation: Presentation): RetrieveRequestObjectError.InvalidState {
        suspend fun log() {
            val cause = "Presentation should be in Requested state but is in ${presentation.javaClass.name}"
            val event = PresentationEvent.FailedToRetrieveRequestObject(presentation.id, clock.instant(), cause)
            publishPresentationEvent(event)
        }
        log()
        return RetrieveRequestObjectError.InvalidState
    }
}

/**
 * Transfer object for Wallet metadata.
 */
@Serializable
private data class WalletMetadataTO(
    @SerialName(OpenId4VPSpec.PRESENTATION_DEFINITION_URI_SUPPORTED)
    val presentationDefinitionUriSupported: Boolean,

    @Required
    @SerialName(OpenId4VPSpec.VP_FORMATS_SUPPORTED)
    val vpFormatsSupported: JsonObject,

    @SerialName(OpenId4VPSpec.CLIENT_ID_SCHEMES_SUPPORTED)
    val clientIdSchemesSupported: List<String>?,

    @SerialName(RFC8414.JWKS)
    val jwks: JsonObject?,

    @SerialName(RFC8414.JWKS_URI)
    val jwksUri: String?,

    @SerialName(JarmSpec.AUTHORIZATION_ENCRYPTION_ALGORITHMS_SUPPORTED)
    val encryptionAlgorithmsSupported: List<String>?,

    @SerialName(JarmSpec.AUTHORIZATION_ENCRYPTION_METHODS_SUPPORTED)
    val encryptionMethodsSupported: List<String>?,

    @SerialName(RFC9101.REQUEST_OBJECT_SIGNING_ALGORITHMS_SUPPORTED)
    val signingAlgorithmsSupported: List<String>?,

    @SerialName(RFC8414.RESPONSE_TYPES_SUPPORTED)
    val responseTypesSupported: List<String>?,

    @SerialName(RFC8414.RESPONSE_MODES_SUPPORTED)
    val responseModesSupported: List<String>?,
)

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
        ResponseModeOption.DirectPost -> "direct_post"
        ResponseModeOption.DirectPostJwt -> "direct_post.jwt"
    }

private fun JsonObject.toVpFormats(): Result<List<VpFormat>> =
    runCatching {
        mapNotNull { (identifier, serializedProperties) ->
            when (identifier) {
                SdJwtVcSpec.MEDIA_SUBTYPE_VC_SD_JWT, SdJwtVcSpec.MEDIA_SUBTYPE_DC_SD_JWT ->
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

private fun PresentationDefinition.vpFormats(supported: VpFormats): List<VpFormat> =
    inputDescriptors.flatMap { inputDescriptor ->
        val format = inputDescriptor.format ?: format
        format?.jsonObject()?.toVpFormats()?.getOrThrow() ?: listOf(supported.sdJwtVc, supported.msoMdoc)
    }.distinct()

private fun DCQL.vpFormats(supported: VpFormats): List<VpFormat> =
    credentials.mapNotNull {
        when (it.format.value) {
            SdJwtVcSpec.MEDIA_SUBTYPE_VC_SD_JWT, SdJwtVcSpec.MEDIA_SUBTYPE_DC_SD_JWT -> supported.sdJwtVc
            OpenId4VPSpec.FORMAT_MSO_MDOC -> supported.msoMdoc
            else -> null
        }
    }.distinct()

private fun VpFormat.supports(other: VpFormat): Boolean =
    when (this) {
        is VpFormat.SdJwtVc ->
            other is VpFormat.SdJwtVc && supports(sdJwtAlgorithms = other.sdJwtAlgorithms, kbJwtAlgorithms = other.kbJwtAlgorithms)

        is VpFormat.MsoMdoc ->
            other is VpFormat.MsoMdoc && supports(other.algorithms)
    }

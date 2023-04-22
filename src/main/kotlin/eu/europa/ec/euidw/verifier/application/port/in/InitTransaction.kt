package eu.europa.ec.euidw.verifier.application.port.`in`

import com.fasterxml.jackson.annotation.JsonInclude
import com.fasterxml.jackson.annotation.JsonInclude.Include
import com.fasterxml.jackson.annotation.JsonProperty
import com.fasterxml.jackson.annotation.JsonValue
import com.fasterxml.jackson.databind.ObjectMapper
import eu.europa.ec.euidw.prex.PresentationExchange
import eu.europa.ec.euidw.verifier.application.port.out.cfg.GeneratePresentationId
import eu.europa.ec.euidw.verifier.application.port.out.cfg.GenerateRequestId
import eu.europa.ec.euidw.verifier.application.port.out.jose.SignRequestObject
import eu.europa.ec.euidw.verifier.application.port.out.persistence.StorePresentation
import eu.europa.ec.euidw.verifier.domain.*
import kotlinx.serialization.Serializable
import java.net.URLEncoder
import java.time.Clock

/**
 * Represent the kind of [Presentation] process
 * a caller wants to initiate
 * It could be either a request (to the wallet) to present
 * a id_token, a vp_token or both
 */
enum class PresentationTypeTO(@get:JsonValue val jsonValue: String) {
    IdTokenRequest("id_token"),
    VpTokenRequest("vp_token"),
    IdAndVpTokenRequest("vp_token id_token")
}

/**
 * Specifies what kind of id_token to request
 */
enum class IdTokenTypeTO(@get:JsonValue val jsonValue: String) {
    SubjectSigned("subject_signed_id_token"),
    AttesterSigned("attester_signed_id_token")
}


@Serializable
data class InitTransactionTO(
    @JsonProperty("type") val type: PresentationTypeTO = PresentationTypeTO.IdAndVpTokenRequest,
    @JsonProperty("id_token_type") val idTokenType: IdTokenTypeTO? = null,
    @JsonProperty("presentation_definition") val presentationDefinition: Any?
)

/**
 * Possible validation errors of caller's input
 */
enum class ValidationError {
    MissingPresentationDefinition,
    InvalidPresentationDefinition
}

/**
 * Carrier of [ValidationError]
 */
data class ValidationException(val error: ValidationError) : RuntimeException()

/**
 * The return value of successfully [initializing][InitTransaction] a [Presentation]
 *
 */
@JsonInclude(Include.NON_NULL)
data class JwtSecuredAuthorizationRequestTO(
    @JsonProperty("client_id") val clientId: String,
    @JsonProperty("request") val request: String? = null,
    @JsonProperty("request_uri") val requestUri: String?
)

/**
 * This is a use case that initializes the [Presentation] process.
 *
 * The caller may define via [InitTransactionTO] what kind of transaction wants to initiate
 * This is represented by [PresentationTypeTO].
 *
 * Use case will initialize a [Presentation] process
 */
interface InitTransaction {
    suspend operator fun invoke(initTransactionTO: InitTransactionTO): Result<JwtSecuredAuthorizationRequestTO>

    companion object {

        /**
         * Factory method to obtain the implementation of the use case
         */
        fun live(
            generatePresentationId: GeneratePresentationId,
            generateRequestId: GenerateRequestId,
            storePresentation: StorePresentation,
            signRequestObject: SignRequestObject,
            verifierConfig: VerifierConfig,
            clock: Clock
        ): InitTransaction = InitTransactionLive(
            generatePresentationId,
            generateRequestId,
            storePresentation,
            signRequestObject,
            verifierConfig,
            clock
        )
    }
}

/**
 * The default implementation of the use case
 */
internal class InitTransactionLive(
    private val generatePresentationId: GeneratePresentationId,
    private val generateRequestId: GenerateRequestId,
    private val storePresentation: StorePresentation,
    private val signRequestObject: SignRequestObject,
    private val verifierConfig: VerifierConfig,
    private val clock: Clock

) : InitTransaction {
    override suspend fun invoke(initTransactionTO: InitTransactionTO): Result<JwtSecuredAuthorizationRequestTO> =
        runCatching {

            // validate input
            val type = initTransactionTO.toDomain().getOrThrow()

            // Initialize presentation
            val requestedPresentation = Presentation.Requested(
                id = generatePresentationId(),
                initiatedAt = clock.instant(),
                requestId = generateRequestId(),
                type = type
            )
            // create request, which may update presentation
            val (updatedPresentation, request) = createRequest(requestedPresentation)

            storePresentation(updatedPresentation)
            request
        }

    /**
     * Creates a request and depending on the case updates also the [requestedPresentation]
     *
     * If the verifier has been configured to use request parameter then
     * presentation will be updated to [Presentation.RequestObjectRetrieved].
     *
     * Otherwise, [requestedPresentation] will remain as is
     */
    private fun createRequest(requestedPresentation: Presentation.Requested): Pair<Presentation, JwtSecuredAuthorizationRequestTO> =
        when (val requestJarOption = verifierConfig.requestJarOption) {
            is EmbedOption.ByValue -> {
                val jwt = signRequestObject(verifierConfig, requestedPresentation).getOrThrow()
                val requestObjectRetrieved =
                    requestedPresentation.retrieveRequestObject(requestedPresentation.initiatedAt).getOrThrow()
                requestObjectRetrieved to JwtSecuredAuthorizationRequestTO(verifierConfig.clientId, jwt, null)
            }

            is EmbedOption.ByReference -> {
                val requestUri = requestJarOption.buildUrl(requestedPresentation.requestId)
                val encoded = URLEncoder.encode(requestUri.toExternalForm(), "UTF-8")
                requestedPresentation to JwtSecuredAuthorizationRequestTO(verifierConfig.clientId, null, encoded)
            }
        }

}


internal fun InitTransactionTO.toDomain(): Result<PresentationType> {

    fun getIdTokenType() = Result.success(idTokenType?.toDomain()?.let { listOf(it) } ?: emptyList())
    fun getPd() = when (presentationDefinition) {
        null -> Result.failure(ValidationException(ValidationError.MissingPresentationDefinition))
        else -> runCatching {
            try {
                val str = ObjectMapper().writeValueAsString(presentationDefinition)
                PresentationExchange.jsonParser.decodePresentationDefinition(str!!).getOrThrow()
            } catch (t: Throwable) {
                throw ValidationException(ValidationError.InvalidPresentationDefinition)
            }
        }
    }

    return runCatching {
        when (type) {
            PresentationTypeTO.IdTokenRequest ->
                PresentationType.IdTokenRequest(getIdTokenType().getOrThrow())

            PresentationTypeTO.VpTokenRequest ->
                PresentationType.VpTokenRequest(getPd().getOrThrow())

            PresentationTypeTO.IdAndVpTokenRequest -> {
                val idTokenTypes = getIdTokenType().getOrThrow()
                val pd = getPd().getOrThrow()
                PresentationType.IdAndVpToken(idTokenTypes, pd)
            }
        }
    }
}


private fun IdTokenTypeTO.toDomain(): IdTokenType = when (this) {
    IdTokenTypeTO.SubjectSigned -> IdTokenType.SubjectSigned
    IdTokenTypeTO.AttesterSigned -> IdTokenType.AttesterSigned
}

package eu.europa.ec.euidw.verifier.application.port.`in`

import eu.europa.ec.euidw.prex.PresentationExchange
import eu.europa.ec.euidw.verifier.application.port.out.GeneratePresentationId
import eu.europa.ec.euidw.verifier.application.port.out.jose.SignRequestObject
import eu.europa.ec.euidw.verifier.application.port.out.persistence.StorePresentation
import eu.europa.ec.euidw.verifier.domain.IdTokenType
import eu.europa.ec.euidw.verifier.domain.Presentation
import eu.europa.ec.euidw.verifier.domain.PresentationType
import eu.europa.ec.euidw.verifier.domain.retrieveRequestObject
import java.net.URL
import java.time.Clock

/**
 * Represent the kind of [Presentation] process
 * a caller wants to initiate
 * It could be either a request (to the wallet) to present
 * a id_token, a vp_token or both
 */
enum class PresentationTypeTO {
    IdTokenRequest,
    VpTokenRequest,
    IdAndVpTokenRequest
}

/**
 * Specifies what kind of id_token to request
 */
enum class IdTokenTypeTO {
    SubjectSigned,
    AttesterSigned
}

data class InitTransactionTO(
    val type: PresentationTypeTO,
    val idTokenType: List<IdTokenTypeTO>,
    val presentationDefinition: String?
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
data class JwtSecuredAuthorizationRequestTO(
    val clientId: String,
    val request: String? = null,
    val requestUri: URL?
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
            storePresentation: StorePresentation,
            signRequestObject: SignRequestObject,
            verifierConfig: VerifierConfig,
            clock: Clock
        ): InitTransaction =
            InitTransactionLive(generatePresentationId, storePresentation, signRequestObject, verifierConfig, clock)
    }
}

/**
 * The default implementation of the use case
 */
internal class InitTransactionLive(
    private val generatePresentationId: GeneratePresentationId,
    private val storePresentation: StorePresentation,
    private val signRequestObject: SignRequestObject,
    private val verifierConfig: VerifierConfig,
    private val clock: Clock

) : InitTransaction {
    override suspend fun invoke(initTransactionTO: InitTransactionTO): Result<JwtSecuredAuthorizationRequestTO> = runCatching {

        // validate input
        val type = initTransactionTO.toDomain().getOrThrow()

        // Initialize presentation
        val requestedPresentation = Presentation.Requested(
            id = generatePresentationId(),
            initiatedAt = clock.instant(),
            type = type
        )
        // create request, which may update presentation
        val (updatedPresentation, request) = createRequest(requestedPresentation)

        storePresentation(updatedPresentation)
        request
    }

    private fun createRequest(requestedPresentation: Presentation.Requested): Pair<Presentation, JwtSecuredAuthorizationRequestTO> =
        when (val requestJarOption = verifierConfig.requestJarOption) {
            is EmbedOption.ByValue -> {
                val jwt = signRequestObject(verifierConfig, requestedPresentation).getOrThrow()
                val requestObjectRetrieved =
                    requestedPresentation.retrieveRequestObject(requestedPresentation.initiatedAt).getOrThrow()
                requestObjectRetrieved to JwtSecuredAuthorizationRequestTO(verifierConfig.clientId, jwt, null)
            }

            is EmbedOption.ByReference -> {
                val requestUri = requestJarOption.urlBuilder.build(requestedPresentation.id)
                requestedPresentation to JwtSecuredAuthorizationRequestTO(verifierConfig.clientId, null, requestUri)
            }
        }
}


internal fun InitTransactionTO.toDomain(): Result<PresentationType> {

    fun getIdTokenType() = Result.success(idTokenType.map { it.toDomain() })
    fun getPd() = when {
        presentationDefinition.isNullOrEmpty() -> Result.failure(ValidationException(ValidationError.MissingPresentationDefinition))
        else -> runCatching {
            try {
                PresentationExchange.jsonParser.decodePresentationDefinition(presentationDefinition!!).getOrThrow()
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

package eu.europa.ec.euidw.verifier.application.port.`in`

import eu.europa.ec.euidw.prex.PresentationExchange
import eu.europa.ec.euidw.verifier.application.port.out.GeneratePresentationId
import eu.europa.ec.euidw.verifier.application.port.out.persistence.StorePresentation
import eu.europa.ec.euidw.verifier.domain.IdTokenType
import eu.europa.ec.euidw.verifier.domain.Presentation
import eu.europa.ec.euidw.verifier.domain.PresentationType
import java.net.URL
import java.time.Clock
import java.time.Instant


enum class PresentationTypeTO {
    IdTokenRequest,
    VpTokenRequest,
    IdAndVpTokenRequest
}

enum class IdTokenTypeTO {
    SubjectSigned,
    AttesterSigned
}

data class InitTransactionTO(
    val type: PresentationTypeTO,
    val idTokenType: List<IdTokenTypeTO>,
    val presentationDefinition: String?
)


enum class ValidationError {
    MissingPresentationDefinition,
    InvalidPresentationDefinition
}

data class ValidationException(val error: ValidationError) : RuntimeException()

data class RequestTO(
    val clientId: String,
    val requestJwt: String? = null,
    val requestUri: URL?
)

interface InitTransaction {
    suspend fun invoke(initTransactionTO: InitTransactionTO): Result<RequestTO>

    companion object {
        fun live(
            generatePresentationId: GeneratePresentationId,
            storePresentation: StorePresentation,
            verifierConfig: VerifierConfig,
            clock: Clock
        ): InitTransaction =
            InitTransactionLive(generatePresentationId, storePresentation, verifierConfig, clock)
    }
}

internal class InitTransactionLive(
    private val generatePresentationId: GeneratePresentationId,
    private val storePresentation: StorePresentation,
    private val verifierConfig: VerifierConfig,
    private val clock: Clock

) : InitTransaction {
    override suspend fun invoke(initTransactionTO: InitTransactionTO) : Result<RequestTO> = runCatching{

        val presentation = Presentation.Requested(
            id = generatePresentationId(),
            initiatedAt = clock.instant(),
            type = initTransactionTO.toDomain().getOrThrow()
        )
        storePresentation(presentation)
        fromDomain(presentation)
    }
}

private fun fromDomain(presentation: Presentation.Requested): RequestTO = TODO()

private fun InitTransactionTO.toDomain(): Result<PresentationType> {

    fun getIdTokenType() = Result.success(idTokenType.map { it.toDomain() })
    fun getPd() = when {
        presentationDefinition.isNullOrEmpty() -> Result.failure(ValidationException(ValidationError.MissingPresentationDefinition))
        else -> PresentationExchange.jsonParser.decodePresentationDefinition(presentationDefinition)
            .fold(
                onSuccess = { Result.success(it) },
                onFailure = { Result.failure(ValidationException(ValidationError.InvalidPresentationDefinition)) }
            )
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

package eu.europa.ec.euidw.verifier.application.port.`in`

import eu.europa.ec.euidw.prex.PresentationDefinition
import eu.europa.ec.euidw.prex.PresentationExchange
import eu.europa.ec.euidw.verifier.domain.IdTokenType
import eu.europa.ec.euidw.verifier.domain.PresentationType


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


enum class ValidationError{
    MissingPresentationDefinition,
    InvalidPresentationDefinition
}

data class ValidationException(val error: ValidationError) : RuntimeException()


class  InitTransaction() {
    suspend fun invoke(initTransactionTO: InitTransactionTO) {
        TODO()
    }
}



private fun InitTransactionTO.toDomain(): Result<PresentationType> {

    fun getIdTokenType() = Result.success(idTokenType.map { it.toDomain() })
    fun getPd() =  when{
        presentationDefinition.isNullOrEmpty()-> Result.failure(ValidationException(ValidationError.MissingPresentationDefinition))
        else -> PresentationExchange.jsonParser.decodePresentationDefinition(presentationDefinition)
            .fold({Result.success(it)}, {Result.failure(ValidationException(ValidationError.InvalidPresentationDefinition))})
    }

    return runCatching { when(type){
        PresentationTypeTO.IdTokenRequest->
            PresentationType.IdTokenRequest(getIdTokenType().getOrThrow())
        PresentationTypeTO.VpTokenRequest ->
            PresentationType.VpTokenRequest(getPd().getOrThrow())
        PresentationTypeTO.IdAndVpTokenRequest->  {
            val idts = getIdTokenType().getOrThrow()
            val pd = getPd().getOrThrow()
            PresentationType.IdAndVpToken(idts, pd)
        }
    }
    }
}


private fun IdTokenTypeTO.toDomain(): IdTokenType= when(this){
    IdTokenTypeTO.SubjectSigned->IdTokenType.SubjectSigned
    IdTokenTypeTO.AttesterSigned->IdTokenType.AttesterSigned
}

package eu.europa.ec.eudi.verifier.endpoint.adapter.out.persistence

import eu.europa.ec.eudi.verifier.endpoint.port.out.persistence.PresentationEvent
import org.slf4j.Logger
import org.slf4j.LoggerFactory

class PresentationEventLogger(
    private val logger: Logger = LoggerFactory.getLogger("EVENTS")
) {
    fun log(e: PresentationEvent) {
        fun txt(s: String) = "$s - tx: ${e.transactionId.value}"
        fun warn(s: String) = logger.warn(txt(s))
        fun info(s: String) = logger.info(txt(s))
        when (e) {
            is PresentationEvent.VerifierFailedToGetWalletResponse -> warn("Verifier failed to retrieve wallet response. Cause ${e.cause}")
            is PresentationEvent.FailedToRetrievePresentationDefinition -> warn(
                "Wallet failed to retrieve presentation definition. Cause ${e.cause}",
            )

            is PresentationEvent.WalletFailedToPostResponse -> warn("Wallet failed to post response. Cause ${e.cause}")
            is PresentationEvent.FailedToRetrieveRequestObject -> warn("Wallet failed to retrieve request object. Cause ${e.cause}")
            is PresentationEvent.PresentationExpired -> info("Presentation expired")
            is PresentationEvent.RequestObjectRetrieved -> info("Wallet retrieved Request Object")
            is PresentationEvent.TransactionInitialized -> info("Verifier initialized transaction")
            is PresentationEvent.VerifierGotWalletResponse -> info("Verifier retrieved wallet response")
            is PresentationEvent.WalletResponsePosted -> info("Wallet posted response")
            is PresentationEvent.AttestationStatusCheckSuccessful -> info("Attestation status check successful")
            is PresentationEvent.AttestationStatusCheckFailed -> warn("Attestation status check failed")
        }
    }
}

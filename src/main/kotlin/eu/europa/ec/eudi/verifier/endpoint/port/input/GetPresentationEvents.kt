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

import eu.europa.ec.eudi.verifier.endpoint.port.out.persistence.PresentationEvent
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.*

@Serializable
private enum class Actor {
    Verifier,
    Wallet,
    VerifierEndPoint,
}

private fun JsonObjectBuilder.putEventNameAndActor(e: PresentationEvent) {
    val (eventName, actor) = when (e) {
        is PresentationEvent.TransactionInitialized -> "Transaction initialized" to Actor.Verifier
        is PresentationEvent.RequestObjectRetrieved -> "Request object retrieved" to Actor.Wallet
        is PresentationEvent.FailedToRetrieveRequestObject -> "FailedToRetrieve request" to Actor.Wallet
        is PresentationEvent.JarmJwkSetRetrieved -> "JARM JWK set retrieved" to Actor.Wallet
        is PresentationEvent.FailedToRetrieveJarmJwkSet -> "FailedToRetrieve JARM JWK set retrieved" to Actor.Wallet
        is PresentationEvent.FailedToRetrievePresentationDefinition -> "Failed to retrieve presentation definition" to Actor.Wallet
        is PresentationEvent.WalletResponsePosted -> "Wallet response posted" to Actor.Wallet
        is PresentationEvent.WalletFailedToPostResponse -> "Wallet failed to post response" to Actor.Wallet
        is PresentationEvent.VerifierGotWalletResponse -> "Verifier got wallet response" to Actor.Verifier
        is PresentationEvent.VerifierFailedToGetWalletResponse -> "Verifier failed to get wallet" to Actor.Verifier
        is PresentationEvent.PresentationExpired -> "Presentation expired" to Actor.VerifierEndPoint
        is PresentationEvent.AttestationStatusCheckSuccessful -> "Attestation status check succeeded" to Actor.VerifierEndPoint
        is PresentationEvent.AttestationStatusCheckFailed -> "Attestation status check failed" to Actor.VerifierEndPoint
    }
    put("event", eventName)
    put("actor", actor.json())
}

private fun WalletResponseValidationError.asText(): String =
    when (this) {
        WalletResponseValidationError.IncorrectState -> "Incorrect state"
        WalletResponseValidationError.MissingIdToken -> "Missing id_token"
        WalletResponseValidationError.MissingState -> "Missing state from JARM"
        WalletResponseValidationError.MissingVpToken -> "Missing vp_token"
        WalletResponseValidationError.MissingPresentationSubmission -> "Missing presentation_submission"
        WalletResponseValidationError.PresentationSubmissionMustNotBePresent -> "presentation_submission must not be provided"
        is WalletResponseValidationError.InvalidVpToken -> "vp_token is not valid: ${message}${cause?.message?.let { ", $it"}}"
        is WalletResponseValidationError.PresentationNotFound -> "Presentation not found"
        is WalletResponseValidationError.PresentationNotInExpectedState -> "Presentation non in expected state"
        is WalletResponseValidationError.UnexpectedResponseMode -> "Unexpected response mode. Expected $expected, actual $actual"
        WalletResponseValidationError.RequiredCredentialSetNotSatisfied ->
            "vp_token does not satisfy all the required credential sets of the query"
        WalletResponseValidationError.InvalidPresentationSubmission -> "Presentation submission is not valid"
        is WalletResponseValidationError.InvalidJarm -> "JARM is not valid: '${error.message}'"
    }

private inline fun <reified A> A.json() = Json.encodeToJsonElement(this)

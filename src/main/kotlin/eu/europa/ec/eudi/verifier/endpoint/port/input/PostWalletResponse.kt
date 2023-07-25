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

import eu.europa.ec.eudi.prex.PresentationSubmission
import eu.europa.ec.eudi.verifier.endpoint.domain.*
import eu.europa.ec.eudi.verifier.endpoint.domain.Presentation.RequestObjectRetrieved
import eu.europa.ec.eudi.verifier.endpoint.port.out.jose.VerifyJarmJwtSignature
import eu.europa.ec.eudi.verifier.endpoint.port.out.persistence.LoadPresentationByRequestId
import eu.europa.ec.eudi.verifier.endpoint.port.out.persistence.StorePresentation
import java.time.Clock

/**
 * Represent the Authorisation Response placed by wallet
 */
data class AuthorisationResponseTO(
    val state: String?, // this is the request_id
    val error: String? = null,
    val errorDescription: String? = null,
    val idToken: String? = null,
    val vpToken: String? = null,
    val presentationSubmission: PresentationSubmission? = null,
)

sealed interface AuthorisationResponse {

    data class DirectPost(val response: AuthorisationResponseTO) : AuthorisationResponse
    data class DirectPostJwt(val state: String?, val jarm: Jwt) : AuthorisationResponse
}

/**
 * Carrier of [ValidationError]
 */
data class WalletResponseValidationException(val error: WalletResponseValidationError) : RuntimeException()

enum class WalletResponseValidationError {
    MissingIdToken,
    MissingVpTokenOrPresentationSubmission,
    MissingIdTokenOrVpTokenOrPresentationSubmission,
}

internal fun AuthorisationResponseTO.toDomain(presentation: RequestObjectRetrieved): Result<WalletResponse> {
    fun requiredIdToken() =
        if (idToken != null) {
            Result.success(WalletResponse.IdToken(idToken))
        } else Result.failure(WalletResponseValidationException(WalletResponseValidationError.MissingIdToken))

    fun requiredVpToken() =
        if (vpToken != null && presentationSubmission != null) {
            Result.success(WalletResponse.VpToken(vpToken, presentationSubmission))
        } else Result.failure(WalletResponseValidationException(WalletResponseValidationError.MissingVpTokenOrPresentationSubmission))

    fun requiredIdAndVpToken() =
        if (idToken != null && vpToken != null && presentationSubmission != null) {
            Result.success(
                WalletResponse.IdAndVpToken(
                    idToken = idToken,
                    vpToken = vpToken,
                    presentationSubmission = presentationSubmission,
                ),
            )
        } else Result.failure(
            WalletResponseValidationException(WalletResponseValidationError.MissingIdTokenOrVpTokenOrPresentationSubmission),
        )

    val maybeError: WalletResponse.Error? = error?.let { WalletResponse.Error(it, errorDescription) }

    return if (maybeError != null) {
        Result.success(maybeError)
    } else {
        runCatching {
            when (presentation.type) {
                is PresentationType.IdTokenRequest -> WalletResponse.IdToken(requiredIdToken().getOrThrow().idToken)
                is PresentationType.VpTokenRequest -> WalletResponse.VpToken(
                    requiredVpToken().getOrThrow().vpToken,
                    requiredVpToken().getOrThrow().presentationSubmission,
                )

                is PresentationType.IdAndVpToken -> WalletResponse.IdAndVpToken(
                    requiredIdAndVpToken().getOrThrow().idToken,
                    requiredIdAndVpToken().getOrThrow().vpToken,
                    requiredIdAndVpToken().getOrThrow().presentationSubmission,
                )
            }
        }
    }
}

/**
 * This is use case 12 of the [Presentation] process.
 *
 * The caller (wallet) may POST the [AuthorisationResponseTO] to the verifier back-end
 */
fun interface PostWalletResponse {
    suspend operator fun invoke(walletResponse: AuthorisationResponse): QueryResponse<String>
}

class PostWalletResponseLive(
    private val loadPresentationByRequestId: LoadPresentationByRequestId,
    private val storePresentation: StorePresentation,
    private val verifyJarmJwtSignature: VerifyJarmJwtSignature,
    private val clock: Clock,
    private val verifierConfig: VerifierConfig,
) : PostWalletResponse {

    override suspend operator fun invoke(walletResponse: AuthorisationResponse): QueryResponse<String> =
        handleWalletResponse(walletResponse).fold(
            onSuccess = { QueryResponse.Found("OK") },
            onFailure = { QueryResponse.InvalidState },
        )

    private suspend fun handleWalletResponse(walletResponse: AuthorisationResponse): Result<Presentation.Submitted> =
        runCatching {
            val presentation = loadPresentation(walletResponse)
            val responseObject = responseObject(walletResponse, presentation)
            submit(presentation, responseObject).also { storePresentation(it) }
        }

    private suspend fun loadPresentation(walletResponse: AuthorisationResponse): RequestObjectRetrieved {
        val requestId = when (walletResponse) {
            is AuthorisationResponse.DirectPost -> walletResponse.response.state
            is AuthorisationResponse.DirectPostJwt -> walletResponse.state
        }?.let { RequestId(it) } ?: throw IllegalArgumentException("Missing state")

        val presentation = loadPresentationByRequestId(requestId)
            ?: throw IllegalArgumentException("Presentation not found for requestId $requestId")
        require(presentation is RequestObjectRetrieved) { "Invalid state for requestId $requestId" }
        return presentation
    }

    private fun responseObject(
        walletResponse: AuthorisationResponse,
        presentation: RequestObjectRetrieved,
    ): AuthorisationResponseTO = when (walletResponse) {
        is AuthorisationResponse.DirectPost -> walletResponse.response
        is AuthorisationResponse.DirectPostJwt -> {
            val response = verifyJarmJwtSignature(
                jarmOption = verifierConfig.clientMetaData.jarmOption,
                ephemeralEcPrivateKey = presentation.ephemeralEcPrivateKey,
                jarmJwt = walletResponse.jarm,
            ).getOrThrow()
            require(response.state == walletResponse.state) {
                "State is not the same in wallet response and inside JARM"
            }
            response
        }
    }

    private fun submit(
        presentation: RequestObjectRetrieved,
        responseObject: AuthorisationResponseTO,
    ): Presentation.Submitted {
        // add the wallet response to the presentation
        val walletResponse = responseObject.toDomain(presentation).getOrThrow()
        return presentation.submit(clock, walletResponse).getOrThrow()
    }
}

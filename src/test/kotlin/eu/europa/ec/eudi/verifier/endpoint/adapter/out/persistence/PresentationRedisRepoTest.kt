package eu.europa.ec.eudi.verifier.endpoint.adapter.out.persistence

import com.fasterxml.jackson.annotation.JsonInclude
import com.fasterxml.jackson.databind.ObjectMapper
import com.fasterxml.jackson.module.kotlin.jacksonObjectMapper
import com.fasterxml.jackson.module.kotlin.registerKotlinModule
import eu.europa.ec.eudi.verifier.endpoint.domain.GetWalletResponseMethod
import eu.europa.ec.eudi.verifier.endpoint.domain.Nonce
import eu.europa.ec.eudi.verifier.endpoint.domain.Presentation
import eu.europa.ec.eudi.verifier.endpoint.domain.PresentationType
import eu.europa.ec.eudi.verifier.endpoint.domain.RequestId
import eu.europa.ec.eudi.verifier.endpoint.domain.RequestUriMethod
import eu.europa.ec.eudi.verifier.endpoint.domain.ResponseMode
import eu.europa.ec.eudi.verifier.endpoint.domain.TransactionId
import kotlinx.serialization.json.Json
import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.Test
import java.time.Instant

class PresentationRedisRepoTest {
    @Test
    fun test() {
        val presentation = Presentation.Requested(
            id = TransactionId("123"),
            initiatedAt = Instant.now(),
            type = PresentationType.IdTokenRequest(emptyList()), // Start with empty list
            requestId = RequestId("456"),
            requestUriMethod = RequestUriMethod.Post,
            nonce = Nonce("789"),
            responseMode = ResponseMode.DirectPost,
            getWalletResponseMethod = GetWalletResponseMethod.Poll,
            issuerChain = null
        )

        val json = Json.encodeToString(presentation)

        println(json)
    }
}

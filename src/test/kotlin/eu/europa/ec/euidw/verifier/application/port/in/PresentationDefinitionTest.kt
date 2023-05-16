package eu.europa.ec.euidw.verifier.application.port.`in`

import com.nimbusds.jwt.SignedJWT
import eu.europa.ec.euidw.verifier.adapter.`in`.web.VerifierApi
import org.json.JSONObject
import org.junit.jupiter.api.Test
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.boot.test.context.SpringBootTest
import org.springframework.http.MediaType
import org.springframework.test.web.reactive.server.WebTestClient
import org.springframework.web.reactive.function.BodyInserters
import java.text.ParseException

@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
internal class PresentationDefinitionTest () {

    @Autowired
    private lateinit var client: WebTestClient

    @Test
    fun `post presentation definition returns 200`() {
        // given
        val body = """
            { 
              "type": "vp_token id_token",
              "id_token_type": "subject_signed_id_token",
              "presentation_definition": {
                "id": "32f54163-7166-48f1-93d8-ff217bdb0653",
                "input_descriptors": [
                  {
                    "id": "wa_driver_license",
                    "name": "Washington State Business License",
                    "purpose": "We can only allow licensed Washington State business representatives into the WA Business Conference",
                    "constraints": {
                      "fields": [
                        {
                          "path": [
                            "$.credentialSubject.dateOfBirth",
                            "$.credentialSubject.dob",
                            "$.vc.credentialSubject.dateOfBirth",
                            "$.vc.credentialSubject.dob"
                          ]
                        }
                      ]
                    }
                  }
                ]
              }
            }
        """

        // when / then
        client.post().uri(VerifierApi.initTransactionPath)
            .contentType(MediaType.APPLICATION_JSON)
            .accept(MediaType.APPLICATION_JSON)
            .body(BodyInserters.fromValue(body))
            .exchange()
            .expectStatus().isOk()
            .expectBody().returnResult().responseBodyContent?.let { println("response: ${String(it)}") }
    }

    @Test
    fun `get presentation definition returns 200`() {
        // given
        val body = """
            { 
              "type": "vp_token id_token",
              "id_token_type": "subject_signed_id_token",
              "presentation_definition": {
                "id": "32f54163-7166-48f1-93d8-ff217bdb0653",
                "input_descriptors": [
                  {
                    "id": "wa_driver_license",
                    "name": "Washington State Business License",
                    "purpose": "We can only allow licensed Washington State business representatives into the WA Business Conference",
                    "constraints": {
                      "fields": [
                        {
                          "path": [
                            "$.credentialSubject.dateOfBirth",
                            "$.credentialSubject.dob",
                            "$.vc.credentialSubject.dateOfBirth",
                            "$.vc.credentialSubject.dob"
                          ]
                        }
                      ]
                    }
                  }
                ]
              }
            }
        """

        val response = client.post().uri(VerifierApi.initTransactionPath)
            .contentType(MediaType.APPLICATION_JSON)
            .accept(MediaType.APPLICATION_JSON)
            .body(BodyInserters.fromValue(body))
            .exchange()
            .expectStatus().isOk()
            .expectBody().returnResult();
        val responseString = String(response.responseBodyContent!!)
        val responseJson = JSONObject(responseString)
        val requestUri = responseJson.get("request_uri")
        println("requestUri=${requestUri}")

        // when
        val relativeRequestUri = requestUri.toString().removePrefix("http://localhost:0")
        println("relative request_uri: ${relativeRequestUri}")

        // then
        val getResponse = client.get().uri(relativeRequestUri)
            .accept(MediaType.APPLICATION_JSON)
            .exchange()
            .expectStatus().isOk()
            .expectBody().returnResult();
        val getResponseString = String(getResponse.responseBodyContent!!)
        println("response: ${getResponseString}")

        val (header, payload) = TestUtils.parseJWT(getResponseString)
        // debug
        val prettyHeader = TestUtils.prettyPrintJson(header)
        val prettyPayload = TestUtils.prettyPrintJson(payload)
        println("prettyHeader:\n${prettyHeader}")
        println("prettyPayload:\n${prettyPayload}")

        val responsePresentationDefinition = JSONObject(payload).get("presentation_definition")
        val bodyPresentationDefinition = JSONObject(body).get("presentation_definition")

        assert(TestUtils.compareJsonStrings(bodyPresentationDefinition.toString(), responsePresentationDefinition.toString()),
            { "presentationDefinition of response is not equal to presentationDefinition of request" })
    }

}
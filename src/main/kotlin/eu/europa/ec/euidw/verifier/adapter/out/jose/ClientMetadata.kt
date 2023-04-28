package eu.europa.ec.euidw.verifier.adapter.out.jose

import com.fasterxml.jackson.databind.ObjectMapper
import com.fasterxml.jackson.module.kotlin.readValue
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.Json
import kotlinx.serialization.encodeToString as kotlinEncodeToString

/**
 * By OpenID Connect Dynamic Client Registration specification (https://openid.net/specs/openid-connect-registration-1_0.html)
 */
@Serializable
data class ClientMetaData(
    @SerialName("jwks_uri") val jwksUri: String,
    @SerialName("id_token_signed_response_alg") val idTokenSignedResponseAlg: String,
    @SerialName("id_token_encrypted_response_alg") val idTokenEncryptedResponseAlg: String,
    @SerialName("id_token_encrypted_response_enc") val idTokenEncryptedResponseEnc: String,
    @SerialName("subject_syntax_types_supported") val subjectSyntaxTypesSupported: List<String>
) {
    companion object {
        private val objectMapper: ObjectMapper by lazy { ObjectMapper() }
        fun toJsonObject(cm: ClientMetaData): Any {
            val jsonStr = Json.kotlinEncodeToString(cm)
            return objectMapper.readValue<Any>(jsonStr)
        }
    }

}
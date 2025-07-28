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
package eu.europa.ec.eudi.verifier.endpoint.domain

/**
 * [OpenID for Verifiable Presentations](https://openid.net/specs/openid-4-verifiable-presentations-1_0-23.html)
 */
object OpenId4VPSpec {
    const val VERSION: String = "draft 24"

    const val RESPONSE_URI: String = "response_uri"

    const val DCQL_QUERY: String = "dcql_query"
    const val TRANSACTION_DATA: String = "transaction_data"

    const val CLIENT_ID: String = "client_id"
    const val REQUEST: String = "request"
    const val REQUEST_URI: String = "request_uri"
    const val REQUEST_URI_METHOD: String = "request_uri_method"
    const val REQUEST_URI_METHOD_GET: String = "get"
    const val REQUEST_URI_METHOD_POST: String = "post"

    const val RESPONSE_MODE_DIRECT_POST: String = "direct_post"
    const val RESPONSE_MODE_DIRECT_POST_JWT: String = "direct_post.jwt"

    const val VP_FORMATS: String = "vp_formats"

    const val FORMAT_MSO_MDOC: String = "mso_mdoc"
    const val FORMAT_SD_JWT_VC: String = "dc+sd-jwt"
    const val FORMAT_W3C_SIGNED_JWT: String = "jwt_vc_json"

    const val DCQL_CREDENTIALS: String = "credentials"
    const val DCQL_CREDENTIAL_SETS: String = "credential_sets"
    const val DCQL_ID: String = "id"
    const val DCQL_FORMAT: String = "format"
    const val DCQL_MULTIPLE: String = "multiple"
    const val DCQL_META: String = "meta"
    const val DCQL_TRUSTED_AUTHORITIES: String = "trusted_authorities"
    const val DCQL_REQUIRE_CRYPTOGRAPHIC_HB: String = "require_cryptographic_holder_binding"
    const val DCQL_CLAIMS: String = "claims"
    const val DCQL_CLAIM_SETS: String = "claim_sets"
    const val DCQL_OPTIONS: String = "options"
    const val DCQL_REQUIRED: String = "required"
    const val DCQL_PATH: String = "path"
    const val DCQL_VALUES: String = "values"
    const val DCQL_SD_JWT_VC_VCT_VALUES: String = "vct_values"
    const val DCQL_MSO_MDOC_DOCTYPE_VALUE: String = "doctype_value"
    const val DCQL_MSO_MDOC_INTENT_TO_RETAIN: String = "intent_to_retain"
    const val DCQL_TRUSTED_AUTHORITY_TYPE: String = "type"
    const val DCQL_TRUSTED_AUTHORITY_VALUES: String = "values"
    const val DCQL_TRUSTED_AUTHORITY_TYPE_AKI: String = "aki"
    const val DCQL_TRUSTED_AUTHORITY_TYPE_ETSI_TL: String = "etsi_tl"
    const val DCQL_TRUSTED_AUTHORITY_TYPE_OPENID_FEDERATION: String = "openid_federation"

    const val WALLET_METADATA: String = "wallet_metadata"
    const val WALLET_NONCE: String = "wallet_nonce"

    const val PRESENTATION_DEFINITION_URI_SUPPORTED: String = "presentation_definition_uri_supported"
    const val VP_FORMATS_SUPPORTED: String = "vp_formats_supported"
    const val CLIENT_ID_SCHEMES_SUPPORTED: String = "client_id_schemes_supported"

    const val CLIENT_ID_SCHEME_PRE_REGISTERED: String = "pre-registered"
    const val CLIENT_ID_SCHEME_X509_SAN_DNS: String = "x509_san_dns"
    const val CLIENT_ID_SCHEME_X509_HASH: String = "x509_hash"

    const val DEFAULT_PRESENTATION_DEFINITION_URI_SUPPORTED: Boolean = true
    val DEFAULT_CLIENT_ID_SCHEMES_SUPPORTED: List<String> = listOf(CLIENT_ID_SCHEME_PRE_REGISTERED)

    const val ENCRYPTED_RESPONSE_ENC_VALUES_SUPPORTED = "encrypted_response_enc_values_supported"
}

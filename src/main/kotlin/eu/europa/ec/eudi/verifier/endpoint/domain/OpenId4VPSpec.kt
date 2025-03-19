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

object OpenId4VPSpec {
    const val VERSION: String = "draft 23"

    const val FORMAT_MSO_MDOC: String = "mso_mdoc"
    const val FORMAT_SD_JWT_VC: String = "dc+sd-jwt"
    const val FORMAT_W3C_SIGNED_JWT: String = "jwt_vc_json"

    const val DCQL_CREDENTIALS: String = "credentials"
    const val DCQL_CREDENTIAL_SETS: String = "credential_sets"
    const val DCQL_ID: String = "id"
    const val DCQL_FORMAT: String = "format"
    const val DCQL_META: String = "meta"
    const val DCQL_CLAIMS: String = "claims"
    const val DCQL_CLAIM_SETS: String = "claim_sets"
    const val DCQL_OPTIONS: String = "options"
    const val DCQL_REQUIRED: String = "required"
    const val DCQL_PURPOSE: String = "purpose"
    const val DCQL_PATH: String = "path"
    const val DCQL_VALUES: String = "values"
    const val DCQL_SD_JWT_VC_VCT_VALUES: String = "vct_values"
    const val DCQL_MSO_MDOC_DOCTYPE_VALUE: String = "doctype_value"
    const val DCQL_MSO_MDOC_NAMESPACE: String = "namespace"
    const val DCQL_MSO_MDOC_CLAIM_NAME: String = "claim_name"

    const val WALLET_METADATA: String = "wallet_metadata"
    const val WALLET_NONCE: String = "wallet_nonce"

    const val PRESENTATION_DEFINITION_URI_SUPPORTED: String = "presentation_definition_uri_supported"
    const val VP_FORMATS_SUPPORTED: String = "vp_formats_supported"
    const val CLIENT_ID_SCHEMES_SUPPORTED: String = "client_id_schemes_supported"

    const val CLIENT_ID_SCHEME_PRE_REGISTERED: String = "pre-registered"
    const val CLIENT_ID_SCHEME_X509_SAN_DNS: String = "x509_san_dns"
    const val CLIENT_ID_SCHEME_X509_SAN_URI: String = "x509_san_uri"
}

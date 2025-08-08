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
 * [Self-Issued OpenID Provider](https://openid.net/specs/openid-connect-self-issued-v2-1_0-13.html)
 */
object SIOPSpec {
    const val ID_TOKEN_TYPE_SUBJECT_SIGNED_ID_TOKEN: String = "subject_signed_id_token"
    const val ID_TOKEN_TYPE_ATTESTER_SIGNED_ID_TOKEN: String = "attester_signed_id_token"
    const val ID_TOKEN_TYPE: String = "id_token_type"
}

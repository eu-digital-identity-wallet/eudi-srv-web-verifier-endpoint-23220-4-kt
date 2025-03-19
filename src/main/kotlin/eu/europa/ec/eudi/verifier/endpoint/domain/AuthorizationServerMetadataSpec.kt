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

object AuthorizationServerMetadataSpec {
    const val RESPONSE_TYPES_SUPPORTED: String = "response_types_supported"
    const val RESPONSE_MODES_SUPPORTED: String = "response_modes_supported"

    const val RESPONSE_MODE_QUERY = "query"
    const val RESPONSE_MODE_FRAGMENT = "fragment"
}

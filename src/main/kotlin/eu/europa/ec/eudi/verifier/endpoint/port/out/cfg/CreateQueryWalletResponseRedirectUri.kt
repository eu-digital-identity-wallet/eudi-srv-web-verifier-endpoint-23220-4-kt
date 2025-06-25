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
package eu.europa.ec.eudi.verifier.endpoint.port.out.cfg

import arrow.core.Either
import eu.europa.ec.eudi.verifier.endpoint.adapter.out.utils.getOrThrow
import eu.europa.ec.eudi.verifier.endpoint.domain.GetWalletResponseMethod
import eu.europa.ec.eudi.verifier.endpoint.domain.ResponseCode
import java.net.URL

interface CreateQueryWalletResponseRedirectUri {

    fun GetWalletResponseMethod.Redirect.redirectUri(responseCode: ResponseCode): URL =
        redirectUri(redirectUriTemplate, responseCode).getOrThrow()

    fun redirectUri(template: String, responseCode: ResponseCode): Either<Throwable, URL>

    fun String.validTemplate(): Boolean = redirectUri(this, ResponseCode("test")).isRight() // .isSuccess

    companion object {
        const val RESPONSE_CODE_PLACE_HOLDER = "{RESPONSE_CODE}"
        val Simple: CreateQueryWalletResponseRedirectUri = object : CreateQueryWalletResponseRedirectUri {
            override fun redirectUri(template: String, responseCode: ResponseCode): Either<Throwable, URL> = Either.catch {
                require(template.contains(RESPONSE_CODE_PLACE_HOLDER)) { "Expected response_code place holder not found in template" }
                val url = template.replace(RESPONSE_CODE_PLACE_HOLDER, responseCode.value)
                URL(url)
            }
        }
    }
}

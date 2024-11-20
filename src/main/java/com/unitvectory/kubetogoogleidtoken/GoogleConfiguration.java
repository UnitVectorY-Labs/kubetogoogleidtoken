/*
 * Copyright 2024 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License. You may obtain a copy of the License at
 *
 * https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software distributed under the License
 * is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express
 * or implied. See the License for the specific language governing permissions and limitations under
 * the License.
 */
package com.unitvectory.kubetogoogleidtoken;

import lombok.Data;
import com.google.gson.annotations.SerializedName;

/**
 * Configuration for the Google STS token generation used by Kubernetes using
 * Workload Identity.
 * 
 * @author Jared Hatfield (UnitVectorY Labs)
 */
@Data
class GoogleConfiguration {

    @SerializedName("universe_domain")
    private String universeDomain;

    private String type;

    private String audience;

    @SerializedName("subject_token_type")
    private String subjectTokenType;

    @SerializedName("token_url")
    private String tokenUrl;

    @SerializedName("credential_source")
    private CredentialSource credentialSource;

    @SerializedName("service_account_impersonation_url")
    private String serviceAccountImpersonationUrl;

    @Data
    public static class CredentialSource {

        private String file;

        private Format format;

        @Data
        public static class Format {

            private String type;
        }
    }
}
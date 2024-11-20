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

import com.google.gson.Gson;
import com.google.gson.JsonObject;

import lombok.AccessLevel;
import lombok.Builder;
import lombok.Getter;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;

/**
 * Client for generating Google ID tokens from a Kubernetes service account
 * token.
 * 
 * @author Jared Hatfield (UnitVectorY Labs)
 */
@Getter(AccessLevel.PACKAGE)
public class KubeToGoogleIdTokenClient {

    private static final String DEFAULT_TOKEN_URL = "https://sts.googleapis.com/v1/token";

    private static final String DEFAULT_IMPERSONATION_TEMPLATE = "https://iamcredentials.googleapis.com/v1/projects/-/serviceAccounts/%s:generateIdToken";

    private static final Gson gson = new Gson();

    /**
     * The URL used to request an access token from the STS service.
     */
    private final String tokenUrl;

    /**
     * The URL used to request an ID token from the IAM Credentials service.
     */
    private final String serviceAccountImpersonationUrl;

    /**
     * The path to the Kubernetes service account token file on the file system.
     * 
     * The token must have the audience set to the STS service.
     */
    private final String k8sTokenPath;

    /**
     * The audience for the STS service.
     */
    private final String stsAudience;

    @Builder
    public KubeToGoogleIdTokenClient(
            Boolean loadEnvironment,
            String k8sTokenPath,
            String projectNumber,
            String workloadIdentityPool,
            String workloadProvider,
            String serviceAccountEmail) {

        String k8sTokenPathValue = null;
        String stsAudienceValue = null;

        String tokenUrlValue = null;
        String serviceAccountImpersonationUrlValue = null;

        String googleApplicationCredentials = System.getenv("GOOGLE_APPLICATION_CREDENTIALS");
        if (googleApplicationCredentials != null) {

            // Try to load the files from the Google Application Credentials if it exists
            // and was set
            Path credentialsPath = Paths.get(googleApplicationCredentials);
            if (Files.exists(credentialsPath)) {
                try {
                    GoogleConfiguration googleConfiguration = gson.fromJson(Files.readString(credentialsPath),
                            GoogleConfiguration.class);
                    if (googleConfiguration != null) {
                        if (googleConfiguration.getCredentialSource() != null) {
                            k8sTokenPathValue = googleConfiguration.getCredentialSource().getFile();
                        }

                        stsAudienceValue = googleConfiguration.getAudience();
                        tokenUrlValue = googleConfiguration.getTokenUrl();

                        if (googleConfiguration.getServiceAccountImpersonationUrl() != null) {
                            serviceAccountImpersonationUrlValue = googleConfiguration
                                    .getServiceAccountImpersonationUrl();

                            // If the URL for the service account impersonation is for generating access
                            // tokens, then change it to generate ID tokens which is what we need
                            if (serviceAccountImpersonationUrlValue.endsWith(":generateAccessToken")) {
                                serviceAccountImpersonationUrlValue = serviceAccountImpersonationUrlValue.substring(0,
                                        serviceAccountImpersonationUrlValue.length() - 20) + ":generateIdToken";
                            }
                        }
                    }
                } catch (IOException e) {
                    // Ignore any exceptions and continue with the default values
                }
            }
        }

        // Override the values if they were set in the builder explicitly

        if (k8sTokenPathValue == null) {
            k8sTokenPathValue = k8sTokenPath;
        }

        if (stsAudienceValue == null) {
            stsAudienceValue = String.format(
                    "//iam.googleapis.com/projects/%s/locations/global/workloadIdentityPools/%s/providers/%s",
                    projectNumber, workloadIdentityPool, workloadProvider);
        }

        if (tokenUrlValue == null) {
            tokenUrlValue = DEFAULT_TOKEN_URL;
        }

        if (serviceAccountImpersonationUrlValue == null) {
            serviceAccountImpersonationUrlValue = String.format(DEFAULT_IMPERSONATION_TEMPLATE, serviceAccountEmail);
        }

        // Set the final value so this class is immutable
        this.k8sTokenPath = k8sTokenPathValue;
        this.stsAudience = stsAudienceValue;
        this.tokenUrl = tokenUrlValue;
        this.serviceAccountImpersonationUrl = serviceAccountImpersonationUrlValue;
    }

    /**
     * Generates a GCP ID token for the specified audience.
     *
     * @param request The KubeToGoogleIdTokenRequest containing the audience.
     * @return The IdTokenResponse containing the ID token.
     * @throws KubeToGoogleIdTokenException If any step in the token generation
     *                                      process fails.
     * @throws IllegalArgumentException     If the audience is not specified.
     * @throws IllegalStateException        If the configuration is not properly
     *                                      set.
     */
    public KubeToGoogleIdTokenResponse getIdToken(KubeToGoogleIdTokenRequest request) {
        if (request == null || request.getAudience() == null || request.getAudience().isEmpty()) {
            throw new IllegalArgumentException("Audience must be specified in the IdTokenRequest.");
        }

        if (this.tokenUrl == null) {
            throw new IllegalStateException("Token URL must be specified in the configuration.");
        } else if (this.serviceAccountImpersonationUrl == null) {
            throw new IllegalStateException(
                    "Service Account Impersonation URL must be specified in the configuration.");
        } else if (this.k8sTokenPath == null) {
            throw new IllegalStateException("Kubernetes Token Path must be specified in the configuration.");
        } else if (this.stsAudience == null) {
            throw new IllegalStateException("STS Audience must be specified in the configuration.");
        }

        // Phase 1: Retrieve Kubernetes Token from the file system
        String k8sToken = retrieveKubernetesToken();

        // Phase 2: Exchange Kubernetes Token for Access Token via STS
        String accessToken = exchangeTokenWithSTS(k8sToken, stsAudience);

        // Phase 3: Generate Identity Token via IAM Credentials by GCP Impersonating
        // Service Account
        String idToken = generateIdentityToken(accessToken, request.getAudience());

        return KubeToGoogleIdTokenResponse.builder().idToken(idToken).build();
    }

    String retrieveKubernetesToken() {
        try {
            Path tokenPath = Paths.get(k8sTokenPath);
            if (!Files.exists(tokenPath)) {
                throw new KubeToGoogleIdTokenException("Kubernetes token file does not exist: " + k8sTokenPath);
            }
            return Files.readString(tokenPath);
        } catch (KubeToGoogleIdTokenException e) {
            throw e;
        } catch (IOException e) {
            throw new KubeToGoogleIdTokenException("Failed to read Kubernetes token file: " + k8sTokenPath, e);
        }
    }

    String exchangeTokenWithSTS(String subjectToken, String audience) {
        GoogleAccessTokenRequest request = GoogleAccessTokenRequest.builder()
                .grantType("urn:ietf:params:oauth:grant-type:token-exchange")
                .audience(audience)
                .scope("https://www.googleapis.com/auth/cloud-platform")
                .requestedTokenType("urn:ietf:params:oauth:token-type:access_token")
                .subjectTokenType("urn:ietf:params:oauth:token-type:jwt")
                .subjectToken(subjectToken)
                .build();

        try {
            String response = sendPostRequest(this.tokenUrl, gson.toJson(request));
            JsonObject jsonResponse = gson.fromJson(response, JsonObject.class);

            if (!jsonResponse.has("access_token")) {
                throw new KubeToGoogleIdTokenException("STS response does not contain access_token.");
            }

            return jsonResponse.get("access_token").getAsString();
        } catch (KubeToGoogleIdTokenException e) {
            throw e;
        } catch (Exception e) {
            throw new KubeToGoogleIdTokenException("Failed to exchange Kubernetes token with STS.", e);
        }
    }

    String generateIdentityToken(String accessToken, String audience) {
        GoogleIdentityTokenRequest request = GoogleIdentityTokenRequest.builder()
                .audience(audience)
                .includeEmail(true)
                .build();

        try {
            String response = sendPostRequest(this.serviceAccountImpersonationUrl, gson.toJson(request), accessToken);
            JsonObject jsonResponse = gson.fromJson(response, JsonObject.class);

            if (!jsonResponse.has("token")) {
                throw new KubeToGoogleIdTokenException("IAM Credentials response does not contain token.");
            }

            return jsonResponse.get("token").getAsString();
        } catch (KubeToGoogleIdTokenException e) {
            throw e;
        } catch (Exception e) {
            throw new KubeToGoogleIdTokenException("Failed to generate ID token using IAM Credentials API.", e);
        }
    }

    String sendPostRequest(String urlStr, String payload) {
        return sendPostRequest(urlStr, payload, null);
    }

    HttpURLConnection createConnection(String urlStr) throws IOException {
        URL url = new URL(urlStr);
        return (HttpURLConnection) url.openConnection();
    }

    String sendPostRequest(String urlStr, String payload, String accessToken) {
        try {
            HttpURLConnection conn = createConnection(urlStr);
            conn.setRequestMethod("POST");
            conn.setDoOutput(true);
            conn.setRequestProperty("Content-Type", "application/json");

            if (accessToken != null && !accessToken.isEmpty()) {
                conn.setRequestProperty("Authorization", "Bearer " + accessToken);
            }

            try (OutputStream os = conn.getOutputStream()) {
                os.write(payload.getBytes());
                os.flush();
            }

            int responseCode = conn.getResponseCode();
            if (responseCode != HttpURLConnection.HTTP_OK) {
                throw new KubeToGoogleIdTokenException("HTTP request failed with response code: " + responseCode);
            }

            try (BufferedReader in = new BufferedReader(new InputStreamReader(conn.getInputStream()))) {
                StringBuilder response = new StringBuilder();
                String inputLine;
                while ((inputLine = in.readLine()) != null) {
                    response.append(inputLine);
                }
                return response.toString();
            }
        } catch (KubeToGoogleIdTokenException e) {
            throw e;
        } catch (IOException e) {
            throw new KubeToGoogleIdTokenException("HTTP request to " + urlStr + " failed.", e);
        }
    }
}
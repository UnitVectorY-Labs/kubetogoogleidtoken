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
import java.nio.file.Paths;

/**
 * Client for generating Google ID tokens from a Kubernetes service account
 * token.
 * 
 * @author Jared Hatfield (UnitVectorY Labs)
 */
@Getter(AccessLevel.PACKAGE)
@Builder
public class KubeToGoogleIdTokenClient {

    private static final String STS_URL = "https://sts.googleapis.com/v1/token";
    private static final String IAM_URL_TEMPLATE = "https://iamcredentials.googleapis.com/v1/projects/-/serviceAccounts/%s:generateIdToken";

    private final String k8sTokenPath;
    private final String projectNumber;
    private final String workloadIdentityPool;
    private final String workloadProvider;
    private final String serviceAccountEmail;

    private final Gson gson = new Gson();

    /**
     * Generates an ID token for the specified audience.
     *
     * @param request The KubeToGoogleIdTokenRequest containing the audience.
     * @return The IdTokenResponse containing the ID token.
     * @throws Exception If any step in the token generation process fails.
     */
    public KubeToGoogleIdTokenResponse getIdToken(KubeToGoogleIdTokenRequest request) throws Exception {
        if (request == null || request.getAudience() == null || request.getAudience().isEmpty()) {
            throw new IllegalArgumentException("Audience must be specified in the IdTokenRequest.");
        }

        // TODO: Failures should really throw a KubeToGoogleIdTokenException

        // Phase 1: Retrieve Kubernetes Token
        String k8sToken = retrieveKubernetesToken();

        // Phase 2: Exchange Kubernetes Token for Access Token via STS
        String stsAudience = String.format(
                "//iam.googleapis.com/projects/%s/locations/global/workloadIdentityPools/%s/providers/%s",
                projectNumber, workloadIdentityPool, workloadProvider);
        String accessToken = exchangeTokenWithSTS(k8sToken, stsAudience);

        // Phase 3: Generate Identity Token via IAM Credentials
        String idToken = generateIdentityToken(accessToken, request.getAudience());

        return KubeToGoogleIdTokenResponse.builder()
                .idToken(idToken)
                .build();
    }

    /**
     * Reads the Kubernetes token from the specified file path.
     *
     * @return The Kubernetes token as a String.
     * @throws IOException If reading the file fails.
     */
    private String retrieveKubernetesToken() throws IOException {
        return Files.readString(Paths.get(k8sTokenPath));
    }

    /**
     * Exchanges the Kubernetes token for an access token using STS.
     *
     * @param subjectToken The Kubernetes token.
     * @param audience     The audience for the STS request.
     * @return The access token.
     * @throws IOException If the HTTP request fails.
     */
    private String exchangeTokenWithSTS(String subjectToken, String audience) throws IOException {
        JsonObject stsRequest = new JsonObject();
        stsRequest.addProperty("grant_type", "urn:ietf:params:oauth:grant-type:token-exchange");
        stsRequest.addProperty("audience", audience);
        stsRequest.addProperty("scope", "https://www.googleapis.com/auth/cloud-platform");
        stsRequest.addProperty("requested_token_type", "urn:ietf:params:oauth:token-type:access_token");
        stsRequest.addProperty("subject_token_type", "urn:ietf:params:oauth:token-type:jwt");
        stsRequest.addProperty("subject_token", subjectToken);

        String response = sendPostRequest(STS_URL, stsRequest.toString(), null);
        JsonObject jsonResponse = gson.fromJson(response, JsonObject.class);

        if (!jsonResponse.has("access_token")) {
            throw new IOException("STS response does not contain access_token.");
        }

        return jsonResponse.get("access_token").getAsString();
    }

    /**
     * Generates an ID token using the IAM Credentials API.
     *
     * @param accessToken The access token obtained from STS.
     * @param audience    The audience for which the ID token is requested.
     * @return The ID token.
     * @throws IOException If the HTTP request fails.
     */
    private String generateIdentityToken(String accessToken, String audience) throws IOException {
        String iamUrl = String.format(IAM_URL_TEMPLATE, serviceAccountEmail);

        JsonObject iamRequest = new JsonObject();
        iamRequest.addProperty("audience", audience);
        iamRequest.addProperty("includeEmail", true);

        String response = sendPostRequest(iamUrl, iamRequest.toString(), accessToken);
        JsonObject jsonResponse = gson.fromJson(response, JsonObject.class);

        if (!jsonResponse.has("token")) {
            throw new IOException("IAM Credentials response does not contain token.");
        }

        return jsonResponse.get("token").getAsString();
    }

    /**
     * Sends a POST request to the specified URL with the given payload and access
     * token.
     *
     * @param urlStr      The URL to send the request to.
     * @param payload     The JSON payload as a String.
     * @param accessToken The access token for authorization (nullable).
     * @return The response body as a String.
     * @throws IOException If the HTTP request fails.
     */
    private String sendPostRequest(String urlStr, String payload, String accessToken) throws IOException {
        URL url = new URL(urlStr);
        HttpURLConnection conn = (HttpURLConnection) url.openConnection();
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
        InputStreamReader isr;
        if (responseCode >= 200 && responseCode < 300) {
            isr = new InputStreamReader(conn.getInputStream());
        } else {
            isr = new InputStreamReader(conn.getErrorStream());
        }

        try (BufferedReader in = new BufferedReader(isr)) {
            String inputLine;
            StringBuilder response = new StringBuilder();
            while ((inputLine = in.readLine()) != null) {
                response.append(inputLine);
            }
            if (responseCode < 200 || responseCode >= 300) {
                throw new IOException("HTTP " + responseCode + ": " + response.toString());
            }
            return response.toString();
        }
    }
}
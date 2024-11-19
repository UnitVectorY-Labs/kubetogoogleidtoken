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
     * Generates a GCP ID token for the specified audience.
     *
     * @param request The KubeToGoogleIdTokenRequest containing the audience.
     * @return The IdTokenResponse containing the ID token.
     * @throws KubeToGoogleIdTokenException If any step in the token generation
     *                                      process fails.
     * @throws IllegalArgumentException     If the audience is not specified.
     */
    public KubeToGoogleIdTokenResponse getIdToken(KubeToGoogleIdTokenRequest request) {
        if (request == null || request.getAudience() == null || request.getAudience().isEmpty()) {
            throw new IllegalArgumentException("Audience must be specified in the IdTokenRequest.");
        }

        // Phase 1: Retrieve Kubernetes Token from the file system
        String k8sToken = retrieveKubernetesToken();

        // Phase 2: Exchange Kubernetes Token for Access Token via STS
        String stsAudience = String.format(
                "//iam.googleapis.com/projects/%s/locations/global/workloadIdentityPools/%s/providers/%s",
                projectNumber, workloadIdentityPool, workloadProvider);
        String accessToken = exchangeTokenWithSTS(k8sToken, stsAudience);

        // Phase 3: Generate Identity Token via IAM Credentials by GCP Impersonating
        // Service Account
        String idToken = generateIdentityToken(accessToken, request.getAudience());

        return KubeToGoogleIdTokenResponse.builder().idToken(idToken).build();
    }

    private String retrieveKubernetesToken() {
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

    private String exchangeTokenWithSTS(String subjectToken, String audience) {
        JsonObject stsRequest = new JsonObject();
        stsRequest.addProperty("grant_type", "urn:ietf:params:oauth:grant-type:token-exchange");
        stsRequest.addProperty("audience", audience);
        stsRequest.addProperty("scope", "https://www.googleapis.com/auth/cloud-platform");
        stsRequest.addProperty("requested_token_type", "urn:ietf:params:oauth:token-type:access_token");
        stsRequest.addProperty("subject_token_type", "urn:ietf:params:oauth:token-type:jwt");
        stsRequest.addProperty("subject_token", subjectToken);

        try {
            String response = sendPostRequest(STS_URL, stsRequest.toString(), null);
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

    private String generateIdentityToken(String accessToken, String audience) {
        String iamUrl = String.format(IAM_URL_TEMPLATE, serviceAccountEmail);

        JsonObject iamRequest = new JsonObject();
        iamRequest.addProperty("audience", audience);
        iamRequest.addProperty("includeEmail", true);

        try {
            String response = sendPostRequest(iamUrl, iamRequest.toString(), accessToken);
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

    private String sendPostRequest(String urlStr, String payload, String accessToken) {
        try {
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
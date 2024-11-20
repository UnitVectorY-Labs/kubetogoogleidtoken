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

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.mockito.ArgumentCaptor;
import org.mockito.Mockito;

import com.google.gson.Gson;
import com.unitvectory.jsonassertify.JSONAssert;

import java.nio.file.Files;
import java.nio.file.Path;
import java.io.ByteArrayInputStream;
import java.net.HttpURLConnection;
import java.io.OutputStream;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.fail;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * Test class for KubeToGoogleIdTokenClient.
 * 
 * @author Jared Hatfield (UnitVectorY Labs)
 */
class KubeToGoogleIdTokenClientTest {

    private static final Gson gson = new Gson();

    private KubeToGoogleIdTokenClient client;

    private Path tokenPath;

    @BeforeEach
    void setUp(@TempDir Path tempDir) {
        // Generate a fake token file in the temp directory for testing
        this.tokenPath = tempDir.resolve("foo");

        // Set the contents of the token file
        try {
            Files.writeString(tokenPath, "fake-token");
        } catch (Exception e) {
            fail("Failed to write token file");
        }

        client = KubeToGoogleIdTokenClient.builder()
                .k8sTokenPath(tokenPath.toAbsolutePath().toString())
                .projectNumber("0000000000")
                .workloadIdentityPool("my-pool")
                .workloadProvider("my-provider")
                .serviceAccountEmail("fake@example.com").build();
    }

    @Test
    void testClientConstruction() {
        assertEquals(tokenPath.toAbsolutePath().toString(), client.getK8sTokenPath());
        assertEquals(
                "//iam.googleapis.com/projects/0000000000/locations/global/workloadIdentityPools/my-pool/providers/my-provider",
                client.getStsAudience());
        assertEquals("https://sts.googleapis.com/v1/token", client.getTokenUrl());
        assertEquals(
                "https://iamcredentials.googleapis.com/v1/projects/-/serviceAccounts/fake@example.com:generateIdToken",
                client.getServiceAccountImpersonationUrl());
    }

    @Test
    void testRetrieveKubernetesToken() throws Exception {
        Files.writeString(tokenPath, "fake-token");

        String token = client.retrieveKubernetesToken();
        assertEquals("fake-token", token);

        Files.delete(tokenPath);
    }

    @Test
    void testExchangeTokenWithSTS() throws Exception {
        KubeToGoogleIdTokenClient spyClient = Mockito.spy(client);

        ArgumentCaptor<String> urlCaptor = ArgumentCaptor.forClass(String.class);
        ArgumentCaptor<String> payloadCaptor = ArgumentCaptor.forClass(String.class);

        doReturn("{\"access_token\":\"fake-access-token\"}").when(spyClient).sendPostRequest(
                urlCaptor.capture(),
                payloadCaptor.capture());

        String accessToken = spyClient.exchangeTokenWithSTS("fake-token", "fake-audience");
        assertEquals("fake-access-token", accessToken);

        assertEquals("https://sts.googleapis.com/v1/token", urlCaptor.getValue());

        GoogleAccessTokenRequest expectedTokenRequest = GoogleAccessTokenRequest.builder()
                .grantType("urn:ietf:params:oauth:grant-type:token-exchange")
                .audience("fake-audience")
                .scope("https://www.googleapis.com/auth/cloud-platform")
                .requestedTokenType("urn:ietf:params:oauth:token-type:access_token")
                .subjectTokenType("urn:ietf:params:oauth:token-type:jwt")
                .subjectToken("fake-token")
                .build();

        JSONAssert.assertEquals(gson.toJson(expectedTokenRequest), payloadCaptor.getValue(), true);
    }

    @Test
    void testExchangeTokenWithSTSNoToken() throws Exception {
        KubeToGoogleIdTokenClient spyClient = Mockito.spy(client);
        doReturn("{}").when(spyClient).sendPostRequest(anyString(),
                anyString());

        KubeToGoogleIdTokenException thrown = assertThrows(KubeToGoogleIdTokenException.class, () -> {
            spyClient.exchangeTokenWithSTS("fake-token", "fake-audience");
        });
        assertEquals("STS response does not contain access_token.", thrown.getMessage());
    }

    @Test
    void testGenerateIdentityToken() throws Exception {
        KubeToGoogleIdTokenClient spyClient = Mockito.spy(client);

        ArgumentCaptor<String> urlCaptor = ArgumentCaptor.forClass(String.class);
        ArgumentCaptor<String> payloadCaptor = ArgumentCaptor.forClass(String.class);
        ArgumentCaptor<String> accessTokenCaptor = ArgumentCaptor.forClass(String.class);

        doReturn("{\"token\":\"fake-id-token\"}").when(spyClient).sendPostRequest(
                urlCaptor.capture(),
                payloadCaptor.capture(),
                accessTokenCaptor.capture());

        String idToken = spyClient.generateIdentityToken("fake-access-token", "fake-audience");
        assertEquals("fake-id-token", idToken);

        assertEquals(
                "https://iamcredentials.googleapis.com/v1/projects/-/serviceAccounts/fake@example.com:generateIdToken",
                urlCaptor.getValue());
        GoogleIdentityTokenRequest expectedTokenRequest = GoogleIdentityTokenRequest.builder()
                .audience("fake-audience")
                .includeEmail(true)
                .build();

        JSONAssert.assertEquals(gson.toJson(expectedTokenRequest), payloadCaptor.getValue(), true);
        assertEquals("fake-access-token", accessTokenCaptor.getValue());
    }

    @Test
    void testGenerateIdentityTokenNoToken() throws Exception {
        KubeToGoogleIdTokenClient spyClient = Mockito.spy(client);
        doReturn("{}").when(spyClient).sendPostRequest(anyString(), anyString(),
                anyString());

        KubeToGoogleIdTokenException thrown = assertThrows(KubeToGoogleIdTokenException.class, () -> {
            spyClient.generateIdentityToken("fake-access-token", "fake-audience");
        });
        assertEquals("IAM Credentials response does not contain token.", thrown.getMessage());
    }

    @Test
    void testSendPostRequest() throws Exception {
        KubeToGoogleIdTokenClient spyClient = Mockito.spy(client);
        HttpURLConnection mockConnection = mock(HttpURLConnection.class);
        OutputStream mockOutputStream = mock(OutputStream.class);

        doReturn(mockConnection).when(spyClient).createConnection(anyString());
        when(mockConnection.getResponseCode()).thenReturn(HttpURLConnection.HTTP_OK);
        when(mockConnection.getInputStream())
                .thenReturn(new ByteArrayInputStream("{\"token\":\"fake-response\"}".getBytes()));
        doReturn(mockOutputStream).when(mockConnection).getOutputStream();

        String response = spyClient.sendPostRequest("https://example.com", "{\"key\":\"value\"}");
        assertEquals("{\"token\":\"fake-response\"}", response);

        verify(mockConnection).setRequestMethod("POST");
        verify(mockConnection).setDoOutput(true);
        verify(mockConnection).setRequestProperty("Content-Type", "application/json");
        verify(mockOutputStream).write(any(byte[].class));
    }
}

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
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.api.io.TempDir;
import org.mockito.Mockito;

import com.google.gson.Gson;
import com.unitvectory.kubetogoogleidtoken.GoogleConfiguration.CredentialSource;
import com.unitvectory.kubetogoogleidtoken.GoogleConfiguration.CredentialSource.Format;

import uk.org.webcompere.systemstubs.environment.EnvironmentVariables;
import uk.org.webcompere.systemstubs.jupiter.SystemStub;
import uk.org.webcompere.systemstubs.jupiter.SystemStubsExtension;

import java.nio.file.Files;
import java.nio.file.Path;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.fail;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.doReturn;

/**
 * Test class for KubeToGoogleIdTokenClient.
 * 
 * @author Jared Hatfield (UnitVectorY Labs)
 */
@ExtendWith(SystemStubsExtension.class)
class KubeToGoogleIdTokenClientEnvVarTest {

    private static final Gson gson = new Gson();

    @SystemStub
    private EnvironmentVariables environmentVariables = new EnvironmentVariables();

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

        GoogleConfiguration config = GoogleConfiguration.builder()
                .universeDomain("googleapis.com")
                .type("external_account")
                .audience(
                        "//iam.googleapis.com/projects/000000000000/locations/global/workloadIdentityPools/my-identity-pool/providers/my-provider")
                .subjectTokenType("urn:ietf:params:oauth:token-type:jwt")
                .tokenUrl("https://sts.googleapis.com/v1/token")
                .serviceAccountImpersonationUrl(
                        "https://iamcredentials.googleapis.com/v1/projects/-/serviceAccounts/account@example.iam.gserviceaccount.com:generateAccessToken")
                .credentialSource(CredentialSource.builder()
                        .file(tokenPath.toAbsolutePath().toString())
                        .format(Format.builder().type("text").build())
                        .build())
                .build();

        // Write the config json file to the temp directory
        Path configPath = tempDir.resolve("config.json");
        try {
            Files.writeString(configPath, gson.toJson(config));
        } catch (Exception e) {
            fail("Failed to write config file");
        }

        environmentVariables.set("GOOGLE_APPLICATION_CREDENTIALS", configPath.toAbsolutePath().toString());
    }

    @Test
    void testClientConstruction() {

        KubeToGoogleIdTokenClient client = KubeToGoogleIdTokenClient.builder()
                .k8sTokenPath(tokenPath.toAbsolutePath().toString()).build();

        assertEquals(tokenPath.toAbsolutePath().toString(), client.getK8sTokenPath());
        assertEquals(
                "//iam.googleapis.com/projects/000000000000/locations/global/workloadIdentityPools/my-identity-pool/providers/my-provider",
                client.getStsAudience());
        assertEquals("https://sts.googleapis.com/v1/token", client.getTokenUrl());
        assertEquals(
                "https://iamcredentials.googleapis.com/v1/projects/-/serviceAccounts/account@example.iam.gserviceaccount.com:generateIdToken",
                client.getServiceAccountImpersonationUrl());
    }

    @Test
    void testGetIdToken() {
        KubeToGoogleIdTokenClient client = KubeToGoogleIdTokenClient.builder()
                .k8sTokenPath(tokenPath.toAbsolutePath().toString()).build();

        KubeToGoogleIdTokenClient spyClient = Mockito.spy(client);
        doReturn("{\"access_token\":\"fake-access-token\"}").when(spyClient).sendPostRequest(anyString(),
                anyString());
        doReturn("{\"token\":\"fake-access-token\"}").when(spyClient).sendPostRequest(anyString(),
                anyString(), anyString());

        KubeToGoogleIdTokenResponse response = spyClient
                .getIdToken(KubeToGoogleIdTokenRequest.builder().audience("https://example.com").build());
        assertNotNull(response);
        assertEquals("fake-access-token", response.getIdToken());
    }

    @Test
    void testGetIdTokenNullAudience() {
        KubeToGoogleIdTokenClient client = KubeToGoogleIdTokenClient.builder()
                .k8sTokenPath(tokenPath.toAbsolutePath().toString()).build();

        IllegalArgumentException thrown = assertThrows(IllegalArgumentException.class, () -> {
            client.getIdToken(null);
        });
        assertEquals("Audience must be specified in the IdTokenRequest.", thrown.getMessage());
    }

    @Test
    void testGetIdTokenMissingAudience() {
        KubeToGoogleIdTokenClient client = KubeToGoogleIdTokenClient.builder()
                .k8sTokenPath(tokenPath.toAbsolutePath().toString()).build();

        IllegalArgumentException thrown = assertThrows(IllegalArgumentException.class, () -> {
            client.getIdToken(KubeToGoogleIdTokenRequest.builder().build());
        });
        assertEquals("Audience must be specified in the IdTokenRequest.", thrown.getMessage());
    }

    @Test
    void testGetIdTokenEmptyAudience() {
        KubeToGoogleIdTokenClient client = KubeToGoogleIdTokenClient.builder()
                .k8sTokenPath(tokenPath.toAbsolutePath().toString()).build();

        IllegalArgumentException thrown = assertThrows(IllegalArgumentException.class, () -> {
            client.getIdToken(KubeToGoogleIdTokenRequest.builder().audience("").build());
        });
        assertEquals("Audience must be specified in the IdTokenRequest.", thrown.getMessage());
    }
}

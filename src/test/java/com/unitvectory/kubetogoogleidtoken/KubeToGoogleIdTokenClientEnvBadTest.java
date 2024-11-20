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

import uk.org.webcompere.systemstubs.environment.EnvironmentVariables;
import uk.org.webcompere.systemstubs.jupiter.SystemStub;
import uk.org.webcompere.systemstubs.jupiter.SystemStubsExtension;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.fail;

import java.nio.file.Files;
import java.nio.file.Path;

/**
 * Test class for KubeToGoogleIdTokenClient.
 * 
 * @author Jared Hatfield (UnitVectorY Labs)
 */
@ExtendWith(SystemStubsExtension.class)
class KubeToGoogleIdTokenClientEnvBadTest {

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

        // Write the config json file to the temp directory
        Path configPath = tempDir.resolve("config.json");
        try {
            // Writing an empty JSON file to test the failure mode code paths
            Files.writeString(configPath, "{}");
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
                "//iam.googleapis.com/projects/null/locations/global/workloadIdentityPools/null/providers/null",
                client.getStsAudience());
        assertEquals("https://sts.googleapis.com/v1/token", client.getTokenUrl());
        assertEquals(
                "https://iamcredentials.googleapis.com/v1/projects/-/serviceAccounts/null:generateIdToken",
                client.getServiceAccountImpersonationUrl());
    }
}

[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0) [![Active](https://img.shields.io/badge/Status-Active-green)](https://guide.unitvectorylabs.com/bestpractices/status/#active) [![codecov](https://codecov.io/gh/UnitVectorY-Labs/kubetogoogleidtoken/graph/badge.svg?token=DvVSkrR8zW)](https://codecov.io/gh/UnitVectorY-Labs/kubetogoogleidtoken)

# kubetogoogleidtoken

A Java library for obtaining Google ID tokens by leveraging Kubernetes Service Accounts with GCP Workload Identity Federation.

## Getting Started

This library requires Java 17 and is available in the Maven Central Repository:

```xml
<dependency>
    <groupId>com.unitvectory</groupId>
    <artifactId>kubetogoogleidtoken</artifactId>
    <version>0.1.0</version>
</dependency>
```

## Usage

The library provides a client that can be used to obtain Google ID tokens. The client requires the following parameters:

```java
public static void main(String[] args) {
    KubeToGoogleIdTokenClient client = KubeToGoogleIdTokenClient.builder()
            .k8sTokenPath("/path/to/token")
            .projectNumber("000000000000")
            .workloadIdentityPool("my-identity-pool")
            .workloadProvider("my-provider")
            .serviceAccountEmail("account@example.iam.gserviceaccount.com")
            .build();

    KubeToGoogleIdTokenRequest request = KubeToGoogleIdTokenRequest.builder().audience("https://example.com").build();
    KubeToGoogleIdTokenResponse response = client.getIdToken(request);
    System.out.println(response.getIdToken());
}
```

## Configuration

When using Kubernetes with GCP Workload Identity Federation, the following configuration format is typically used. Instead of explicitely providing the configuration attributes those can be 

```java
KubeToGoogleIdTokenClient client = KubeToGoogleIdTokenClient.builder().build();
```

The path to the following JSON file can be provided with the `GOOGLE_APPLICATION_CREDENTIALS` environment variable.

```json
{
    "universe_domain": "googleapis.com",
    "type": "external_account",
    "audience": "//iam.googleapis.com/projects/000000000000/locations/global/workloadIdentityPools/my-identity-pool/providers/my-provider",
    "subject_token_type": "urn:ietf:params:oauth:token-type:jwt",
    "token_url": "https://sts.googleapis.com/v1/token",
    "credential_source": {
        "file": "/var/run/secrets/tokens/gcp-token",
        "format": {
            "type": "text"
        }
    },
    "service_account_impersonation_url": "https://iamcredentials.googleapis.com/v1/projects/-/serviceAccounts/account@example.iam.gserviceaccount.com:generateAccessToken"
}
```

One important note is that the `service_account_impersonation_url` is going to be set to call `:generateAccessToken` by default, but the use case here is for ID Tokens, therefore this client will automatically change that to `:generateIdToken` before making the request.

## Limitations

- Token caching is not implemented. The client will request a new token for each invocation. It is recommended to cache the token in the application.
- Custom audiences for Workload Identity Federation are not supported. The default audience pattern of `//iam.googleapis.com/projects/{PROJECT_NUMBER}/locations/global/workloadIdentityPools/{WORKLOAD_IDENTITY_POOL}/providers/{WORKLOAD_PROVIDER}` is used.

[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0) [![Active](https://img.shields.io/badge/Status-Active-green)](https://guide.unitvectorylabs.com/bestpractices/status/#active)

# kubetogoogleidtoken

A Java library for obtaining Google ID tokens by leveraging Kubernetes Service Accounts with GCP Workload Identity Federation.

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

## Limitations

- Token caching is not implemented. The client will request a new token for each invocation. It is recommended to cache the token in the application.

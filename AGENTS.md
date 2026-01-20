# Instructions for Agents

This file contains essential instructions for working with the `DualTokenApi` repository in this environment.

## Environment Setup & Installation

The environment runs on a Linux distribution with OpenSSL 3.0 and the .NET 6 SDK. The project targets `.netcoreapp3.1`. To ensure `.NET` commands function correctly without globalization errors, you **must** set the following environment variable in every session:

```bash
export DOTNET_SYSTEM_GLOBALIZATION_INVARIANT=1
```

## Build and Verification

1.  **SDK Mismatch**: The project targets `netcoreapp3.1`, but the environment uses the .NET 6 SDK.
2.  **Running the App**: To run or test the application in this environment, you may need to temporarily change the `TargetFramework` in `DualTokenApi.csproj` from `netcoreapp3.1` to `net6.0`.
3.  **Final Deliverable**: You **must** revert the `TargetFramework` back to `netcoreapp3.1` before submitting your changes. The user strictly requires the project to remain on .NET Core 3.1.

## Codebase Constraints

### Authorization
-   **DualSchemeAuthorizeAttribute**: Do not replace this attribute with standard `[Authorize]` attributes.
-   **Logic**: The `DualSchemeAuthorizeAttribute` implements `IAuthorizationFilter` to enforce specific rules:
    -   **SchemeA (Login)**: Requires validation of both the **User** (identity existence) and **Role**.
    -   **SchemeB (Service)**: Requires validation of the **Role** only.
-   **Scheme Detection**: `Startup.cs` explicitly sets `AuthenticationType` to "SchemeA" and "SchemeB" in `TokenValidationParameters` to allow the attribute to detect the scheme correctly. Do not remove this configuration.

### Signing Key Service
-   **Rotation**: `SigningKeyService` must implement "lazy" rotation. It checks for rotation logic in both `GetCurrentKey` (signing) and `GetValidationKeys` (validating) to ensure keys rotate even if no new tokens are being issued.
-   **Resources**: Ensure `RandomNumberGenerator` is properly disposed of using `using` statements.

### Authentication Flows
-   **Login (SchemeA)**: `POST /auth/login` with `LoginModel` (Username/Password).
-   **Service (SchemeB)**: `POST /auth/service-token` with `ServiceKeyModel` (ApiKey).

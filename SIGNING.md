# Signing: what the owner must provide

Nothing here is faked. Without these items the build script and CI produce clearly named `-unsigned` artifacts,
which are fine for lab testing and will not install cleanly on managed fleets.

## Windows (credential provider DLL, `atlas-enroll.exe`, `atlas-sync.exe`, MSI)

A credential provider is loaded by LogonUI into a protected process, and enterprise
fleets enforce Smart App Control / WDAC / AppLocker. Unsigned or untrusted binaries are
blocked.

1. **An Authenticode code-signing certificate**, ideally Extended Validation (EV), from a
   public CA (DigiCert, Sectigo, GlobalSign, SSL.com), issued to the company that publishes
   the agent. An OV certificate works but triggers SmartScreen reputation warnings on the
   MSI until reputation builds. Since June 2023 the private key must live on a hardware
   token or HSM (FIPS 140-2 L2 / EV requirement), so you cannot export it to a `.pfx`.
   Options: (a) a cloud HSM signing service (Azure Trusted Signing, DigiCert KeyLocker,
   SSL.com eSigner) and run signing in CI with that service's action; (b) a token on a
   self-hosted runner. A `.pfx` path (secrets `ATLAS_SIGN_PFX_BASE64`, `ATLAS_SIGN_PFX_PASSWORD`)
   works only for certificates that still allow export.
2. **A timestamp server URL** (RFC 3161), e.g. the CA's. Default in the scripts:
   `http://timestamp.digicert.com`.
3. **The same certificate signs the MSI and every PE file inside it** (DLL, both EXEs).
4. (Optional but recommended) Microsoft attestation signing is NOT needed for a user-mode
   credential provider; it is needed only for kernel drivers.
5. Customers using WDAC must add your publisher certificate to their allow-list; give them
   the certificate thumbprint.

### GitHub Actions secrets used by the release workflow

| Secret | Content |
|---|---|
| `ATLAS_SIGN_PFX_BASE64`, `ATLAS_SIGN_PFX_PASSWORD` | exportable Authenticode certificate (or use a cloud-signing action instead) |

Plan to test on: Windows 10 22H2 and Windows 11 23H2/24H2, with and without TPM, Secure Boot, Smart App Control,
Credential Guard and BitLocker; domain-joined and Entra-joined. The unit tests cover protocol and cryptography only.

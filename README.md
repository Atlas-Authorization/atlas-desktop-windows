# Atlas Login Agent for Windows

A Windows credential provider that adds a second factor to workstation sign-in and unlock, driven by an
Atlas instance. It wraps the stock Windows password provider: the user types their password as usual, then the
Atlas step runs (push approval with number matching, an authenticator code, or an offline code), and the
password serialization is released to Windows only after the step succeeds.

> **Status: the portable core is tested; the Windows provider has never been compiled or run.**
> `src/provider` was written without a Windows toolchain at hand. It stays untested on Windows until the
> `windows` CI job and a hands-on test on a throwaway VM have run. Do not roll it out to real machines before then.

## What is in the box

| Piece | Where | Notes |
|---|---|---|
| `atlas_core` | `src/core`, `include/atlas` | Portable C++17: protocol client, signed messages, offline bundle (MAC check, ECIES open), PIN (scrypt), TOTP, offline unlock state machine, config parsing, `LoginGate`. No Windows APIs. Builds and tests on Linux, macOS and Windows. |
| `atlas_credential_provider.dll` | `src/provider/provider.cpp` | COM credential provider wrapping `{60b78e88-ead8-445c-9cfd-0b87f74ea6cd}`. UI glue only. |
| `atlas-enroll.exe` | `src/provider/enroll_main.cpp` | One-time enrolment (creates the device key, calls `enroll`, writes the config and secrets). |
| `atlas-sync.exe` | `src/provider/sync_main.cpp` | Refreshes policy and the offline bundle, uploads queued offline events. Run by a scheduled task. |
| Installer | `installer/` | WiX v4 MSI, `build.ps1`, registry helpers, rollback notes. |

The wire protocol is in [PROTOCOL.md](PROTOCOL.md). The unit tests reproduce the reference vectors in
`testdata/protocol-vectors.json` (sealed bundle, bundle MAC, scrypt PIN verifier, TOTP codes, signed message).

## Architecture

```
LogonUI -> AtlasProvider (wraps the stock password provider)
             -> AtlasCredential per user tile (wraps the stock credential, + 6 extra fields)
                  -> LoginGate (atlas_core)  --  Client (WinHTTP)  --  Atlas instance
                                              \- OfflineVault (DPAPI) \- CngDeviceKey (TPM or software KSP)
```

Sign-in flow: password typed, Enter -> `GetSerialization` runs `LoginGate::begin()` (a short best-effort sync,
then the decision). Not required: the stock serialization is returned. Required: the tile shows the Atlas fields,
a push is started automatically (the number to match is displayed large), a poll thread checks every 2 seconds,
and the user can instead type a code or choose "Use offline code". When the gate is satisfied the user presses
Enter again and only then is the stock serialization returned. A failed logon resets the gate.

Platform pieces behind interfaces (`IDeviceKey`, `IHttpClient`, `ISecretStore`, `IClock`): CNG key (TPM
"Microsoft Platform Crypto Provider", falling back to the software KSP), WinHTTP (HTTPS only, short timeouts),
DPAPI machine-scope files in `%ProgramData%\Atlas\secrets` restricted to SYSTEM and Administrators.

### Fail-closed rules (enforced in `atlas_core`, covered by tests)

- A PC whose last good sync said "required" never signs in without a factor, online or offline.
- Never synced: refused unless installed with `FAIL_OPEN_WHEN_NEVER_SYNCED=1`.
- Server unreachable: only the cached policy and a valid offline bundle count. No bundle, expired bundle,
  clock moved back more than 5 minutes, or 5 wrong attempts (15 minute lock, persisted) all refuse.
- A revoked device (`403`, `device_status: revoked`) has its offline bundle wiped and is refused.
- Offline codes are single use per 30 second step (replay refused).
- A bundle whose MAC does not verify is never stored or opened.
- Enrolled but with a broken config or missing device key: refused with a message. Not enrolled / no config: stock behaviour.
- Passkeys: `unsupported_in_this_build` unless a WebAuthn handler is injected into `LoginGate`.

## Build and test

Portable core (any OS, OpenSSL 3, CMake 3.21+; GoogleTest and nlohmann/json are fetched at pinned versions if not installed):

```sh
cmake -S . -B build -DATLAS_BUILD_PROVIDER=OFF          # add -DOPENSSL_ROOT_DIR=... if OpenSSL is not found
cmake --build build -j2
ctest --test-dir build --output-on-failure
```

Windows (Visual Studio 2022, vcpkg with `VCPKG_ROOT` set; the manifest installs OpenSSL, GoogleTest, nlohmann-json):

```powershell
cmake --preset windows-msvc-x64
cmake --build --preset windows-msvc-x64
ctest --preset windows-msvc-x64
```

MSI (needs the WiX v4 dotnet tool): `installer\build.ps1 -Version 0.1.0`. Signing happens only if
`ATLAS_SIGN_CERT_THUMBPRINT`, or `ATLAS_SIGN_PFX` and `ATLAS_SIGN_PFX_PASSWORD`, are set (timestamp server:
`ATLAS_SIGN_TIMESTAMP_URL`). Otherwise the output is named `AtlasLoginAgent-<version>-unsigned.msi`.

## Install

```powershell
msiexec /i AtlasLoginAgent-0.1.0.msi INSTANCE_URL=https://auth.example.com PUBLISHABLE_KEY=pk_live_... INSTANCE_ID=ins_... /qn
atlas-enroll.exe          # elevated; prompts for the enrolment code and the offline PIN (no echo)
```

Optional properties: `FAIL_OPEN_WHEN_NEVER_SYNCED=1`, `EXCLUDE_STOCK_PROVIDER=1` (read the next section first).
Files go to `%ProgramFiles%\Atlas\LoginAgent`; config to `%ProgramData%\Atlas\config.json`; a scheduled task
`Atlas\LoginAgentSync` (boot, hourly, network change) runs `atlas-sync.exe` as SYSTEM.
`atlas-enroll.exe --show-otp-uri` prints the authenticator URI once if the user wants offline codes in an app.

## Kill switch and rollback

`HKLM\SOFTWARE\Atlas\LoginAgent`, value `Disabled` (DWORD) = `1` turns the provider into a pure pass-through to the
stock password provider. Details, Safe Mode behaviour, the break-glass options and what happens if the DLL fails to
load are in [installer/ROLLBACK.md](installer/ROLLBACK.md). Short version: keep the stock password tile available
(the default) until you have proven the kill switch on a test PC.

## Signing

Release binaries need an Authenticode code-signing certificate (EV preferred, private key on an HSM or token, so
usually a cloud signing service rather than a `.pfx`), a timestamp server, and the same certificate for the MSI and
the DLL and EXEs inside it. See [SIGNING.md](SIGNING.md). Customers using WDAC allow-list your publisher certificate.
Unsigned builds are named `-unsigned` and are for lab use.

## Security notes

- Two device keys are created, non-exportable, machine scope: an ECDSA P-256 signing key and an ECDH P-256 seal key.
  The public half of the seal key is sent at enrolment as `seal_public_key`, and the server then seals offline
  bundles to it. Each key uses the TPM when available, otherwise the software KSP, and `atlas-enroll` says which.
  Their labels are stored in `config.json` (`device_key_id`, `seal_key_id`).
- The bundle MAC key and the sealed offline bundle are DPAPI machine-scope blobs. Machine scope means any
  process on the PC can decrypt them, so the folder ACL (SYSTEM + Administrators) is the real boundary.
- Secrets (codes, PINs, number matches, bundles, keys) are never logged.
- With the stock tile left in place (default) a user can bypass the Atlas step by choosing it. Excluding it is
  a deliberate trade-off against lockout risk, see the rollback notes.
- The second factor is checked before Windows validates the password, so a wrong password can still trigger a push.
- Unsigned binaries run, but signed MSI/DLL is strongly recommended and required under WDAC/HVCI policies.

## Known gaps and what is unverified

- Everything under `src/provider` and `installer/` has not been compiled or run on Windows.
- Whether the TPM provider accepts a persisted ECDH P-256 key on every device; the software KSP is the fallback.
- `BCRYPT_KDF_RAW_SECRET` output is little-endian; the code reverses it to the big-endian X coordinate the
  protocol needs. Verify against a real sealed bundle on hardware.
- The provider updates fields from a background thread (push polling). Confirm LogonUI tolerates this on all
  supported builds.
- Passkey (WebAuthn) sign-in is not implemented.
- Offline events and attempt counters are plain read-modify-write on a file; concurrent writers (sync task and
  sign-in screen at the same moment) are not serialised across processes.

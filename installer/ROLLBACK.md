# Rollback and safe mode

The Atlas credential provider wraps the stock password provider. It is built so a failure of the Atlas
side cannot lock an administrator out, as long as the stock sign-in path is still available.

## Kill switch (fastest)

Set `HKLM\SOFTWARE\Atlas\LoginAgent` value `Disabled` (DWORD) to `1`. The next time the sign-in screen
loads, the provider returns the stock password credentials unchanged: no Atlas fields, no second factor.
Import `kill-switch-on.reg` (and `kill-switch-off.reg` to resume), or:

    reg add HKLM\SOFTWARE\Atlas\LoginAgent /v Disabled /t REG_DWORD /d 1 /f

A repair of the MSI does not reset a value that is already present.

## When the provider itself will not load

1. Leave `EXCLUDE_STOCK_PROVIDER` at its default `0` until you have signed in successfully with the
   provider on a test PC. With `0` the stock password tile stays available beside the Atlas tile, so a broken
   DLL costs you the Atlas step, not the machine. The price: a user can choose the stock tile and skip the
   Atlas step. Turn `EXCLUDE_STOCK_PROVIDER=1` on (it sets the policy value
   `HKLM\SOFTWARE\Policies\Microsoft\Windows\System\ExcludedCredentialProviders`) only for PCs where that
   bypass is not acceptable, and only after the kill switch is proven to work.
2. Credential providers from third parties are not loaded in Safe Mode. If the stock provider has NOT been
   excluded, boot to Safe Mode and sign in normally, then uninstall or set the kill switch.
3. If the stock provider HAS been excluded and the DLL fails to load, nothing can sign in: boot Windows
   Recovery, open a command prompt, load the `SYSTEM`/`SOFTWARE` hives and delete the value
   `ExcludedCredentialProviders` (or the Atlas CLSID under `Credential Providers`).

## Local administrator bypass

There is no built-in bypass account: a bypass that the product knows about is a bypass an attacker can use.
Use one of these, decided by your policy owner:

- keep a break-glass local administrator on a PC that is not enrolled (no `config.json`, or `enrolled: false`)
  and so signs in with the stock behaviour;
- or use the kill switch above from a Safe Mode / recovery session, with the action logged by your endpoint tooling.

## Fail-closed behaviour to know about

- An enrolled PC whose config is corrupt or whose device key is missing refuses sign-in (message on the screen);
  use the kill switch or reinstall.
- A PC that has never synced refuses sign-in unless it was installed with `FAIL_OPEN_WHEN_NEVER_SYNCED=1`.
- A PC with no `config.json` or `enrolled: false` behaves exactly like stock Windows.

## Uninstall

Uninstalling removes the files, the COM registration, the Credential Providers entry, the policy exclusion
(if the installer set it) and the sync task. `%ProgramData%\Atlas` (config and DPAPI-protected secrets) and the
device key are left in place; delete the folder and the CNG key named
`AtlasLoginAgent-<instance id>` if you want them gone.

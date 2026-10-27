# Rollback, safe mode and break glass

The Atlas credential provider wraps the stock password provider, and an `ICredentialProviderFilter` in the same DLL
hides the stock password-type tiles (password, picture password, PIN) so the Atlas step cannot be bypassed by picking
a different tile. Both are built so that an Atlas failure cannot lock an administrator out.

## Why the filter is fail-safe

- The filter lives in the provider DLL. If the DLL does not load, is deleted, or its registration is removed,
  nothing is hidden and the stock tiles come back. There is no separate policy setting that could outlive the DLL.
- The filter hides stock only while ALL of these hold: the kill switch is not set, this PC is enrolled and the agent
  loads cleanly, the Atlas provider is itself in the provider list for that sign-in, and the cached policy from the last
  good sync says MFA is required. With no cached state at all, stock stays visible unless the config has
  `"fail_closed_hide": true` (MSI: `FAIL_CLOSED_HIDE=1`) or a valid offline bundle is held.
- The stock password, picture-password and PIN-logon tiles are hidden; Windows Hello for Business stays (it is device-bound two-factor already) unless `"hide_windows_hello": true`.
- Only sign-in and unlock are filtered. UAC / CredUI and password change keep the stock tile.
- Hello biometrics (face, fingerprint) and smart cards are not hidden: they are strong factors of their own.

## Kill switch (fastest)

Set `HKLM\SOFTWARE\Atlas\LoginAgent` value `Disabled` (DWORD) to `1`. The next time the sign-in screen loads the
filter hides nothing and the provider returns the stock credentials unchanged. Import `kill-switch-on.reg` (and
`kill-switch-off.reg` to resume), or:

    reg add HKLM\SOFTWARE\Atlas\LoginAgent /v Disabled /t REG_DWORD /d 1 /f

A repair of the MSI does not reset a value that is already present.

## Break-glass local administrator

A documented local administrator that skips the Atlas step on this PC, for when the Atlas service, the network or the
second factor is unavailable. It is only usable through the Atlas tile (the stock tile is hidden), and the Atlas
provider hands it the stock path without a second factor.

1. Create it: run `create-break-glass.ps1` elevated (default name `AtlasBreakGlass`). It generates a random
   password, prints it once, and makes the account a local administrator. Use a different password per PC.
2. Vault the password immediately in your secrets manager, with access restricted to the people allowed to use it.
   Rotate it after every use.
3. Declare it: install with `BREAK_GLASS_ACCOUNTS=AtlasBreakGlass`, or add it to `break_glass_accounts` in
   `%ProgramData%\Atlas\config.json`. The default list is empty, so nothing is exempt until you list it. A bare name
   matches only a LOCAL account of that name; write `DOMAIN\name` to name a domain account.
4. Audit it: every sign-in attempt by a break-glass account writes event id 100 (Warning, source
   `AtlasLoginAgent`, Application log) with the account name. Forward it and alert on it.
   Its password is still the only thing protecting it, so treat the vaulted password as the most sensitive secret here.

## When the provider itself will not load

Nothing is hidden, so the stock tile is there: sign in normally and set the kill switch or uninstall. Credential
providers from third parties are not loaded in Safe Mode either, so Safe Mode always gives you the stock tile.
If you ever suspect a stale filter registration, delete
`HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\Credential Provider Filters\{C3B1A0E6-6D1F-4B0E-9C57-2F1B7A9D4E58}`
(offline, from Windows Recovery, if needed) - without the filter the stock tiles return.

## Fail-closed behaviour to know about

- Atlas runs only after the typed password has been verified locally. A wrong password gets the normal "incorrect
  password" message and never triggers a sync or a push. If the password cannot be checked (for example no domain
  controller and no cached credentials), sign-in is refused with a message.
- An enrolled PC whose config is corrupt or whose signing or seal key is missing refuses sign-in (message on the
  screen); the filter then hides nothing, so use the stock tile, the kill switch or reinstall.
- A PC that has never synced refuses sign-in unless it was installed with `FAIL_OPEN_WHEN_NEVER_SYNCED=1`.
- A PC with no `config.json` or `enrolled: false` behaves exactly like stock Windows.

## Uninstall

Uninstalling removes the files, the COM registration, the Credential Providers and Filters entries, the event source
and the sync task. `%ProgramData%\Atlas` (config and DPAPI-protected secrets) and the device keys are left in place;
delete the folder and the CNG keys named `AtlasLoginAgent-<instance id>` and `AtlasLoginAgent-seal-<instance id>` if
you want them gone. The break-glass account is not removed.

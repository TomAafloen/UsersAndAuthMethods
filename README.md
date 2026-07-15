# Entra ID MFA Method Deprecation Tooling

PowerShell tooling for safely deprecating less secure MFA methods in a large Microsoft Entra ID tenant without disrupting existing users.

> **Read-only:** The scripts only read data from your Entra ID tenant (user registration details and sign-in logs). Nothing is created, modified, or deleted in Entra ID. All output is written to local files only.

## How it works

The strategy relies on Entra ID's **Authentication Methods Policy inclusion groups**:

1. Identify which users have already registered a target method (e.g., SMS).
2. Place those users in an Entra ID group.
3. Set the Authentication Methods Policy to allow that method **only for that group**.
4. Result: Existing users are unaffected. New users and users who never registered the method cannot enroll going forward.

This is safer than a block/exclusion list because new users would not appear on an exclusion list until manually added — they would be able to register the weak method in the interim.

## Prerequisites

```powershell
# Install the Microsoft Graph PowerShell SDK (once)
Install-Module Microsoft.Graph -Scope CurrentUser
```

**Required Graph scope (delegated):** `AuditLog.Read.All`

**Required Entra ID role:** The signed-in account must hold one of:
- Reports Reader
- Security Reader
- Security Administrator
- Authentication Administrator
- Global Administrator

> If you see a **403 Forbidden / RequestFromUnsupportedUserRole** error, your account is missing one of the roles above. The scope alone is not sufficient.

## Usage

There is one script. It automatically fetches registration data from Graph when needed, then generates the HTML report and CSV exports.

### Basic usage

```powershell
.\New-MfaMethodReport.ps1 -TargetMethod mobilePhone
```

On first run (or when the cache is older than 7 days), the script opens a browser window to sign in to Microsoft Graph, collects all user registration data (~3–8 minutes for 200k users), and generates the report.

Each data collection run creates a timestamped subfolder under `reports\` (e.g. `reports\2026-06-01_1532\`). All CSVs and the HTML report go into that folder. Re-running for a different method on the same day reuses the cache and writes into the same folder:

```powershell
# Generates reports\2026-06-01_1532\report-mobilePhone.html (collects data)
.\New-MfaMethodReport.ps1 -TargetMethod mobilePhone

# Generates reports\2026-06-01_1532\report-softwareOneTimePasscode.html (reuses cache — instant)
.\New-MfaMethodReport.ps1 -TargetMethod softwareOneTimePasscode
```

### Forcing a data refresh

```powershell
.\New-MfaMethodReport.ps1 -TargetMethod mobilePhone -ForceRefresh
```

This creates a new timestamped subfolder with fresh data — the previous folder is preserved for comparison.

### Changing the cache expiry

```powershell
.\New-MfaMethodReport.ps1 -TargetMethod mobilePhone -CacheMaxAgeDays 14
```

### Output files

Each run creates a timestamped subfolder, e.g. `reports\2026-06-01_1532\`:

| File | Purpose |
|------|---------|
| `report-{method}.html` | Static HTML dashboard — open in any browser |
| `users-{method}-registered.csv` | All users (Members + Guests) with target method registered |
| `users-{method}-registered-members.csv` | ✅ **Action item** — populate Entra inclusion group (Members only) |
| `users-{method}-registered-guests.csv` | Guests with method registered — review and handle separately |
| `users-{method}-only.csv` | ⚠️ At-risk — this is their only second factor; migrate before disabling |
| `users-{method}-safe-to-block.csv` | 🟢 Safe to remove from inclusion group (prefer a stronger method) |
| `users-no-mfa.csv` | 🔴 No MFA registered at all — address via Conditional Access |
| `users-full-export.csv` | Full reference export, all users and methods |

The cache file (`reports\raw-registrations.json`) stays at the top level and is shared across runs.

> The HTML report links to CSV files using relative paths. Keep all files in the same subfolder, or open the HTML directly from the timestamped folder.

### Why separate Members and Guests?

**Members** (internal users) can be required to register a stronger method and migrated through a communication campaign or Conditional Access policy. Populate your inclusion group from `users-{method}-registered-members.csv`.

**Guests** (external collaborators) may not have the option to register all methods. Disabling a method for guests without coordination can block their access. Use `users-{method}-registered-guests.csv` to review the guest population and handle separately.

## Supported methods

| `-TargetMethod` value | Friendly name | Strength tier |
|-----------------------|---------------|---------------|
| `mobilePhone` | SMS OTP | Weak |
| `alternateMobilePhone` | Alt. Mobile (SMS) | Weak |
| `officePhone` | Office Phone | Weak |
| `email` | Email OTP | Weak |
| `softwareOneTimePasscode` | Software OATH / TOTP | Adequate |
| `hardwareOneTimePasscode` | Hardware OATH Token | Adequate |
| `temporaryAccessPass` | Temporary Access Pass | Adequate |
| `microsoftAuthenticatorPush` | Authenticator App (Push) | Strong |
| `microsoftAuthenticatorPasswordless` | Authenticator (Passwordless) | Strong |
| `fido2SecurityKey` | FIDO2 Security Key | Strong |
| `windowsHelloForBusiness` | Windows Hello for Business | Strong |

## Recommended rollout sequence

### Phase 1 — Block new enrollments (zero disruption)

1. Run `New-MfaMethodReport.ps1` for the target method.
2. Create a new Entra ID security group (e.g., `MFA - SMS Registered Members`).
3. Import `users-{method}-registered-members.csv` into the group (via portal, PowerShell, or CSV import).
4. Create a second group for guests if needed (`MFA - SMS Registered Guests`) using `users-{method}-registered-guests.csv`.
5. In **Entra ID → Security → Authentication Methods → Policies**, set the target method to **Enabled for selected groups** and target the group(s) you created.

New users and users who never registered the method are now blocked from enrolling. Existing users are unaffected.

### Phase 2 — Migrate at-risk users

Use `users-{method}-only.csv` to identify users for whom the method is their only second factor. Run a targeted communication campaign directing them to [aka.ms/mysecurityinfo](https://aka.ms/mysecurityinfo) to register the Microsoft Authenticator app before the method is disabled.

Consider using a **Conditional Access policy** with an Authentication Strength requirement to nudge these users before a deadline.

### Phase 3 — Full deprecation

Once `users-{method}-only.csv` is empty (or an acceptable residual), disable the method entirely by removing the policy group or setting the method to **Disabled**.

### Parallel effort — No-MFA users

`users-no-mfa.csv` contains users with zero MFA registered. Enforce MFA registration via a Conditional Access policy targeting this group.

## Tracking progress over time

Re-run the script monthly (use `-ForceRefresh` to get fresh data). Each run creates a new dated folder — keep the old folders to compare `users-{method}-only.csv` counts over time. The shrinking size of that file is your primary migration KPI.

## Troubleshooting

### 403 Forbidden / RequestFromUnsupportedUserRole

Your account is missing a required role. Activate one of these in PIM before running: Reports Reader, Security Reader, Security Administrator, Authentication Administrator, or Global Administrator.

### Sign-in browser does not open / sign-in fails

The script opens a pop-up browser window via the Microsoft Graph PowerShell SDK. If this fails (e.g. in headless environments or terminals without browser integration), use the `-AccessToken` parameter to bypass interactive sign-in:

```powershell
# Get a token from Azure Cloud Shell or any terminal with az CLI:
$token = (az account get-access-token --resource https://graph.microsoft.com | ConvertFrom-Json).accessToken
.\New-MfaMethodReport.ps1 -TargetMethod mobilePhone -AccessToken $token
```

The token is valid for ~1 hour. If the script fails with 401 mid-run, obtain a fresh token and re-run. The cache is never written on failure, so no data is lost.

### Token expired mid-run

Tokens expire after ~1 hour. For large tenants where collection takes close to an hour, this can happen near the end. Re-run with a fresh token — the script resumes from a clean state (no partial caches are written).

## Other scripts

- **`Get-AuthMethodRegistrations.ps1`** — standalone data collection only. Useful if you want to separate the fetch step, schedule it, or save the cache to a custom path.
- **`Get-SignInActivity.ps1`** — diagnostic tool for querying sign-in logs. Note: Microsoft currently does not populate the per-method MFA fields in the Graph sign-in log list endpoint; this script is retained for future use.

## Notes

- The `reports\` folder is git-ignored to avoid committing potentially sensitive user data.
- The HTML report requires internet access to load Chart.js and Bootstrap from CDN.
- Graph API may throttle requests for very large tenants. The collection handles this gracefully.

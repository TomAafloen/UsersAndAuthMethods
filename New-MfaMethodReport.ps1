<#
.SYNOPSIS
    All-in-one MFA method report: collects registration data from Entra ID (if needed),
    then generates an HTML dashboard and targeted CSV exports for a specified method.

.DESCRIPTION
    Registration data is cached in $OutputDir\raw-registrations.json and reused across
    runs. A fresh fetch from the Graph API is triggered automatically when the cache is
    missing or older than -CacheMaxAgeDays (default: 7). Use -ForceRefresh to force an
    immediate update.

    Each run produces a timestamped subfolder under $OutputDir (e.g. reports\2026-06-01_1532)
    based on when the registration data was collected. Running the script again for a
    different method on the same day reuses the same cache and writes into the same subfolder.

    For a given target method (e.g. SMS, Software OATH), the script produces:

      - users-{method}-registered.csv          : All users who have registered the method.
                                                 Use this to populate an Entra ID inclusion
                                                 group. Set the Authentication Methods Policy
                                                 to allow the method ONLY for this group —
                                                 blocking new enrollments without disrupting
                                                 existing users.

      - users-{method}-registered-members.csv  : Members-only subset of the above.
      - users-{method}-registered-guests.csv   : Guests-only subset.

      - users-{method}-only.csv                : Users for whom this is their ONLY second
                                                 factor. Disabling the method for them would
                                                 break MFA. Migrate these users first.

      - users-{method}-safe-to-block.csv       : Users who have the method registered but
                                                 are using a portable stronger alternative
                                                 as their preferred MFA method.
                                                 "Portable" means the alternative works on
                                                 any device (e.g. Authenticator push/
                                                 passwordless). Device-bound methods such
                                                 as Windows Hello for Business, FIDO2 keys,
                                                 and passkeys do NOT qualify — a user with
                                                 only WHfB as their strong alternative cannot
                                                 authenticate from a phone or shared device
                                                 if SMS is disabled.
                                                 Safe to remove from the inclusion group.

      - users-no-mfa.csv                       : Users with no MFA at all.
      - users-full-export.csv                  : All users with all methods (reference).
      - report-{method}.html                   : Self-contained HTML dashboard with charts.

.PARAMETER TargetMethod
    The internal Graph API method key to analyze. Use tab-completion to see valid values.
    Example: mobilePhone, softwareOneTimePasscode

.PARAMETER OutputDir
    Base directory for all output. A timestamped subfolder is created here for each
    data collection run. Defaults to .\reports.

.PARAMETER AccessToken
    A bearer token for Microsoft Graph. Only needed when interactive sign-in fails.
    See the Troubleshooting section in README.md for when and how to use this.

.PARAMETER CacheMaxAgeDays
    Maximum age of the cached registration data in days before a refresh is triggered.
    Defaults to 7. Set to 0 to always fetch fresh data.

.PARAMETER ForceRefresh
    Forces a fresh fetch from the Graph API even if the cache is current.

.EXAMPLE
    # Generate a report for SMS — connects to Graph on first run, uses cache after that
    .\New-MfaMethodReport.ps1 -TargetMethod mobilePhone

    # Generate a report for a different method — reuses the same cache (instant)
    .\New-MfaMethodReport.ps1 -TargetMethod softwareOneTimePasscode

    # Force a fresh data collection
    .\New-MfaMethodReport.ps1 -TargetMethod mobilePhone -ForceRefresh

.NOTES
    Required Entra role: Reports Reader, Security Reader, Security Administrator,
                         Authentication Administrator, or Global Administrator
    Required Graph scope: AuditLog.Read.All (delegated)
    Required module:      Microsoft.Graph.Authentication
                          (only when -AccessToken is not provided)
    Install:              Install-Module Microsoft.Graph -Scope CurrentUser

    Data collection takes 3–8 minutes for ~200,000 users. The cache allows multiple
    method analyses without re-fetching. The HTML report requires internet access to
    load Chart.js and Bootstrap from CDN.
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [ValidateSet(
        'mobilePhone',
        'alternateMobilePhone',
        'officePhone',
        'email',
        'softwareOneTimePasscode',
        'hardwareOneTimePasscode',
        'microsoftAuthenticatorPush',
        'microsoftAuthenticatorPasswordless',
        'fido2SecurityKey',
        'windowsHelloForBusiness',
        'temporaryAccessPass'
    )]
    [string]$TargetMethod,

    [string]$OutputDir = ".\reports",

    # Bearer token for Microsoft Graph. Only needed when interactive sign-in fails.
    # See README.md troubleshooting section for details.
    [string]$AccessToken = "",

    # Re-fetch registration data from Graph when the cache is older than this many days.
    [int]$CacheMaxAgeDays = 7,

    # Force a fresh fetch from Graph even if the cache is still current.
    [switch]$ForceRefresh
)

Add-Type -AssemblyName System.Web

# ---------------------------------------------------------------------------
# Method definitions — add new entries here to extend support for more methods
# ---------------------------------------------------------------------------
$methodMap = @{
    'mobilePhone'                        = @{ Label = 'SMS OTP';                       Tier = 'Weak';     Color = '#dc3545'; DeviceBound = $false }
    'alternateMobilePhone'               = @{ Label = 'Alt. Mobile (SMS)';             Tier = 'Weak';     Color = '#fd7e14'; DeviceBound = $false }
    'officePhone'                        = @{ Label = 'Office Phone';                  Tier = 'Weak';     Color = '#fd7e14'; DeviceBound = $false }
    'email'                              = @{ Label = 'Email OTP';                     Tier = 'Weak';     Color = '#ffc107'; DeviceBound = $false }
    'softwareOneTimePasscode'            = @{ Label = 'Software OATH / TOTP';          Tier = 'Adequate'; Color = '#0dcaf0'; DeviceBound = $false }
    'hardwareOneTimePasscode'            = @{ Label = 'Hardware OATH Token';           Tier = 'Adequate'; Color = '#0dcaf0'; DeviceBound = $false }
    'temporaryAccessPass'                = @{ Label = 'Temporary Access Pass';         Tier = 'Adequate'; Color = '#6f42c1'; DeviceBound = $false }
    'microsoftAuthenticatorPush'         = @{ Label = 'Authenticator App (Push)';      Tier = 'Strong';   Color = '#198754'; DeviceBound = $false }
    'microsoftAuthenticatorPasswordless' = @{ Label = 'Authenticator (Passwordless)';  Tier = 'Strong';   Color = '#198754'; DeviceBound = $false }
    # Device-bound: tied to specific hardware — not a safe fallback if the target method is blocked
    # (user may be unable to authenticate from a phone, shared machine, or after hardware loss)
    'fido2SecurityKey'                   = @{ Label = 'FIDO2 Security Key';            Tier = 'Strong';   Color = '#0d6efd'; DeviceBound = $true }
    'windowsHelloForBusiness'            = @{ Label = 'Windows Hello for Business';    Tier = 'Strong';   Color = '#0d6efd'; DeviceBound = $true }
    'passKeyDeviceBound'                 = @{ Label = 'Passkey (Device-bound)';        Tier = 'Strong';   Color = '#0d6efd'; DeviceBound = $true }
    'passKeyDeviceBoundAuthenticator'    = @{ Label = 'Passkey (Authenticator)';       Tier = 'Strong';   Color = '#0d6efd'; DeviceBound = $true }
}

# Maps each method to the userPreferredMethodForSecondaryAuthentication value(s) that indicate
# the user is actively choosing that method as their MFA second factor.
# An empty array means we cannot infer usage from preference data alone.
$methodToPreferredValues = @{
    'mobilePhone'                        = @('sms', 'voiceMobile')
    'alternateMobilePhone'               = @('voiceAlternateMobile')
    'officePhone'                        = @('voiceOffice')
    'email'                              = @('email')
    'softwareOneTimePasscode'            = @('oath')
    'hardwareOneTimePasscode'            = @('oath')
    'microsoftAuthenticatorPush'         = @('push')
    'microsoftAuthenticatorPasswordless' = @('microsoftAuthenticatorPasswordless')
    'fido2SecurityKey'                   = @()
    'windowsHelloForBusiness'            = @()
    'temporaryAccessPass'                = @()
}

# Tier ordering used to find "better" alternatives when computing safe-to-block.
$tierRank = @{ None = 0; Weak = 1; Adequate = 2; Strong = 3 }

# NOTE ON SAFE-TO-BLOCK LOGIC
# We use userPreferredMethodForSecondaryAuthentication as a proxy for actual usage.
# This field reflects the user's chosen default second factor. Combined with the DeviceBound
# flag above, we require that the "better alternative" be a portable method — one that works
# across all devices and scenarios, not just on a specific enrolled machine.
#
# WHY NOT SIGN-IN LOGS:
# The Microsoft Graph sign-in log list endpoint does not return authenticationDetails
# (which field shows which MFA method was used). It is explicitly documented as
# "not returned from the list method" and returns 400 Unsupported Query when selected.
# Individual sign-in record GETs do include it, but querying 80k+ users individually
# is not feasible. The preference-based approach with device-bound exclusion is the
# practical alternative and directly addresses the device-binding concern.

if (-not $methodMap.ContainsKey($TargetMethod)) {
    $methodMap[$TargetMethod] = @{ Label = $TargetMethod; Tier = 'Unknown'; Color = '#6c757d' }
}

$targetLabel           = $methodMap[$TargetMethod].Label
$methodKey             = $TargetMethod -replace '[^a-zA-Z0-9]', '-'
$targetTierRank        = $tierRank[$methodMap[$TargetMethod].Tier]
$targetPreferredValues = if ($methodToPreferredValues.ContainsKey($TargetMethod)) { $methodToPreferredValues[$TargetMethod] } else { @() }
$canComputeSafeToBlock = $targetPreferredValues.Count -gt 0

# ---------------------------------------------------------------------------
# Ensure output directory exists and determine cache path
# ---------------------------------------------------------------------------
if (-not (Test-Path $OutputDir)) {
    New-Item -ItemType Directory -Path $OutputDir -Force | Out-Null
}

$cachePath = Join-Path $OutputDir "raw-registrations.json"

# ---------------------------------------------------------------------------
# Step 1: Collect registration data from Graph (if cache is missing or stale)
# ---------------------------------------------------------------------------
$needsFetch = $ForceRefresh -or
              -not (Test-Path $cachePath) -or
              ((Get-Date) - (Get-Item $cachePath).LastWriteTime).TotalDays -gt $CacheMaxAgeDays

if ($needsFetch) {
    $reason = if ($ForceRefresh) { "-ForceRefresh specified" }
              elseif (-not (Test-Path $cachePath)) { "cache not found" }
              else {
                  $ageHours = [math]::Round(((Get-Date) - (Get-Item $cachePath).LastWriteTime).TotalHours, 1)
                  "cache is ${ageHours}h old (limit: ${CacheMaxAgeDays}d)"
              }
    Write-Host "Fetching registration data from Graph API ($reason)..." -ForegroundColor Cyan

    $useDirectRest = [bool]$AccessToken
    if ($useDirectRest) {
        Write-Host "  Using provided access token (direct REST)..." -ForegroundColor Gray
        $headers = @{ Authorization = "Bearer $AccessToken" }
    } else {
        if (-not (Get-Module -ListAvailable -Name Microsoft.Graph.Authentication)) {
            throw "Microsoft.Graph.Authentication module not found. Install with: Install-Module Microsoft.Graph -Scope CurrentUser`nAlternatively, pass -AccessToken with a bearer token from az CLI."
        }
        Import-Module Microsoft.Graph.Authentication -ErrorAction Stop
        Write-Host "  Connecting to Microsoft Graph (browser sign-in)..." -ForegroundColor Gray
        Connect-MgGraph -Scopes "AuditLog.Read.All", "Reports.Read.All" -NoWelcome
    }

    $allUsers  = [System.Collections.Generic.List[object]]::new()
    $pageSize  = 999
    $uri       = "https://graph.microsoft.com/v1.0/reports/authenticationMethods/userRegistrationDetails?`$top=$pageSize"
    $pageCount = 0
    $startTime = Get-Date

    do {
        try {
            if ($useDirectRest) {
                $response = Invoke-RestMethod -Uri $uri -Headers $headers -Method GET
            } else {
                $response = Invoke-MgGraphRequest -Uri $uri -Method GET -OutputType PSObject
            }
        }
        catch {
            # Do not save partial data — an incomplete user list would cause real users
            # to be excluded from the inclusion group and lose access to their method.
            if ($_ -match '403|Forbidden|RequestFromUnsupportedUserRole') {
                throw @"
Access denied (403). Your account lacks the required Entra ID role for this report.
The signed-in user must hold one of:
  - Reports Reader
  - Security Reader
  - Security Administrator
  - Authentication Administrator
  - Global Administrator

If using PIM, ensure the role is activated and obtain a fresh token after activation:
  `$token = (az account get-access-token --resource https://graph.microsoft.com | ConvertFrom-Json).accessToken
"@
            }
            if ($_ -match '401|Unauthorized|InvalidAuthenticationToken') {
                throw "Access token expired on page ${pageCount} after collecting $($allUsers.Count) users. No file written. Obtain a fresh token and re-run."
            }
            throw "Graph API error on page ${pageCount} after collecting $($allUsers.Count) users. No file written. $_"
        }

        foreach ($user in $response.value) {
            $allUsers.Add($user)
        }

        $pageCount++
        $elapsed = (Get-Date) - $startTime
        $rate    = if ($elapsed.TotalSeconds -gt 0) { [math]::Round($allUsers.Count / $elapsed.TotalSeconds) } else { 0 }
        Write-Progress -Activity "Collecting user registration data" `
            -Status "$($allUsers.Count) users | Page $pageCount | $rate users/sec" `
            -PercentComplete -1

        $uri = $response.'@odata.nextLink'
    } while ($uri)

    Write-Progress -Activity "Collecting user registration data" -Completed

    $elapsed = (Get-Date) - $startTime
    Write-Host ("  Collected {0} users in {1:N1} min ({2} pages)" -f $allUsers.Count, $elapsed.TotalMinutes, $pageCount) -ForegroundColor White
    Write-Host "  Saving cache to $cachePath..." -ForegroundColor Gray
    $allUsers | ConvertTo-Json -Depth 5 | Set-Content -Path $cachePath -Encoding UTF8
    Write-Host ""
} else {
    $cacheAge = [math]::Round(((Get-Date) - (Get-Item $cachePath).LastWriteTime).TotalHours, 1)
    Write-Host ("Using cached data ({0}h old, max {1}d — use -ForceRefresh to update)" -f $cacheAge, $CacheMaxAgeDays) -ForegroundColor Cyan
}

# ---------------------------------------------------------------------------
# Step 2: Load data
# ---------------------------------------------------------------------------
Write-Host "Loading data from $cachePath..." -ForegroundColor Cyan
$raw        = [System.IO.File]::ReadAllText((Resolve-Path $cachePath)) | ConvertFrom-Json
$totalUsers = @($raw).Count
Write-Host "  Loaded $totalUsers users" -ForegroundColor White

if ($totalUsers -eq 0) {
    Write-Error "No users found in $cachePath. Re-run with -ForceRefresh."
    exit 1
}

# ---------------------------------------------------------------------------
# Derive per-run output subfolder from the cache timestamp
# Each data collection run gets its own dated folder (e.g. reports\2026-06-01_1532).
# Multiple method analyses on the same cached data share the same folder.
# ---------------------------------------------------------------------------
$cacheTimestamp = (Get-Item $cachePath).LastWriteTime.ToString('yyyy-MM-dd_HHmm')
$runOutputDir   = Join-Path $OutputDir $cacheTimestamp
if (-not (Test-Path $runOutputDir)) {
    New-Item -ItemType Directory -Path $runOutputDir -Force | Out-Null
}
Write-Host "  Output folder: $runOutputDir" -ForegroundColor Gray

# ---------------------------------------------------------------------------
# Compute statistics
# ---------------------------------------------------------------------------
Write-Host "Analyzing registration data..." -ForegroundColor Cyan

$methodCounts       = @{}
$tierCounts         = @{ Strong = 0; Adequate = 0; Weak = 0; None = 0 }
$methodCountPerUser = @{}
$comboCounts        = @{}

$targetRegistered = [System.Collections.Generic.List[PSObject]]::new()
$targetOnly       = [System.Collections.Generic.List[PSObject]]::new()
$noMfa            = [System.Collections.Generic.List[PSObject]]::new()

# Member / Guest splits (populated from the same loop)
$targetRegisteredMembers = [System.Collections.Generic.List[PSObject]]::new()
$targetRegisteredGuests  = [System.Collections.Generic.List[PSObject]]::new()
$targetOnlyMembers       = [System.Collections.Generic.List[PSObject]]::new()
$targetOnlyGuests        = [System.Collections.Generic.List[PSObject]]::new()
$noMfaMembers            = [System.Collections.Generic.List[PSObject]]::new()
$noMfaGuests             = [System.Collections.Generic.List[PSObject]]::new()

# Safe to block: users who have the target method registered but actively prefer a stronger method.
# Computed from userPreferredMethodForSecondaryAuthentication in registration data — no sign-in
# logs required. Empty when $canComputeSafeToBlock is false (method has no known preference mapping).
$safeToBlock        = [System.Collections.Generic.List[PSObject]]::new()
$safeToBlockMembers = [System.Collections.Generic.List[PSObject]]::new()
$safeToBlockGuests  = [System.Collections.Generic.List[PSObject]]::new()

foreach ($user in $raw) {
    # Null-safe: @($null).Count is 1, which would miscount a user with no methods.
    $methods = if ($user.methodsRegistered) { @($user.methodsRegistered) } else { @() }

    # Method count histogram
    $cnt = $methods.Count
    if (-not $methodCountPerUser.ContainsKey($cnt)) { $methodCountPerUser[$cnt] = 0 }
    $methodCountPerUser[$cnt]++

    # Per-method counts
    foreach ($m in $methods) {
        if (-not $methodCounts.ContainsKey($m)) { $methodCounts[$m] = 0 }
        $methodCounts[$m]++
    }

    # Method combination
    $comboKey = if ($methods.Count -eq 0) { '(none)' } else { ($methods | Sort-Object) -join ' + ' }
    if (-not $comboCounts.ContainsKey($comboKey)) { $comboCounts[$comboKey] = 0 }
    $comboCounts[$comboKey]++

    # No MFA
    if ($methods.Count -eq 0) {
        $entry = [PSCustomObject]@{
            UserId            = $user.id
            UserPrincipalName = $user.userPrincipalName
            DisplayName       = $user.userDisplayName
            UserType          = $user.userType
        }
        $noMfa.Add($entry)
        if ($user.userType -ieq 'guest') { $noMfaGuests.Add($entry) } else { $noMfaMembers.Add($entry) }
    }

    # Target method tracking
    if ($methods -contains $TargetMethod) {
        $regEntry = [PSCustomObject]@{
            UserId            = $user.id
            UserPrincipalName = $user.userPrincipalName
            DisplayName       = $user.userDisplayName
            MethodsRegistered = $comboKey
            UserType          = $user.userType
        }
        $targetRegistered.Add($regEntry)
        if ($user.userType -ieq 'guest') { $targetRegisteredGuests.Add($regEntry) } else { $targetRegisteredMembers.Add($regEntry) }
        if ($methods.Count -eq 1) {
            $onlyEntry = [PSCustomObject]@{
                UserId            = $user.id
                UserPrincipalName = $user.userPrincipalName
                DisplayName       = $user.userDisplayName
                UserType          = $user.userType
            }
            $targetOnly.Add($onlyEntry)
            if ($user.userType -ieq 'guest') { $targetOnlyGuests.Add($onlyEntry) } else { $targetOnlyMembers.Add($onlyEntry) }
        }

        # Safe to block: user has the target method but prefers a better, portable alternative.
        # Device-bound methods (WHfB, FIDO2, passkeys) are excluded — a user who only has
        # WHfB as their strong alternative cannot authenticate from a phone or shared computer
        # if SMS is removed, making it unsafe to block.
        if ($canComputeSafeToBlock) {
            $hasBetterAlt = ($methods | Where-Object {
                $_ -ne $TargetMethod -and
                $methodMap.ContainsKey($_) -and
                $tierRank[$methodMap[$_].Tier] -gt $targetTierRank -and
                -not $methodMap[$_].DeviceBound
            }).Count -gt 0

            $pref = $user.userPreferredMethodForSecondaryAuthentication
            $prefersTargetMethod = $pref -and ($targetPreferredValues -contains $pref)

            if ($hasBetterAlt -and -not $prefersTargetMethod) {
                $safeEntry = [PSCustomObject]@{
                    UserId             = $user.id
                    UserPrincipalName  = $user.userPrincipalName
                    DisplayName        = $user.userDisplayName
                    UserType           = $user.userType
                    MethodsRegistered  = $comboKey
                    PreferredMfaMethod = if ($pref) { $pref } else { 'not set' }
                }
                $safeToBlock.Add($safeEntry)
                if ($user.userType -ieq 'guest') { $safeToBlockGuests.Add($safeEntry) } else { $safeToBlockMembers.Add($safeEntry) }
            }
        }
    }

    # Best strength tier for this user
    $userBestTier = 'None'
    foreach ($m in $methods) {
        $tier = if ($methodMap.ContainsKey($m)) { $methodMap[$m].Tier } else { 'Adequate' }
        if     ($tier -eq 'Strong')   { $userBestTier = 'Strong'; break }
        elseif ($tier -eq 'Adequate' -and $userBestTier -ne 'Strong')  { $userBestTier = 'Adequate' }
        elseif ($tier -eq 'Weak'     -and $userBestTier -eq 'None')    { $userBestTier = 'Weak' }
    }
    $tierCounts[$userBestTier]++
}

# ---------------------------------------------------------------------------
# ---------------------------------------------------------------------------
# Export CSVs
# ---------------------------------------------------------------------------
$targetRegisteredCsv        = Join-Path $runOutputDir "users-$methodKey-registered.csv"
$targetRegisteredMembersCsv = Join-Path $runOutputDir "users-$methodKey-registered-members.csv"
$targetRegisteredGuestsCsv  = Join-Path $runOutputDir "users-$methodKey-registered-guests.csv"
$targetOnlyCsv              = Join-Path $runOutputDir "users-$methodKey-only.csv"
$targetOnlyMembersCsv       = Join-Path $runOutputDir "users-$methodKey-only-members.csv"
$targetOnlyGuestsCsv        = Join-Path $runOutputDir "users-$methodKey-only-guests.csv"
$safeToBlockCsv             = Join-Path $runOutputDir "users-$methodKey-safe-to-block.csv"
$safeToBlockMembersCsv      = Join-Path $runOutputDir "users-$methodKey-safe-to-block-members.csv"
$safeToBlockGuestsCsv       = Join-Path $runOutputDir "users-$methodKey-safe-to-block-guests.csv"
$noMfaCsv                   = Join-Path $runOutputDir "users-no-mfa.csv"
$noMfaMembersCsv            = Join-Path $runOutputDir "users-no-mfa-members.csv"
$noMfaGuestsCsv             = Join-Path $runOutputDir "users-no-mfa-guests.csv"
$fullExportCsv              = Join-Path $runOutputDir "users-full-export.csv"

$targetRegistered        | Export-Csv -Path $targetRegisteredCsv        -NoTypeInformation -Encoding UTF8
$targetRegisteredMembers | Export-Csv -Path $targetRegisteredMembersCsv -NoTypeInformation -Encoding UTF8
$targetRegisteredGuests  | Export-Csv -Path $targetRegisteredGuestsCsv  -NoTypeInformation -Encoding UTF8
$targetOnly              | Export-Csv -Path $targetOnlyCsv              -NoTypeInformation -Encoding UTF8
$targetOnlyMembers       | Export-Csv -Path $targetOnlyMembersCsv       -NoTypeInformation -Encoding UTF8
$targetOnlyGuests        | Export-Csv -Path $targetOnlyGuestsCsv        -NoTypeInformation -Encoding UTF8
$noMfa                   | Export-Csv -Path $noMfaCsv                   -NoTypeInformation -Encoding UTF8
$noMfaMembers            | Export-Csv -Path $noMfaMembersCsv            -NoTypeInformation -Encoding UTF8
$noMfaGuests             | Export-Csv -Path $noMfaGuestsCsv             -NoTypeInformation -Encoding UTF8

if ($canComputeSafeToBlock) {
    $safeToBlock        | Export-Csv -Path $safeToBlockCsv        -NoTypeInformation -Encoding UTF8
    $safeToBlockMembers | Export-Csv -Path $safeToBlockMembersCsv -NoTypeInformation -Encoding UTF8
    $safeToBlockGuests  | Export-Csv -Path $safeToBlockGuestsCsv  -NoTypeInformation -Encoding UTF8
}

$raw | Select-Object @{N='UserId';E={$_.id}}, userPrincipalName, userDisplayName, userType, isMfaRegistered,
    @{ N = 'methodsRegistered'; E = { ($_.methodsRegistered | Sort-Object) -join '; ' } },
    defaultMfaMethod |
    Export-Csv -Path $fullExportCsv -NoTypeInformation -Encoding UTF8

Write-Host "  CSVs exported" -ForegroundColor White

# ---------------------------------------------------------------------------
# Build chart data
# ---------------------------------------------------------------------------
$sortedMethods      = $methodCounts.GetEnumerator() | Sort-Object Value -Descending
$chartMethodLabels  = ($sortedMethods | ForEach-Object {
    $lbl = if ($methodMap.ContainsKey($_.Key)) { $methodMap[$_.Key].Label } else { $_.Key }
    "`"$lbl`""
}) -join ','
$chartMethodData    = ($sortedMethods | ForEach-Object { $_.Value }) -join ','
$chartMethodColors  = ($sortedMethods | ForEach-Object {
    $col = if ($methodMap.ContainsKey($_.Key)) { $methodMap[$_.Key].Color } else { '#6c757d' }
    "`"$col`""
}) -join ','

$chartTierData   = "$($tierCounts.Strong),$($tierCounts.Adequate),$($tierCounts.Weak),$($tierCounts.None)"

$sortedHist      = $methodCountPerUser.GetEnumerator() | Sort-Object Key
$chartHistLabels = ($sortedHist | ForEach-Object {
    $s = if ($_.Key -eq 1) { '1 method' } else { "$($_.Key) methods" }
    "`"$s`""
}) -join ','
$chartHistData   = ($sortedHist | ForEach-Object { $_.Value }) -join ','

$topCombos       = $comboCounts.GetEnumerator() | Sort-Object Value -Descending | Select-Object -First 10
$comboTableRows  = ($topCombos | ForEach-Object {
    $pct = [math]::Round($_.Value / $totalUsers * 100, 1)
    "<tr><td class=`"text-break`">$([System.Web.HttpUtility]::HtmlEncode($_.Key))</td><td class=`"text-end`">$($_.Value)</td><td class=`"text-end`">$pct%</td></tr>"
}) -join "`n"

$notRegisteredCount = $totalUsers - $targetRegistered.Count
$timestamp          = Get-Date -Format 'yyyy-MM-dd HH:mm'
$targetPct          = [math]::Round($targetRegistered.Count / $totalUsers * 100, 1)
$notRegPct          = [math]::Round($notRegisteredCount / $totalUsers * 100, 1)
$onlyPct            = [math]::Round($targetOnly.Count / $totalUsers * 100, 1)
$noMfaPct           = [math]::Round($noMfa.Count / $totalUsers * 100, 1)
$safeToBlockPct     = if ($targetRegistered.Count -gt 0) { [math]::Round($safeToBlock.Count / $targetRegistered.Count * 100, 1) } else { 0 }

# ---------------------------------------------------------------------------
# Pre-build conditional HTML sections (resolved before the main here-string)
# ---------------------------------------------------------------------------
$safeToBlockColHeader = if ($canComputeSafeToBlock) { '<th class="text-end">Safe to Block</th>' } else { '' }
$safeToBlockMembersCell = if ($canComputeSafeToBlock) { "<td class=`"text-end text-success fw-bold`">$($safeToBlockMembers.Count)</td>" } else { '' }
$safeToBlockGuestsCell  = if ($canComputeSafeToBlock) { "<td class=`"text-end text-success fw-bold`">$($safeToBlockGuests.Count)</td>" } else { '' }

$memberGuestHtml = @"
  <!-- Member / Guest Breakdown -->
  <div class="row g-3 mb-3">
    <div class="col-12">
      <div class="panel">
        <div class="section-title">Member / Guest Breakdown</div>
        <div class="row align-items-start g-3">
          <div class="col-12 col-lg-7">
            <table class="table table-sm table-hover mb-0">
              <thead class="table-light">
                <tr>
                  <th>User Segment</th>
                  <th class="text-end">$targetLabel Registered</th>
                  <th class="text-end">Only Method</th>
                  <th class="text-end">No MFA</th>
                  $safeToBlockColHeader
                </tr>
              </thead>
              <tbody>
                <tr>
                  <td><span class="badge bg-primary">Members</span></td>
                  <td class="text-end fw-bold">$($targetRegisteredMembers.Count)</td>
                  <td class="text-end text-warning fw-bold">$($targetOnlyMembers.Count)</td>
                  <td class="text-end text-danger fw-bold">$($noMfaMembers.Count)</td>
                  $safeToBlockMembersCell
                </tr>
                <tr>
                  <td><span class="badge bg-secondary">Guests</span></td>
                  <td class="text-end fw-bold">$($targetRegisteredGuests.Count)</td>
                  <td class="text-end text-warning fw-bold">$($targetOnlyGuests.Count)</td>
                  <td class="text-end text-danger fw-bold">$($noMfaGuests.Count)</td>
                  $safeToBlockGuestsCell
                </tr>
              </tbody>
            </table>
          </div>
          <div class="col-12 col-lg-5 text-muted small">
            <strong>Members</strong> are internal users (employees). They can be required to register a stronger
            method and migrated before the target method is disabled.<br><br>
            <strong>Guests</strong> are external collaborators who may not have the option to register all methods.
            Use <code>users-$methodKey-registered-guests.csv</code> to review and handle separately.
          </div>
        </div>
      </div>
    </div>
  </div>
"@

if ($canComputeSafeToBlock) {
    $remainingAfterSafe = $targetRegistered.Count - $safeToBlock.Count
    $safeToBlockHtml = @"
  <!-- Safe to Block -->
  <div class="row g-3 mb-3">
    <div class="col-12">
      <div class="panel" style="border-left:4px solid #198754;">
        <div class="section-title" style="color:#198754;">&#10003; Preferred Method Analysis &#8212; Safe to Block</div>
        <p class="text-muted small mb-3">
          These users have <strong>$targetLabel registered</strong> but their preferred MFA method is a
          <strong>portable, stronger alternative</strong> (e.g. Authenticator push, OATH/TOTP).
          Device-bound methods (Windows Hello for Business, FIDO2 keys, device-bound passkeys) do
          <strong>not</strong> qualify as safe alternatives — they only work on specific hardware and
          would leave users unable to authenticate from other devices if $targetLabel were removed.<br><br>
          Users listed here can safely be removed from the $targetLabel inclusion group — their next
          sign-in will use their portable preferred method.
        </p>
        <div class="d-flex flex-wrap gap-3 align-items-start">
          <div class="kpi-card card bg-success text-white p-3" style="min-width:210px;">
            <div class="kpi-value">$($safeToBlock.Count)</div>
            <div class="fw-semibold mt-1">Safe to Remove from Group</div>
            <div class="kpi-sub">$safeToBlockPct% of $targetLabel-registered users</div>
          </div>
          <div class="text-muted small pt-2">
            <strong>$($safeToBlockMembers.Count)</strong> members &nbsp;·&nbsp; <strong>$($safeToBlockGuests.Count)</strong> guests<br><br>
            After removing safe-to-block users, <strong>$remainingAfterSafe</strong> users
            remain in the inclusion group &mdash; they actively prefer $targetLabel or have no portable alternative registered.<br><br>
            Download <code>users-$methodKey-safe-to-block.csv</code> to action these removals.
          </div>
        </div>
      </div>
    </div>
  </div>
"@
} else {
    $safeToBlockHtml = ""
}

# Downloads table: All | Members | Guests columns × Registered / Only / No MFA / Safe to Block rows
$safeToBlockDownloadsRow = if ($canComputeSafeToBlock) {
    @"
          <tr>
            <td>Safe to Block</td>
            <td><a href="users-$methodKey-safe-to-block.csv" class="btn btn-outline-success btn-sm dl-btn">&#11015; All <span class="badge bg-success ms-1">$($safeToBlock.Count)</span></a></td>
            <td><a href="users-$methodKey-safe-to-block-members.csv" class="btn btn-outline-success btn-sm dl-btn">&#11015; Members <span class="badge bg-success ms-1">$($safeToBlockMembers.Count)</span></a></td>
            <td><a href="users-$methodKey-safe-to-block-guests.csv" class="btn btn-outline-success btn-sm dl-btn">&#11015; Guests <span class="badge bg-success ms-1">$($safeToBlockGuests.Count)</span></a></td>
          </tr>
"@
} else { "" }

$downloadsTableHtml = @"
      <table class="table table-sm table-hover align-middle mb-3">
        <thead class="table-light">
          <tr>
            <th>List</th>
            <th>All Users</th>
            <th>Members</th>
            <th>Guests</th>
          </tr>
        </thead>
        <tbody>
          <tr>
            <td>$targetLabel Registered</td>
            <td><a href="users-$methodKey-registered.csv" class="btn btn-outline-primary btn-sm dl-btn">&#11015; All <span class="badge bg-primary ms-1">$($targetRegistered.Count)</span></a></td>
            <td><a href="users-$methodKey-registered-members.csv" class="btn btn-outline-primary btn-sm dl-btn">&#11015; Members <span class="badge bg-primary ms-1">$($targetRegisteredMembers.Count)</span></a></td>
            <td><a href="users-$methodKey-registered-guests.csv" class="btn btn-outline-secondary btn-sm dl-btn">&#11015; Guests <span class="badge bg-secondary ms-1">$($targetRegisteredGuests.Count)</span></a></td>
          </tr>
          <tr>
            <td>Only Method (at risk)</td>
            <td><a href="users-$methodKey-only.csv" class="btn btn-outline-warning btn-sm dl-btn">&#11015; All <span class="badge bg-warning text-dark ms-1">$($targetOnly.Count)</span></a></td>
            <td><a href="users-$methodKey-only-members.csv" class="btn btn-outline-warning btn-sm dl-btn">&#11015; Members <span class="badge bg-warning text-dark ms-1">$($targetOnlyMembers.Count)</span></a></td>
            <td><a href="users-$methodKey-only-guests.csv" class="btn btn-outline-warning btn-sm dl-btn">&#11015; Guests <span class="badge bg-warning text-dark ms-1">$($targetOnlyGuests.Count)</span></a></td>
          </tr>
          <tr>
            <td>No MFA</td>
            <td><a href="users-no-mfa.csv" class="btn btn-outline-danger btn-sm dl-btn">&#11015; All <span class="badge bg-danger ms-1">$($noMfa.Count)</span></a></td>
            <td><a href="users-no-mfa-members.csv" class="btn btn-outline-danger btn-sm dl-btn">&#11015; Members <span class="badge bg-danger ms-1">$($noMfaMembers.Count)</span></a></td>
            <td><a href="users-no-mfa-guests.csv" class="btn btn-outline-danger btn-sm dl-btn">&#11015; Guests <span class="badge bg-danger ms-1">$($noMfaGuests.Count)</span></a></td>
          </tr>
          $safeToBlockDownloadsRow
        </tbody>
      </table>
      <a href="users-full-export.csv" class="btn btn-outline-dark btn-sm dl-btn">
        &#11015; users-full-export.csv &mdash; all $totalUsers users (full raw export)
      </a>
"@

# ---------------------------------------------------------------------------
# Generate HTML report
# ---------------------------------------------------------------------------
$html = @"
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>MFA Report – $targetLabel</title>
  <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.2/dist/css/bootstrap.min.css" rel="stylesheet">
  <script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.0/dist/chart.umd.min.js"></script>
  <style>
    body { background: #f0f2f5; font-family: system-ui, -apple-system, sans-serif; }
    .kpi-card  { border: none; border-radius: 14px; }
    .kpi-value { font-size: 2.4rem; font-weight: 700; line-height: 1; }
    .kpi-sub   { font-size: 0.78rem; opacity: .8; margin-top: 4px; }
    .panel     { background: white; border-radius: 14px; padding: 1.5rem; box-shadow: 0 1px 4px rgba(0,0,0,.07); }
    .section-title { font-weight: 600; font-size: .9rem; text-transform: uppercase;
                     letter-spacing: .05em; color: #6c757d; margin-bottom: 1rem; }
    .badge-method { font-size: .85rem; background: #e8f0fe; color: #1a56db;
                    border-radius: 20px; padding: 3px 12px; font-weight: 600; }
    .dl-btn { font-size: .8rem; }
    a.dl-btn:hover { text-decoration: none; }
  </style>
</head>
<body>
<div class="container-fluid py-4 px-4" style="max-width: 1400px;">

  <!-- Header -->
  <div class="d-flex flex-wrap align-items-center gap-2 mb-4">
    <div>
      <h1 class="h4 mb-0 fw-bold">MFA Registration Report</h1>
      <div class="text-muted mt-1 small">
        Target method: <span class="badge-method">$targetLabel</span>
        &nbsp;·&nbsp; $timestamp
        &nbsp;·&nbsp; <strong>$totalUsers</strong> total users
      </div>
    </div>
  </div>

  <!-- KPI cards -->
  <div class="row g-3 mb-4">
    <div class="col-6 col-xl-3">
      <div class="kpi-card card bg-primary text-white p-3">
        <div class="kpi-value">$($targetRegistered.Count)</div>
        <div class="fw-semibold mt-1">$targetLabel Registered</div>
        <div class="kpi-sub">$targetPct% of tenant &nbsp;·&nbsp; Populate inclusion group with this list</div>
      </div>
    </div>
    <div class="col-6 col-xl-3">
      <div class="kpi-card card bg-success text-white p-3">
        <div class="kpi-value">$notRegisteredCount</div>
        <div class="fw-semibold mt-1">Never Registered $targetLabel</div>
        <div class="kpi-sub">$notRegPct% &nbsp;·&nbsp; Already excluded from inclusion group — new users safe</div>
      </div>
    </div>
    <div class="col-6 col-xl-3">
      <div class="kpi-card card bg-warning text-dark p-3">
        <div class="kpi-value">$($targetOnly.Count)</div>
        <div class="fw-semibold mt-1">$targetLabel Is Only Method</div>
        <div class="kpi-sub">$onlyPct% &nbsp;·&nbsp; At-risk — migrate before disabling</div>
      </div>
    </div>
    <div class="col-6 col-xl-3">
      <div class="kpi-card card bg-danger text-white p-3">
        <div class="kpi-value">$($noMfa.Count)</div>
        <div class="fw-semibold mt-1">No MFA Registered</div>
        <div class="kpi-sub">$noMfaPct% &nbsp;·&nbsp; Enforce via Conditional Access</div>
      </div>
    </div>
  </div>

$memberGuestHtml

  <!-- Charts row 1 -->
  <div class="row g-3 mb-3">
    <div class="col-12 col-xl-8">
      <div class="panel">
        <div class="section-title">Method Registrations Across Tenant</div>
        <canvas id="methodChart" height="100"></canvas>
      </div>
    </div>
    <div class="col-12 col-xl-4">
      <div class="panel">
        <div class="section-title">MFA Strength Tier Distribution</div>
        <canvas id="tierChart"></canvas>
      </div>
    </div>
  </div>

  <!-- Charts row 2 -->
  <div class="row g-3 mb-3">
    <div class="col-12 col-xl-5">
      <div class="panel">
        <div class="section-title">Method Count per User</div>
        <canvas id="histChart" height="120"></canvas>
      </div>
    </div>
    <div class="col-12 col-xl-7">
      <div class="panel">
        <div class="section-title">Top 10 Method Combinations</div>
        <table class="table table-sm table-hover mb-0">
          <thead class="table-light">
            <tr><th>Methods registered</th><th class="text-end">Users</th><th class="text-end">%</th></tr>
          </thead>
          <tbody>$comboTableRows</tbody>
        </table>
      </div>
    </div>
  </div>

$safeToBlockHtml

  <!-- Downloads -->
  <div class="panel mt-3">
    <div class="section-title">CSV Exports</div>
$downloadsTableHtml  </div>

</div>

<script>
Chart.defaults.font.family = 'system-ui, -apple-system, sans-serif';

new Chart(document.getElementById('methodChart'), {
  type: 'bar',
  data: {
    labels: [$chartMethodLabels],
    datasets: [{
      label: 'Users registered',
      data: [$chartMethodData],
      backgroundColor: [$chartMethodColors]
    }]
  },
  options: {
    responsive: true,
    plugins: { legend: { display: false } },
    scales: { y: { beginAtZero: true, ticks: { precision: 0 } } }
  }
});

new Chart(document.getElementById('tierChart'), {
  type: 'doughnut',
  data: {
    labels: ['Strong', 'Adequate', 'Weak', 'None'],
    datasets: [{
      data: [$chartTierData],
      backgroundColor: ['#198754', '#0dcaf0', '#ffc107', '#dc3545']
    }]
  },
  options: {
    responsive: true,
    plugins: { legend: { position: 'bottom' } }
  }
});

new Chart(document.getElementById('histChart'), {
  type: 'bar',
  data: {
    labels: [$chartHistLabels],
    datasets: [{
      label: 'Users',
      data: [$chartHistData],
      backgroundColor: 'rgba(13,110,253,0.65)'
    }]
  },
  options: {
    responsive: true,
    plugins: { legend: { display: false } },
    scales: { y: { beginAtZero: true, ticks: { precision: 0 } } }
  }
});
</script>
</body>
</html>
"@

$htmlPath = Join-Path $runOutputDir "report-$methodKey.html"
$html | Set-Content -Path $htmlPath -Encoding UTF8

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------
Write-Host ""
Write-Host "Report complete!" -ForegroundColor Green
Write-Host ("  Total users                  : {0}"       -f $totalUsers)
Write-Host ("  {0,-28} : {1} ({2}%)" -f "$targetLabel registered", $targetRegistered.Count, $targetPct)
Write-Host ("    Members                    : {0}" -f $targetRegisteredMembers.Count)
Write-Host ("    Guests                     : {0}" -f $targetRegisteredGuests.Count)
Write-Host ("  {0,-28} : {1} ({2}%)" -f "Never registered $targetLabel", $notRegisteredCount, $notRegPct)
Write-Host ("  {0,-28} : {1} ({2}%) -- at-risk" -f "$targetLabel only method", $targetOnly.Count, $onlyPct) -ForegroundColor Yellow
Write-Host ("    Members at-risk            : {0}" -f $targetOnlyMembers.Count) -ForegroundColor Yellow
Write-Host ("    Guests at-risk             : {0}" -f $targetOnlyGuests.Count) -ForegroundColor Yellow
Write-Host ("  {0,-28} : {1} ({2}%) -- no MFA" -f "No MFA registered", $noMfa.Count, $noMfaPct) -ForegroundColor Red
Write-Host ("    Members no MFA             : {0}" -f $noMfaMembers.Count) -ForegroundColor Red
Write-Host ("    Guests no MFA              : {0}" -f $noMfaGuests.Count) -ForegroundColor Red
if ($canComputeSafeToBlock) {
    Write-Host ("  {0,-28} : {1} ({2}% of registered)" -f "Safe to block $targetLabel", $safeToBlock.Count, $safeToBlockPct) -ForegroundColor Green
    Write-Host ("    Members safe to block      : {0}" -f $safeToBlockMembers.Count) -ForegroundColor Green
    Write-Host ("    Guests safe to block       : {0}" -f $safeToBlockGuests.Count) -ForegroundColor Green
}
Write-Host ""
Write-Host "  HTML report : $(Resolve-Path $htmlPath)"
Write-Host "  CSV exports : $(Resolve-Path $runOutputDir)"
Write-Host ""
Write-Host "Next steps:" -ForegroundColor Cyan
Write-Host "  1. Import users-$methodKey-registered-members.csv into an Entra ID group (Members)"
Write-Host "  2. In Authentication Methods Policy, set '$targetLabel' to 'Selected groups' targeting that group"
Write-Host "  3. Work through users-$methodKey-only.csv to migrate at-risk users to a stronger method"
if ($canComputeSafeToBlock -and $safeToBlock.Count -gt 0) {
    Write-Host "  4. Use users-$methodKey-safe-to-block.csv to remove users from the group who prefer a stronger method" -ForegroundColor Green
}

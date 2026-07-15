<#
.SYNOPSIS
    Collects MFA sign-in activity for users registered with a specific authentication method.

.DESCRIPTION
    Queries Entra ID sign-in logs and produces a JSON file with per-user sign-in counts.

    NOTE ON SAFE-TO-BLOCK ANALYSIS:
    New-MfaMethodReport.ps1 now computes safe-to-block users directly from registration data
    using the userPreferredMethodForSecondaryAuthentication field — no sign-in logs required.
    This is the recommended approach and produces correct results.

    This script can still be useful as a diagnostic tool: it shows which target-method users
    actually had MFA sign-ins in the lookback period (i.e., active users vs. dormant accounts).
    However, the authenticationMethodsUsed field in the Graph beta sign-in logs API is currently
    not populated by Microsoft and always returns empty arrays, so per-sign-in method detection
    does not work. The script collects sign-in counts correctly but cannot determine which method
    was used.

    Authentication: same options as Get-AuthMethodRegistrations.ps1.

.PARAMETER RegistrationsPath
    Path to raw-registrations.json from Get-AuthMethodRegistrations.ps1.
    Used to restrict analysis to users who have the target method registered.

.PARAMETER TargetMethod
    The Graph API method key to analyze. Default: mobilePhone (SMS OTP).

.PARAMETER DaysBack
    Days of sign-in history to analyze. Default: 90.
    Note: Sign-in log retention depends on license:
      - Entra ID Free / P1: 30 days interactive sign-ins
      - Microsoft 365 E3/E5 (Audit log integration): up to 90 days
    Adjust to match your tenant's actual retention period.

.PARAMETER OutputPath
    Output JSON file path. Defaults to .\reports\sign-in-activity-{method}.json.

.PARAMETER AccessToken
    Bearer token for Microsoft Graph (same as Get-AuthMethodRegistrations.ps1).
    Recommended for PIM environments or tenants with device-code flow disabled.

    Getting a token (works with PIM-activated roles):
        $token = (az account get-access-token --resource https://graph.microsoft.com | ConvertFrom-Json).accessToken

.PARAMETER MaxPages
    Maximum sign-in log pages (999 records/page). Default: 300 (~300k sign-ins).
    For 200k-user tenants with 90 days of MFA sign-ins, 200–300 pages typically
    covers all target-method users. The Graph API skip token can expire after
    ~300 pages; if it does, the script saves partial results and warns you.

.EXAMPLE
    $token = (az account get-access-token --resource https://graph.microsoft.com | ConvertFrom-Json).accessToken
    .\Get-SignInActivity.ps1 -AccessToken $token

.NOTES
    Required scope:      AuditLog.Read.All
    Required Entra role: Reports Reader, Security Reader, Security Administrator,
                         Authentication Administrator, or Global Administrator
#>

[CmdletBinding()]
param(
    [string]$RegistrationsPath = ".\reports\raw-registrations.json",

    [ValidateSet(
        'mobilePhone', 'alternateMobilePhone', 'officePhone', 'email',
        'softwareOneTimePasscode', 'hardwareOneTimePasscode',
        'microsoftAuthenticatorPush', 'microsoftAuthenticatorPasswordless',
        'fido2SecurityKey', 'windowsHelloForBusiness', 'temporaryAccessPass'
    )]
    [string]$TargetMethod = 'mobilePhone',

    [int]$DaysBack = 90,

    [string]$OutputPath = "",

    [string]$AccessToken = "",

    [int]$MaxPages = 300
)

if (-not $OutputPath) {
    $methodKey  = $TargetMethod -replace '[^a-zA-Z0-9]', '-'
    $OutputPath = ".\reports\sign-in-activity-$methodKey.json"
}

$outputDir = Split-Path -Parent $OutputPath
if ($outputDir -and -not (Test-Path $outputDir)) {
    New-Item -ItemType Directory -Path $outputDir -Force | Out-Null
}

if (-not (Test-Path $RegistrationsPath)) {
    Write-Error "Registrations file not found: $RegistrationsPath`nRun Get-AuthMethodRegistrations.ps1 first."
    exit 1
}

# ---------------------------------------------------------------------------
# Load registrations — restrict to users who have the target method registered
# ---------------------------------------------------------------------------
Write-Host "Loading registrations from $RegistrationsPath..." -ForegroundColor Cyan
$raw = [System.IO.File]::ReadAllText((Resolve-Path $RegistrationsPath)) | ConvertFrom-Json

$targetUsers = @{}  # userId -> userPrincipalName
foreach ($user in $raw) {
    $methods = if ($user.methodsRegistered) { @($user.methodsRegistered) } else { @() }
    if ($methods -contains $TargetMethod) {
        $targetUsers[$user.id] = $user.userPrincipalName
    }
}
Write-Host ("  Users with {0} registered: {1}" -f $TargetMethod, $targetUsers.Count) -ForegroundColor White

if ($targetUsers.Count -eq 0) {
    Write-Host "No users have $TargetMethod registered. Nothing to analyze." -ForegroundColor Yellow
    exit 0
}

# ---------------------------------------------------------------------------
# Helper: test whether a sign-in authenticationMethod string matches the target
# Uses case-insensitive substring matching to handle Microsoft's varying value formats.
# ---------------------------------------------------------------------------
function Test-IsTargetMethod {
    param([string]$Method, [string]$TargetKey)
    switch ($TargetKey) {
        'mobilePhone'                        {
            # "Text message" / "SMS" — but NOT "Phone app notification" / "Phone app OTP"
            return ($Method -ilike '*text*' -or $Method -ilike '*sms*' -or
                    ($Method -ilike '*phone*' -and $Method -notlike '*app*' -and $Method -notlike '*notification*'))
        }
        'alternateMobilePhone'               {
            return ($Method -ilike '*text*' -or $Method -ilike '*sms*' -or
                    ($Method -ilike '*phone*' -and $Method -notlike '*app*' -and $Method -notlike '*notification*'))
        }
        'officePhone'                        { return ($Method -ilike '*voice*' -or $Method -ilike '*phone call*') }
        'email'                              { return ($Method -ilike '*email*') }
        'softwareOneTimePasscode'            {
            return ($Method -ilike '*app otp*' -or $Method -ilike '*software oath*' -or
                    ($Method -ilike '*oath*' -and $Method -notlike '*hardware*'))
        }
        'hardwareOneTimePasscode'            { return ($Method -ilike '*hardware*') }
        'microsoftAuthenticatorPush'         { return ($Method -ilike '*notification*' -or $Method -ilike '*push*') }
        'microsoftAuthenticatorPasswordless' { return ($Method -ilike '*passwordless*' -or $Method -ilike '*phone sign-in*') }
        'fido2SecurityKey'                   { return ($Method -ilike '*fido*' -or $Method -ilike '*security key*') }
        'windowsHelloForBusiness'            { return ($Method -ilike '*hello*') }
        'temporaryAccessPass'                { return ($Method -ilike '*temporary*') }
        default                              { return ($Method -ilike "*$TargetKey*") }
    }
}

# ---------------------------------------------------------------------------
# Setup authentication
# ---------------------------------------------------------------------------
$useDirectRest = [bool]$AccessToken

if ($useDirectRest) {
    Write-Host "Using provided access token (direct REST)..." -ForegroundColor Cyan
    $headers = @{ Authorization = "Bearer $AccessToken" }
} else {
    if (-not (Get-Module -ListAvailable -Name Microsoft.Graph.Authentication)) {
        throw "Microsoft.Graph.Authentication module not found. Install with: Install-Module Microsoft.Graph -Scope CurrentUser"
    }
    Import-Module Microsoft.Graph.Authentication -ErrorAction Stop
    Write-Host "Connecting to Microsoft Graph..." -ForegroundColor Cyan
    Connect-MgGraph -Scopes "AuditLog.Read.All" -NoWelcome
}

# ---------------------------------------------------------------------------
# Query sign-in logs
# ---------------------------------------------------------------------------
$cutoff      = (Get-Date).AddDays(-$DaysBack).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
$selectFields = "userId,userPrincipalName,authenticationMethodsUsed,authenticationRequirement,createdDateTime"
$uri          = "https://graph.microsoft.com/beta/auditLogs/signIns?`$filter=createdDateTime ge $cutoff&`$select=$selectFields&`$top=999"

$userActivity = @{}  # userId -> { upn, signInCount, lastSignIn, usedTarget, usedNonTarget, methods }
$pageCount    = 0
$totalSignIns = 0
$startTime    = Get-Date

Write-Host ("Scanning sign-in logs (last {0} days, up to {1} pages of 999)..." -f $DaysBack, $MaxPages) -ForegroundColor Cyan
Write-Host "  Only MFA sign-ins for $TargetMethod-registered users are processed." -ForegroundColor Gray

do {
    try {
        if ($useDirectRest) {
            $response = Invoke-RestMethod -Uri $uri -Headers $headers -Method GET
        } else {
            $response = Invoke-MgGraphRequest -Uri $uri -Method GET -OutputType PSObject
        }
    }
    catch {
        if ($_ -match '403|Forbidden|RequestFromUnsupportedUserRole') {
            throw @"
Access denied (403). Ensure the required Entra ID role is activated.
Required roles: Reports Reader, Security Reader, Security Administrator,
                Authentication Administrator, or Global Administrator

If using PIM: activate the role and obtain a fresh token:
  `$token = (az account get-access-token --resource https://graph.microsoft.com | ConvertFrom-Json).accessToken
"@
        }
        if ($_ -match '401|Unauthorized|InvalidAuthenticationToken') {
            throw "Access token expired on page $pageCount after $totalSignIns sign-ins. Obtain a fresh token and re-run."
        }
        if ($_ -match 'skiptoken|skip token' -and $_ -match 'null|expired|typo') {
            Write-Warning ("Skip token expired on page {0} after {1} sign-ins. Saving partial results." -f $pageCount, $totalSignIns)
            Write-Warning "This is a known Graph API pagination limit. Results cover the most recent sign-ins within the scan window."
            $uri = $null  # stop pagination loop
            break
        }
        throw "Sign-in log query failed on page ${pageCount}: $_"
    }

    $pageCount++

    foreach ($signIn in $response.value) {
        $totalSignIns++

        # Only process MFA sign-ins for users who have the target method registered
        if ($signIn.authenticationRequirement -ne 'multiFactorAuthentication') { continue }
        if (-not $targetUsers.ContainsKey($signIn.userId))                     { continue }

        # Initialize record on first sighting
        if (-not $userActivity.ContainsKey($signIn.userId)) {
            $userActivity[$signIn.userId] = @{
                upn           = $signIn.userPrincipalName
                signInCount   = 0
                lastSignIn    = $null
                usedTarget    = $false
                usedNonTarget = $false
                methods       = [System.Collections.Generic.HashSet[string]]::new()
            }
        }

        $rec = $userActivity[$signIn.userId]
        $rec.signInCount++

        $signinDate = if ($signIn.createdDateTime) { $signIn.createdDateTime.ToString('yyyy-MM-dd') } else { $null }
        if ($signinDate -and (-not $rec.lastSignIn -or $signinDate -gt $rec.lastSignIn)) {
            $rec.lastSignIn = $signinDate
        }

        # Extract which MFA method(s) were used in this sign-in.
        # authenticationMethodsUsed is a flat string array, e.g. ["Password", "Text message"]
        if ($signIn.authenticationMethodsUsed) {
            foreach ($method in $signIn.authenticationMethodsUsed) {
                if (-not $method -or $method -eq 'Password' -or $method -eq 'Previously satisfied') { continue }

                $rec.methods.Add($method) | Out-Null

                if (Test-IsTargetMethod -Method $method -TargetKey $TargetMethod) {
                    $rec.usedTarget = $true
                } else {
                    $rec.usedNonTarget = $true
                }
            }
        }
    }

    $elapsed      = (Get-Date) - $startTime
    $rate         = if ($elapsed.TotalSeconds -gt 0) { [math]::Round($totalSignIns / $elapsed.TotalSeconds) } else { 0 }
    $matchedUsers = $userActivity.Count
    Write-Progress -Activity "Scanning sign-in logs" `
        -Status ("Page {0} | {1} sign-ins scanned | {2}/{3} target users matched | {4} sign-ins/sec" -f $pageCount, $totalSignIns, $matchedUsers, $targetUsers.Count, $rate) `
        -PercentComplete ([math]::Min(99, ($pageCount / $MaxPages * 100)))

    $uri = $response.'@odata.nextLink'
} while ($uri -and $pageCount -lt $MaxPages)

Write-Progress -Activity "Scanning sign-in logs" -Completed

if ($pageCount -ge $MaxPages -and $uri) {
    Write-Warning ("Reached MaxPages limit ({0}). Results may be incomplete for some users. Increase -MaxPages for more coverage." -f $MaxPages)
}

$elapsed = (Get-Date) - $startTime
Write-Host ""
Write-Host "Sign-in log scan complete:" -ForegroundColor Green
Write-Host ("  Pages scanned        : {0}" -f $pageCount)
Write-Host ("  Total sign-ins seen  : {0}" -f $totalSignIns)
Write-Host ("  Target users matched : {0} of {1}" -f $userActivity.Count, $targetUsers.Count)
Write-Host ("  Time elapsed         : {0:N1} min" -f $elapsed.TotalMinutes)

# ---------------------------------------------------------------------------
# Build output — include ALL target users, even those with no sign-in data
# (so the report can distinguish "actively using other method" vs "unknown")
# ---------------------------------------------------------------------------
Write-Host "Building output..." -ForegroundColor Cyan
$output = [System.Collections.Generic.List[PSObject]]::new()

foreach ($userId in $targetUsers.Keys) {
    if ($userActivity.ContainsKey($userId)) {
        $rec = $userActivity[$userId]
        $output.Add([PSCustomObject]@{
            userId                   = $userId
            userPrincipalName        = $rec.upn
            signInCount              = $rec.signInCount
            lastSignIn               = $rec.lastSignIn
            mfaMethodsUsed           = @($rec.methods)
            usedTargetMethodInPeriod = $rec.usedTarget
            usedNonTargetMfaInPeriod = $rec.usedNonTarget
        })
    } else {
        # No MFA sign-in found — unknown usage pattern, not safe to block
        $output.Add([PSCustomObject]@{
            userId                   = $userId
            userPrincipalName        = $targetUsers[$userId]
            signInCount              = 0
            lastSignIn               = $null
            mfaMethodsUsed           = @()
            usedTargetMethodInPeriod = $false
            usedNonTargetMfaInPeriod = $false
        })
    }
}

# Summary
$safeCount       = @($output | Where-Object { -not $_.usedTargetMethodInPeriod -and $_.usedNonTargetMfaInPeriod }).Count
$usedTargetCount = @($output | Where-Object {  $_.usedTargetMethodInPeriod }).Count
$noActivityCount = @($output | Where-Object {  $_.signInCount -eq 0 }).Count

Write-Host ("  Safe to block        : {0}" -f $safeCount)
Write-Host ("  Used target method   : {0}  (keep in inclusion group)" -f $usedTargetCount)
Write-Host ("  No MFA activity seen : {0}  (unknown — kept in group)" -f $noActivityCount)

# ---------------------------------------------------------------------------
# Save output
# ---------------------------------------------------------------------------
Write-Host ""
Write-Host "Saving to $OutputPath..." -ForegroundColor Cyan
$output | ConvertTo-Json -Depth 5 | Set-Content -Path $OutputPath -Encoding UTF8
Write-Host "Done! Output: $(Resolve-Path $OutputPath)" -ForegroundColor Green
Write-Host ""
Write-Host "Next step:" -ForegroundColor Cyan
$methodKey = $TargetMethod -replace '[^a-zA-Z0-9]', '-'
Write-Host ("  .\New-MfaMethodReport.ps1 -TargetMethod {0} -SignInActivityPath '{1}'" -f $TargetMethod, (Resolve-Path $OutputPath))

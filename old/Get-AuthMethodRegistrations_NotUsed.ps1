<#
.SYNOPSIS
    Collects authentication method registration data for all users in an Entra ID tenant
    and saves the result as a cached JSON file for downstream analysis.

.DESCRIPTION
    Paginates through the userRegistrationDetails report for all users and saves raw data
    to a JSON file that can be reused by New-MfaMethodReport.ps1 without re-querying
    the Graph API.

    For large tenants (~200,000 users), expect 3–8 minutes depending on throttling.

    Authentication options:
      1. Pass -AccessToken with a bearer token (recommended for PIM environments or
         when device-code flow is disabled). Uses Invoke-RestMethod directly — no
         Graph SDK session involved.
      2. Interactive browser sign-in via Connect-MgGraph (default when no token supplied).

    Getting a token (works with PIM-activated roles):
        # In Azure Cloud Shell or any terminal with az CLI:
        $token = (az account get-access-token --resource https://graph.microsoft.com | ConvertFrom-Json).accessToken

.PARAMETER OutputPath
    Path for the output JSON file. Defaults to .\reports\raw-registrations.json.

.PARAMETER AccessToken
    A bearer token for Microsoft Graph. See .DESCRIPTION for how to obtain one.

.EXAMPLE
    # Interactive browser sign-in
    .\Get-AuthMethodRegistrations.ps1

    # Pass a token from az CLI (bypasses embedded browser / PIM issues)
    $token = (az account get-access-token --resource https://graph.microsoft.com | ConvertFrom-Json).accessToken
    .\Get-AuthMethodRegistrations.ps1 -AccessToken $token

.NOTES
    Required scope:      AuditLog.Read.All (delegated)
    Required Entra role: One of: Reports Reader, Security Reader, Security Administrator,
                         Authentication Administrator, or Global Administrator
    Required module:     Microsoft.Graph.Authentication (only needed when not using -AccessToken)
    Install:             Install-Module Microsoft.Graph -Scope CurrentUser
#>

[CmdletBinding()]
param(
    [string]$OutputPath  = ".\reports\raw-registrations.json",
    [string]$AccessToken = ""
)

$outputDir = Split-Path -Parent $OutputPath
if ($outputDir -and -not (Test-Path $outputDir)) {
    New-Item -ItemType Directory -Path $outputDir -Force | Out-Null
}

# When an access token is provided, use Invoke-RestMethod directly — this bypasses the
# Graph SDK session entirely and avoids issues with cached connections or PIM tokens.
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
    Connect-MgGraph -Scopes "AuditLog.Read.All", "Reports.Read.All" -NoWelcome
}

$allUsers  = [System.Collections.Generic.List[object]]::new()
$pageSize  = 999
$uri       = "https://graph.microsoft.com/v1.0/reports/authenticationMethods/userRegistrationDetails?`$top=$pageSize"
$pageCount = 0
$startTime = Get-Date

Write-Host "Collecting user registration data..." -ForegroundColor Cyan

do {
    try {
        if ($useDirectRest) {
            $response = Invoke-RestMethod -Uri $uri -Headers $headers -Method GET
        } else {
            $response = Invoke-MgGraphRequest -Uri $uri -Method GET -OutputType PSObject
        }
    }
    catch {
        # Do not save partial data: an incomplete user list would cause real users
        # to be excluded from the inclusion group and lose their existing method.
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

Write-Host "Saving to $OutputPath..." -ForegroundColor Cyan
$allUsers | ConvertTo-Json -Depth 5 | Set-Content -Path $OutputPath -Encoding UTF8

Write-Host ""
Write-Host "Collection complete!" -ForegroundColor Green
Write-Host ("  Users collected : {0}" -f $allUsers.Count)
Write-Host ("  Pages fetched   : {0}" -f $pageCount)
Write-Host ("  Time elapsed    : {0:N1} min" -f $elapsed.TotalMinutes)
Write-Host ("  Output file     : {0}" -f (Resolve-Path $OutputPath))

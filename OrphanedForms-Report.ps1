<#
.SYNOPSIS
  Produces a "Forms orphan risk" report:
    - This script creates an inventory report to identify Orphaned Microsoft Forms allowing Admins to restore the Form before it's permanently deleted.
    - Detects likely user-owned Forms by mining Unified Audit Log "MicrosoftForms" events
    - Flags orphan risk by joining to Entra soft-deleted users (30-day window)

.DESCRIPTION
  This is a signal-based inventory because Microsoft Forms doesn't provide a tenant-wide admin inventory API.
  It relies on Microsoft Purview audit log "Forms activities" (CreateForm, MoveForm, etc.) to identify likely owners. 
  [1](https://learn.microsoft.com/en-us/purview/audit-log-activities)

  Batching:
    - Uses the Graph Audit Log Query API (POST /security/auditLog/queries).
    - Results are fully paginated via @odata.nextLink — no per-query row-count limit.
    - Query is submitted async; script polls until status = succeeded, then pages all records.

  Orphan risk:
    - Any user found in Entra "deletedItems" is within the soft-delete window (commonly 30 days). The report computes
      DaysSinceDeleted and flags <= OrphanWindowDays as HIGH.

.NOTES
  Requires:
    - App registration with: AuditLogsQuery.Read.All, User.Read.All, Directory.Read.All, Mail.Send
      - Mail.Send is required only when $SendEmailNotifications = $true (used by Send-FormsOrphanAlertEmail)
    - No PowerShell modules required — all calls use Invoke-RestMethod against Graph API

    Created by: Mike Lee
    Created Date: 5/4/2026
    Updated: 5/6/2026 - Added support for e-mail notifications

  Authentication:
    - Graph API only: client-credentials token via AcquireToken() using certificate or client secret
#>

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

#region Configuration
##############################################################
#                  CONFIGURATION SECTION                     #
##############################################################

# ---- Debug output ----
$debug = $false

# ---- Tenant & App Registration ----
$tenantId = '9cfc42cb-51da-4055-87e9-b20a170b6ba3'
$clientId = 'abc64618-283f-47ba-a185-50d935d51d57'

# ---- Authentication type: 'Certificate' or 'ClientSecret' ----
$AuthType = 'Certificate'

# Certificate thumbprint (used when $AuthType = 'Certificate')
$Thumbprint = 'B696FDCFE1453F3FBC6031F54DE988DA0ED905A9'

# Certificate store: 'LocalMachine' or 'CurrentUser'
$CertStore = 'LocalMachine'

# Client Secret (used when $AuthType = 'ClientSecret')
$clientSecret = ''

# ---- Audit query window ----
$LookbackDays = 31    # How far back to search Forms audit activity (days)
$OrphanWindowDays = 30    # Users deleted within this many days are flagged HIGH risk

# ---- Forms operations to query (owner-leaning / governance-relevant) ----
$Operations = @(
    'CreateForm',
    'MoveForm',
    'DeleteForm',
    'EditForm',
    'ViewForm',
    'ListForms',
    'AddFormCoauthor',
    'RemoveFormCoauthor',
    'AllowShareFormForCopy',
    'DisallowShareFormForCopy',
    'EnableWorkOrSchoolCollaboration',
    'EnableSameOrgCollaboration',
    'EnableSpecificCollaboaration',
    'DisableCollaboration',
    'ExportForm',
    'UpdateFormSetting',
    'GetSummaryLink',
    'DeleteSummaryLink',
    'ConnectToExcelWorkbook'
)

# Set $true to include responder operations (CreateResponse/SubmitResponse); increases volume and may add noise
$IncludeResponseSignals = $false

# ---- Output folder ----
$OutputFolder = $env:TEMP

# ---- Request throttling ----
$MaxRetries = 15
$InitialBackoffSec = 3
$RequestTimeoutSec = 300

# ---- Email Notifications ----
# Set $SendEmailNotifications = $true to send an alert email after the report runs.
# An email is sent listing all HIGH (and optionally Medium) risk orphaned Forms accounts.
$SendEmailNotifications = $false

# Recipients — individual addresses or mail-enabled group/distribution-list addresses.
$EmailTo = @(
    'admin@M365CPI13246019.onmicrosoft.com'
)

# Sender address — must be a licensed Exchange Online mailbox in the tenant.
# The app registration must have Mail.Send (Application) permission granted in Entra ID.
# Email is sent via Graph API (POST /users/{EmailFrom}/sendMail) — no SMTP relay needed.
$EmailFrom = 'admin@M365CPI13246019.onmicrosoft.com'

# Minimum risk level to include in the alert email: 'HIGH', 'Medium', or 'Low'
$EmailMinRiskLevel = 'HIGH'

##############################################################
#                END CONFIGURATION SECTION                   #
##############################################################
#endregion Configuration

#region Initialization
$global:token = $null
$global:tokenExpiry = $null

# Required for HTML-encoding display names and UPNs in alert email bodies
Add-Type -AssemblyName System.Web
#endregion Initialization

#region Helper Functions

function Invoke-GraphRequestWithThrottleHandling {
    <#
    .SYNOPSIS
        Wraps Invoke-RestMethod with Retry-After / exponential-backoff throttle handling
        for Microsoft Graph API calls (429, 502, 503, 504, timeouts).
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)] [string]   $Uri,
        [Parameter(Mandatory)] [string]   $Method,
        [Parameter()]          [hashtable] $Headers = @{},
        [Parameter()]          [string]    $Body = $null,
        [Parameter()]          [string]    $ContentType = 'application/json',
        [Parameter()]          [int]      $MaxRetries = $script:MaxRetries,
        [Parameter()]          [int]      $InitialBackoffSeconds = $script:InitialBackoffSec,
        [Parameter()]          [int]      $TimeoutSeconds = $script:RequestTimeoutSec
    )

    $retryCount = 0
    $backoffSec = $InitialBackoffSeconds
    $result = $null

    if ($debug) { Write-Host "  Graph -> $Method $Uri" -ForegroundColor DarkGray }

    while ($retryCount -le $MaxRetries) {
        try {
            $invokeParams = @{
                Uri         = $Uri
                Method      = $Method
                Headers     = $Headers
                ContentType = $ContentType
                TimeoutSec  = $TimeoutSeconds
                ErrorAction = 'Stop'
                Verbose     = $false
            }
            if ($Body) { $invokeParams['Body'] = $Body }

            $result = Invoke-RestMethod @invokeParams
            return $result
        }
        catch {
            $statusCode = $null
            if ($_.Exception.Response) {
                $statusCode = [int]$_.Exception.Response.StatusCode
            }

            $isRetryable = $statusCode -in @(429, 502, 503, 504) -or
            $_.Exception -is [System.Net.WebException] -and (
                $_.Exception.Status -eq [System.Net.WebExceptionStatus]::Timeout -or
                $_.Exception.Status -eq [System.Net.WebExceptionStatus]::ConnectionClosed
            )

            if (-not $isRetryable) {
                $detail = if ($_.ErrorDetails.Message) { " | API response: $($_.ErrorDetails.Message)" } else { '' }
                throw "$($_.Exception.Message)$detail"
            }

            if ($retryCount -ge $MaxRetries) {
                Write-Host "    Max retries reached for: $Uri" -ForegroundColor Red
                throw $_
            }

            $waitSec = $backoffSec
            if ($statusCode -eq 429) {
                try {
                    $ra = $_.Exception.Response.Headers['Retry-After']
                    if ($ra) { $waitSec = [int]$ra }
                }
                catch {}
            }

            $retryCount++
            Write-Host "    Throttled ($statusCode). Waiting ${waitSec}s (attempt $retryCount/$MaxRetries)..." -ForegroundColor Yellow
            Start-Sleep -Seconds $waitSec
            $backoffSec = [Math]::Min($backoffSec * 2, 300)
        }
    }
}

#endregion Helper Functions

#region Authentication Functions

function AcquireToken {
    <#
    .SYNOPSIS
        Acquires a Microsoft Graph access token (scope: graph.microsoft.com/.default).
        One token covers all Graph endpoints across all geo datacenters.
    #>
    Write-Host "Authenticating to Microsoft Graph ($AuthType)..." -ForegroundColor Cyan

    $scope = 'https://graph.microsoft.com/.default'
    $tokenUri = "https://login.microsoftonline.com/$tenantId/oauth2/v2.0/token"

    if ($AuthType -eq 'ClientSecret') {
        $body = @{
            grant_type    = 'client_credentials'
            client_id     = $clientId
            client_secret = $clientSecret
            scope         = $scope
        }
        try {
            $resp = Invoke-RestMethod -Method Post -Uri $tokenUri -Body $body `
                -ContentType 'application/x-www-form-urlencoded' -ErrorAction Stop -Verbose:$false
            $global:token = $resp.access_token
            $expiresIn = if ($resp.expires_in) { $resp.expires_in } else { 3600 }
            $global:tokenExpiry = (Get-Date).AddSeconds($expiresIn - 300)
            Write-Host "  Connected via Client Secret. Token valid until: $($global:tokenExpiry)" -ForegroundColor Green
        }
        catch {
            Write-Host "  Authentication failed (ClientSecret): $($_.Exception.Message)" -ForegroundColor Red
            Exit
        }
    }
    elseif ($AuthType -eq 'Certificate') {
        try {
            $cert = Get-Item -Path "Cert:\$CertStore\My\$Thumbprint" -ErrorAction Stop
        }
        catch {
            Write-Host "  Certificate $Thumbprint not found in $CertStore\My store." -ForegroundColor Red
            Exit
        }

        $now = [System.DateTimeOffset]::UtcNow
        $exp = $now.AddMinutes(10).ToUnixTimeSeconds()
        $nbf = $now.ToUnixTimeSeconds()

        $header = @{ alg = 'RS256'; typ = 'JWT'; x5t = [Convert]::ToBase64String($cert.GetCertHash()).TrimEnd('=').Replace('+', '-').Replace('/', '_') } | ConvertTo-Json -Compress
        $payload = @{ aud = $tokenUri; exp = $exp; iss = $clientId; jti = [System.Guid]::NewGuid().ToString(); nbf = $nbf; sub = $clientId } | ConvertTo-Json -Compress

        $hB64 = [Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($header)).TrimEnd('=').Replace('+', '-').Replace('/', '_')
        $pB64 = [Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($payload)).TrimEnd('=').Replace('+', '-').Replace('/', '_')
        $toSign = "$hB64.$pB64"
        $rsa = [System.Security.Cryptography.X509Certificates.RSACertificateExtensions]::GetRSAPrivateKey($cert)
        if (-not $rsa) {
            Write-Host "  Unable to access RSA private key for certificate $Thumbprint." -ForegroundColor Red
            Exit
        }
        $sig = $rsa.SignData(
            [System.Text.Encoding]::UTF8.GetBytes($toSign),
            [System.Security.Cryptography.HashAlgorithmName]::SHA256,
            [System.Security.Cryptography.RSASignaturePadding]::Pkcs1)
        $jwt = "$toSign.$([Convert]::ToBase64String($sig).TrimEnd('=').Replace('+', '-').Replace('/', '_'))"

        $body = @{
            client_id             = $clientId
            client_assertion_type = 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer'
            client_assertion      = $jwt
            scope                 = $scope
            grant_type            = 'client_credentials'
        }

        try {
            $resp = Invoke-RestMethod -Method Post -Uri $tokenUri -Body $body `
                -ContentType 'application/x-www-form-urlencoded' -ErrorAction Stop -Verbose:$false
            $global:token = $resp.access_token
            $expiresIn = if ($resp.expires_in) { $resp.expires_in } else { 3600 }
            $global:tokenExpiry = (Get-Date).AddSeconds($expiresIn - 300)
            Write-Host "  Connected via Certificate. Token valid until: $($global:tokenExpiry)" -ForegroundColor Green
        }
        catch {
            Write-Host "  Authentication failed (Certificate): $($_.Exception.Message)" -ForegroundColor Red
            Exit
        }
    }
    else {
        Write-Host "  Invalid AuthType '$AuthType'. Use 'Certificate' or 'ClientSecret'." -ForegroundColor Red
        Exit
    }
}

function Test-ValidToken {
    if ($null -eq $global:tokenExpiry -or (Get-Date) -gt $global:tokenExpiry) {
        Write-Host 'Token expired or expiring soon — refreshing...' -ForegroundColor Yellow
        AcquireToken
    }
}

function Get-AuthHeader {
    Test-ValidToken
    return @{ Authorization = "Bearer $($global:token)" }
}

#endregion Authentication Functions

#region Logging Functions

# --------------------------
# Logging helpers
# --------------------------
function New-FolderIfMissing([string]$Path) {
    if (-not (Test-Path -LiteralPath $Path)) { New-Item -ItemType Directory -Path $Path | Out-Null }
}

function Write-Log {
    param(
        [ValidateSet("INFO", "WARN", "ERROR", "DEBUG")] [string]$Level,
        [string]$Message
    )
    $ts = (Get-Date).ToString("s")
    $line = "[$ts][$Level] $Message"
    Write-Host $line
    Add-Content -LiteralPath $script:LogFile -Value $line
}

function Invoke-WithRetry {
    param(
        [scriptblock]$ScriptBlock,
        [int]$MaxAttempts = 6,
        [int]$BaseDelaySeconds = 2,
        [string]$OperationName = "operation"
    )

    for ($attempt = 1; $attempt -le $MaxAttempts; $attempt++) {
        try {
            return & $ScriptBlock
        }
        catch {
            $msg = $_.Exception.Message
            if ($attempt -eq $MaxAttempts) {
                Write-Log -Level "ERROR" -Message "FAILED $OperationName after $MaxAttempts attempts. Last error: $msg"
                throw
            }

            # Do not retry auth/permission errors — they will never self-resolve
            if ($msg -match '401|403|Unauthorized|Forbidden|dont have any permissions') {
                Write-Log -Level "ERROR" -Message "Non-retryable auth error for $OperationName : $msg"
                throw
            }

            # Exponential backoff + jitter
            $delay = [Math]::Min(60, $BaseDelaySeconds * [Math]::Pow(2, $attempt - 1))
            $jitter = Get-Random -Minimum 0 -Maximum 1000
            $sleepMs = ($delay * 1000) + $jitter

            Write-Log -Level "WARN" -Message "Retry $attempt/$MaxAttempts for $OperationName due to: $msg. Sleeping $([Math]::Round($sleepMs/1000,2))s"
            Start-Sleep -Milliseconds $sleepMs
        }
    }
}

#endregion Logging Functions

#region Email Functions

function Send-FormsOrphanAlertEmail {
    <#
    .SYNOPSIS
        Sends an HTML alert email to the admin list ($EmailTo) summarising orphaned
        Microsoft Forms accounts whose owners have been deleted and whose Forms are at
        risk of permanent deletion.

        Uses the Microsoft Graph API (POST /users/{EmailFrom}/sendMail) with the
        existing bearer token — no SMTP relay required.
        Requires $SendEmailNotifications = $true and Mail.Send (Application) on the
        app registration.
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)] [object[]] $AffectedAccounts
    )

    if ($AffectedAccounts.Count -eq 0) { return }

    $subject = "[Forms Orphan Alert] $($AffectedAccounts.Count) account(s) with orphaned Forms require attention — Tenant: $script:tenantId"

    # Build HTML table rows, sorted by days until permanent deletion (most urgent first)
    $sortedAccounts = $AffectedAccounts | Sort-Object {
        if ($null -ne $_.DaysUntilPermanentDeletion) { $_.DaysUntilPermanentDeletion } else { 999 }
    }

    $tableRows = foreach ($acct in $sortedAccounts) {
        $daysLeft = if ($null -ne $acct.DaysUntilPermanentDeletion) { "$($acct.DaysUntilPermanentDeletion)" } else { 'N/A' }
        $daysNum = if ($null -ne $acct.DaysUntilPermanentDeletion) { [double]$acct.DaysUntilPermanentDeletion } else { 999 }

        # Row colour: red shading <= 3 days, amber <= 7 days, white otherwise
        $rowColor = if ($daysNum -le 3) { '#fde8e8' } elseif ($daysNum -le 7) { '#fff3cd' } else { '#ffffff' }

        $safeUpn = [System.Web.HttpUtility]::HtmlEncode($acct.UserPrincipalName)
        $safeAction = [System.Web.HttpUtility]::HtmlEncode($acct.RecommendedAction)
        $safeRisk = [System.Web.HttpUtility]::HtmlEncode($acct.RiskLevel)
        $safeForms = [System.Web.HttpUtility]::HtmlEncode($acct.FormNames)

        # Build recovery URL hyperlinks — one per form
        $urlLinks = if ($acct.RecoveryUrls) {
            $urls = $acct.RecoveryUrls -split ';' | Where-Object { $_ }
            ($urls | ForEach-Object { "<a href='$_'>Recover</a>" }) -join ' | '
        }
        else { 'N/A' }

        "<tr style='background-color:$rowColor;'>
          <td style='padding:5px 10px;border:1px solid #d0d0d0;'>$safeUpn</td>
          <td style='padding:5px 10px;border:1px solid #d0d0d0;text-align:center;'>$safeRisk</td>
          <td style='padding:5px 10px;border:1px solid #d0d0d0;text-align:center;'>$($acct.FormCount)</td>
          <td style='padding:5px 10px;border:1px solid #d0d0d0;'>$safeForms</td>
          <td style='padding:5px 10px;border:1px solid #d0d0d0;text-align:center;'>$daysLeft</td>
          <td style='padding:5px 10px;border:1px solid #d0d0d0;'>$safeAction</td>
          <td style='padding:5px 10px;border:1px solid #d0d0d0;'>$urlLinks</td>
        </tr>"
    }

    $headerColor = '#1a5276'
    $alertHeading = "Forms Orphan Alert — $($AffectedAccounts.Count) account(s) with orphaned Forms require immediate attention"

    $body = @"
<!DOCTYPE html>
<html>
<body style="font-family:Segoe UI,Arial,sans-serif;font-size:14px;color:#222;margin:20px;">
  <h2 style="color:$headerColor;margin-bottom:4px;">$alertHeading</h2>
  <p style="margin-top:0;color:#555;font-size:13px;">
    Tenant: <strong>$script:tenantId</strong> &nbsp;|&nbsp;
    Report date: <strong>$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')</strong> &nbsp;|&nbsp;
    Orphan window: <strong>$script:OrphanWindowDays days</strong>
  </p>
  <p>
    The accounts below have been deleted and their Microsoft Forms are at risk of
    permanent deletion when the soft-delete window expires. Please recover or transfer
    Forms ownership immediately using the recovery links provided.
  </p>
  <table style="border-collapse:collapse;width:100%;font-size:13px;">
    <thead>
      <tr style="background-color:$headerColor;color:#fff;">
        <th style="padding:6px 10px;border:1px solid #999;text-align:left;">User (UPN)</th>
        <th style="padding:6px 10px;border:1px solid #999;text-align:center;">Risk</th>
        <th style="padding:6px 10px;border:1px solid #999;text-align:center;">Form Count</th>
        <th style="padding:6px 10px;border:1px solid #999;text-align:left;">Form Names</th>
        <th style="padding:6px 10px;border:1px solid #999;text-align:center;">Days Until Permanent Deletion</th>
        <th style="padding:6px 10px;border:1px solid #999;text-align:left;">Recommended Action</th>
        <th style="padding:6px 10px;border:1px solid #999;text-align:left;">Recovery Links</th>
      </tr>
    </thead>
    <tbody>
      $($tableRows -join "`n      ")
    </tbody>
  </table>
  <br/>
  <p style="font-size:12px;color:#888;">
    Full report saved to: $script:reportCsv<br/>
    Generated by OrphanedForms-Report.ps1
  </p>
</body>
</html>
"@

    # Build the Graph sendMail payload.
    # toRecipients is constructed from the $EmailTo array — each address becomes
    # a separate emailAddress object so both individual mailboxes and mail-enabled
    # groups are handled correctly.
    $toRecipients = @($script:EmailTo | ForEach-Object {
            @{ emailAddress = @{ address = $_ } }
        })

    $graphMailBody = @{
        message         = @{
            subject      = $subject
            body         = @{ contentType = 'HTML'; content = $body }
            toRecipients = $toRecipients
        }
        saveToSentItems = $false
    } | ConvertTo-Json -Depth 6 -Compress

    # The sender mailbox must match $EmailFrom. With app-only auth the call is
    # POST /users/{sender}/sendMail — /me is not valid for client-credentials tokens.
    $sendUri = "https://graph.microsoft.com/v1.0/users/$([Uri]::EscapeDataString($script:EmailFrom))/sendMail"

    Test-ValidToken
    $headers = @{ Authorization = "Bearer $global:token" }

    try {
        Invoke-GraphRequestWithThrottleHandling -Uri $sendUri -Method POST -Headers $headers `
            -Body $graphMailBody -ContentType 'application/json'
        Write-Log INFO "Forms orphan alert email sent to: $($script:EmailTo -join ', ')"
    }
    catch {
        Write-Log ERROR "Forms orphan alert email send failed: $($_.Exception.Message)"
        Write-Host "  Verify: Mail.Send (Application) is granted for app '$script:clientId' in Entra ID." -ForegroundColor Yellow
        Write-Host "  Sender mailbox '$script:EmailFrom' must be a licensed Exchange Online mailbox." -ForegroundColor Yellow
    }
}

#endregion Email Functions

#region User Resolution

function Resolve-UserStatusMap {
    <#
    .SYNOPSIS
        For each UPN seen in audit data, does a live Graph lookup to determine whether
        the user is active, disabled, soft-deleted, or hard-deleted.
        This is more reliable than pre-fetching all deleted items because Entra can
        mutate a user's UPN on deletion (adds a conflict suffix), which breaks key matching.
    #>
    param([string[]]$Upns)

    $map = @{}
    $total = $Upns.Count
    $i = 0
    foreach ($upn in $Upns) {
        $i++
        $key = $upn.ToLowerInvariant()
        Write-Log INFO "  Resolving user status ($i/$total): $upn"
        try {
            # Happy path: user exists in active directory
            $u = Invoke-GraphRequestWithThrottleHandling -Method GET `
                -Uri ("https://graph.microsoft.com/v1.0/users/" + [System.Uri]::EscapeDataString($upn) + "?`$select=id,displayName,userPrincipalName,accountEnabled") `
                -Headers (Get-AuthHeader)
            $map[$key] = @{
                IsDeleted         = $false
                IsDisabled        = (-not [bool]$u.accountEnabled)
                DeletedDateTime   = $null
                DisplayName       = $u.displayName
                UserPrincipalName = $u.userPrincipalName
                ObjId             = $u.id
            }
        }
        catch {
            if ($_.Exception.Message -match '404|ResourceNotFound|does not exist') {
                # Not in active directory — check soft-deleted items filtered by UPN
                try {
                    $escapedUpn = $upn.Replace("'", "''")
                    $delResp = Invoke-GraphRequestWithThrottleHandling -Method GET `
                        -Uri ("https://graph.microsoft.com/v1.0/directory/deletedItems/microsoft.graph.user?`$filter=userPrincipalName eq '" + $escapedUpn + "'&`$select=id,displayName,userPrincipalName,deletedDateTime") `
                        -Headers (Get-AuthHeader)
                    $du = if ($delResp.value -and $delResp.value.Count -gt 0) { $delResp.value[0] } else { $null }

                    # Fallback: Entra mutates the UPN on deletion to free the namespace.
                    # The mail attribute is NOT mutated, so search by mail using the pre-deletion UPN value.
                    if (-not $du) {
                        try {
                            $mailResp = Invoke-GraphRequestWithThrottleHandling -Method GET `
                                -Uri ("https://graph.microsoft.com/v1.0/directory/deletedItems/microsoft.graph.user?`$filter=mail eq '" + $escapedUpn + "'&`$select=id,displayName,userPrincipalName,deletedDateTime,mail") `
                                -Headers (Get-AuthHeader)
                            if ($mailResp.value -and $mailResp.value.Count -gt 0) {
                                $du = $mailResp.value[0]
                                Write-Log INFO "    -> Found via mail attribute (UPN was mutated on deletion)"
                            }
                        }
                        catch {
                            Write-Log WARN "    -> mail fallback query failed: $_"
                        }
                    }

                    if ($du) {
                        $map[$key] = @{
                            IsDeleted         = $true
                            IsDisabled        = $false
                            DeletedDateTime   = $du.deletedDateTime
                            DisplayName       = $du.displayName
                            UserPrincipalName = $du.userPrincipalName
                            ObjId             = $du.id
                        }
                        Write-Log INFO "    -> Soft-deleted (deleted $($du.deletedDateTime))"
                    }
                    else {
                        # Not in active directory or recycle bin — deletion date cannot be determined
                        Write-Log WARN "    -> User $upn not found in active directory or recycle bin (deleted with unknown date or hard-deleted)"
                        $map[$key] = @{
                            IsDeleted         = $true
                            IsDisabled        = $false
                            DeletedDateTime   = $null
                            DisplayName       = $null
                            UserPrincipalName = $upn
                            ObjId             = $null
                        }
                    }
                }
                catch {
                    Write-Log WARN "    -> Could not look up deleted items for $upn : $_"
                    $map[$key] = @{ IsDeleted = $true; IsDisabled = $false; DeletedDateTime = $null; DisplayName = $null; UserPrincipalName = $upn; ObjId = $null }
                }
            }
            else {
                Write-Log WARN "    -> Unexpected error resolving $upn : $_"
                $map[$key] = @{ IsDeleted = $false; IsDisabled = $false; DeletedDateTime = $null; DisplayName = $null; UserPrincipalName = $upn; ObjId = $null }
            }
        }
    }
    return $map
}

#endregion User Resolution

#region Audit Functions

function Get-UserBucket([string]$upnLower) {
    if (-not $userAgg.ContainsKey($upnLower)) {
        $userAgg[$upnLower] = @{
            UserPrincipalName = $upnLower
            DisplayName       = $null
            FirstSeenUtc      = $null
            LastSeenUtc       = $null
            TotalEvents       = 0
            CreateFormCount   = 0
            MoveFormCount     = 0
            DeleteFormCount   = 0
            AddCoauthorCount  = 0
            ExportFormCount   = 0
            OperationsSeen    = New-Object System.Collections.Generic.HashSet[string]
            Forms             = @{}   # FormId -> FormName
        }
    }
    return $userAgg[$upnLower]
}

function ConvertTo-NormalizedFormsUserId([string]$userId) {
    if ([string]::IsNullOrWhiteSpace($userId)) { return $null }

    $u = $userId.Trim()

    # Ignore urn:forms:* patterns for anonymous/external responders
    if ($u.StartsWith('urn:forms:', [System.StringComparison]::OrdinalIgnoreCase)) { return $null }

    # Accept UPNs (contain @) and object IDs (hex GUIDs without hyphens or standard GUID format)
    return $u.ToLowerInvariant()
}

function Invoke-GraphAuditQuery {
    param(
        [datetime]$StartUtc,
        [datetime]$EndUtc
    )

    Write-Log INFO "Submitting Graph audit query: $StartUtc -> $EndUtc"

    $queryBody = @{
        displayName         = "FormsRisk-$runStamp"
        filterStartDateTime = $StartUtc.ToString('yyyy-MM-ddTHH:mm:ssZ')
        filterEndDateTime   = $EndUtc.ToString('yyyy-MM-ddTHH:mm:ssZ')
        recordTypeFilters   = @('microsoftForms')
    } | ConvertTo-Json -Depth 3

    # Submit the query
    $createResp = Invoke-WithRetry -OperationName 'POST auditLog/queries' -ScriptBlock {
        Invoke-GraphRequestWithThrottleHandling `
            -Method      POST `
            -Uri         'https://graph.microsoft.com/beta/security/auditLog/queries' `
            -Headers     (Get-AuthHeader) `
            -Body        $queryBody `
            -ContentType 'application/json'
    }

    $queryId = $createResp.id
    Write-Log INFO "Audit query created: $queryId — polling for completion..."

    # Poll until succeeded or failed (max 30 minutes)
    $pollUri = "https://graph.microsoft.com/beta/security/auditLog/queries/$queryId"
    $pollIntervalSec = 10
    $maxPollSec = 1800
    $elapsed = 0

    while ($true) {
        Start-Sleep -Seconds $pollIntervalSec
        $elapsed += $pollIntervalSec

        $statusResp = Invoke-WithRetry -OperationName "GET auditLog/queries/$queryId status" -ScriptBlock {
            Invoke-GraphRequestWithThrottleHandling -Method GET -Uri $pollUri -Headers (Get-AuthHeader)
        }

        $status = if ($statusResp.PSObject.Properties['status']) { [string]$statusResp.status } else { 'unknown' }
        Write-Log INFO "  Query status: $status (elapsed: ${elapsed}s)"

        if ($status -eq 'succeeded') { break }
        if ($status -eq 'failed') {
            Write-Log ERROR "Audit query $queryId failed."
            throw "Graph audit query failed: $queryId"
        }
        if ($elapsed -ge $maxPollSec) {
            Write-Log ERROR "Audit query $queryId timed out after ${maxPollSec}s."
            throw "Graph audit query timed out: $queryId"
        }
    }

    # Page through all records
    $recordsUri = "https://graph.microsoft.com/beta/security/auditLog/queries/$queryId/records?`$top=1000"
    $total = 0
    while ($recordsUri) {
        $page = Invoke-WithRetry -OperationName "GET auditLog/queries/$queryId/records" -ScriptBlock {
            Invoke-GraphRequestWithThrottleHandling -Method GET -Uri $recordsUri -Headers (Get-AuthHeader)
        }
        foreach ($r in $page.value) { $rawEvents.Add($r) | Out-Null }
        $total += @($page.value).Count
        $recordsUri = if ($page.PSObject.Properties['@odata.nextLink']) { $page.'@odata.nextLink' } else { $null }
        Write-Log INFO "  Fetched $total records so far..."
    }

    Write-Log INFO "Audit query complete. Total records: $total"
}

#endregion Audit Functions

#region Script Execution

#region Environment Setup
New-FolderIfMissing $OutputFolder
$runStamp = (Get-Date).ToString("yyyyMMdd-HHmmss")
$script:LogFile = Join-Path $OutputFolder "FormsOrphanRisk-$runStamp.log"
Write-Log INFO "Starting Forms orphan risk run. LookbackDays=$LookbackDays, OrphanWindowDays=$OrphanWindowDays"
#endregion Environment Setup

#region Authenticate
AcquireToken
#endregion Authenticate

#region Collect Audit Data
if ($IncludeResponseSignals) {
    $Operations += @("CreateResponse", "SubmitResponse", "ViewRuntimeForm", "ViewResponse", "ViewResponses")
    $Operations = $Operations | Select-Object -Unique
    Write-Log WARN "IncludeResponseSignals enabled; this may increase volume significantly."
}
$endUtc = (Get-Date).ToUniversalTime()
$startUtc = $endUtc.AddDays(-1 * $LookbackDays)
$userAgg = @{}  # key: lower UPN, value: hashtable stats
$rawEvents = New-Object System.Collections.Generic.List[object]
Write-Log INFO "Audit query UTC window: $startUtc -> $endUtc"
Write-Log INFO "RecordType filter: microsoftForms (via Graph auditLog/queries)"
Invoke-GraphAuditQuery -StartUtc $startUtc -EndUtc $endUtc
#endregion Collect Audit Data

#region Parse and Aggregate
Write-Log INFO "Total raw audit rows collected: $($rawEvents.Count)"
Write-Log INFO "Parsing audit records and aggregating per user..."

foreach ($ev in $rawEvents) {
    $op = [string]$ev.operation
    if ($op -notin $Operations) { continue }

    # auditData.UserId is the real UPN; ev.userId is a PUID used internally by Forms
    $rawUserId = [string]$ev.userId
    if ($ev.PSObject.Properties['auditData'] -and $ev.auditData -and
        $ev.auditData.PSObject.Properties['UserId'] -and $ev.auditData.UserId) {
        $rawUserId = [string]$ev.auditData.UserId
    }

    $user = ConvertTo-NormalizedFormsUserId $rawUserId
    if (-not $user) { continue }

    $when = $null
    if ($ev.createdDateTime) {
        $when = [datetime]$ev.createdDateTime
    }

    $bucket = Get-UserBucket $user
    $bucket.TotalEvents++

    if ($when) {
        if (-not $bucket.FirstSeenUtc -or $when -lt $bucket.FirstSeenUtc) { $bucket.FirstSeenUtc = $when }
        if (-not $bucket.LastSeenUtc -or $when -gt $bucket.LastSeenUtc) { $bucket.LastSeenUtc = $when }
    }

    if ($op) { [void]$bucket.OperationsSeen.Add($op) }

    # Track unique forms for this user
    if ($ev.PSObject.Properties['auditData'] -and $ev.auditData) {
        $fid = if ($ev.auditData.PSObject.Properties['FormId'] -and $ev.auditData.FormId) { [string]$ev.auditData.FormId }   else { $null }
        if ($fid -and -not $bucket.Forms.ContainsKey($fid)) {
            $fname = if ($ev.auditData.PSObject.Properties['FormName'] -and $ev.auditData.FormName) { [string]$ev.auditData.FormName } else { '(unknown)' }
            $bucket.Forms[$fid] = $fname
        }
    }

    switch ($op) {
        'CreateForm' { $bucket.CreateFormCount++ }
        'MoveForm' { $bucket.MoveFormCount++ }
        'DeleteForm' { $bucket.DeleteFormCount++ }
        'AddFormCoauthor' { $bucket.AddCoauthorCount++ }
        'ExportForm' { $bucket.ExportFormCount++ }
    }
}

Write-Log INFO "Users with Forms activity (post-normalization): $($userAgg.Count)"

#endregion Parse and Aggregate

#region Resolve User Status
# --------------------------
# Resolve live user status (deleted / disabled / active) for every audit user
# Live lookups fix UPN-mutation issues when Entra modifies a user's UPN on deletion.
# --------------------------
Write-Log INFO "Resolving live Entra user status for $($userAgg.Count) unique audit users..."
$userStatusMap = Resolve-UserStatusMap -Upns @($userAgg.Keys)
#endregion Resolve User Status

#region Build Report
# --------------------------
# Build final report (join to user status -> orphan risk)
# --------------------------
$nowUtc = (Get-Date).ToUniversalTime()

$report = foreach ($kvp in $userAgg.GetEnumerator()) {
    $upnLower = $kvp.Key
    $b = $kvp.Value

    $status = if ($userStatusMap.ContainsKey($upnLower)) { $userStatusMap[$upnLower] } else { $null }
    $isDeleted = $status -and $status.IsDeleted
    $isDisabled = $status -and $status.IsDisabled

    # Only report on users whose account is deleted or disabled
    if (-not $isDeleted -and -not $isDisabled) { continue }

    $daysSinceDeleted = $null
    $inOrphanWindow = $false

    if ($isDeleted -and $status.DeletedDateTime) {
        $dd = [datetime]$status.DeletedDateTime
        $daysSinceDeleted = [Math]::Round(($nowUtc - $dd).TotalDays, 2)
        $inOrphanWindow = ($daysSinceDeleted -le $OrphanWindowDays)
    }

    # "Owner likelihood" heuristic:
    # CreateForm and MoveForm are strong ownership signals.
    $ownerLikelihood = if (($b.CreateFormCount + $b.MoveFormCount) -gt 0) { "High" } else { "Medium" }

    $risk = "Low"
    $action = "No action"
    if ($isDeleted -and $inOrphanWindow -and $ownerLikelihood -eq "High") {
        $risk = "HIGH"
        $action = "Recover/transfer Forms now (user in deleted window)"
    }
    elseif ($isDeleted -and $inOrphanWindow) {
        $risk = "HIGH"
        $action = "Investigate quickly (user in deleted window; Forms activity seen)"
    }
    elseif ($isDeleted -and $null -eq $status.DeletedDateTime) {
        # Deletion date unknown (Entra UPN mutation prevented recycle-bin match)
        # Be conservative: assume still within the orphan window
        $inOrphanWindow = $true
        $risk = "HIGH"
        $action = "User deleted (deletion date unknown — UPN may have been renamed); verify in Entra and transfer Forms"
    }
    elseif ($isDeleted) {
        # Deleted and confirmed outside the 30-day window — forms permanently gone
        $risk = "Low"
        $action = "Forms likely permanently deleted (user was deleted $([Math]::Round($daysSinceDeleted,0)) days ago, beyond the $OrphanWindowDays-day window)"
    }
    elseif ($isDisabled -and $ownerLikelihood -eq "High") {
        $risk = "Medium"
        $action = "User account disabled — move Forms to group ownership before account is deleted"
    }
    elseif ($isDisabled) {
        $risk = "Low"
        $action = "User account disabled — review if Forms ownership needs transferring"
    }
    elseif ($ownerLikelihood -eq "High") {
        $risk = "Low"
        $action = "Proactively move business-critical Forms to group ownership"
    }

    # Resolve display UPN: prefer the canonical UPN from the live lookup, then audit record
    $resolvedUpn = if ($status -and $status.UserPrincipalName) { $status.UserPrincipalName } else { $b.UserPrincipalName }

    # Days until permanent deletion (30-day soft-delete window)
    $daysUntilPerm = if ($isDeleted -and $null -ne $daysSinceDeleted) {
        [Math]::Round([Math]::Max(0, $OrphanWindowDays - $daysSinceDeleted), 1)
    }
    else { $null }

    # Build delegatepage.aspx recovery URLs — one per unique form owned by this user.
    # Use $upnLower (the audit-log UPN = pre-deletion email) as originalowner; $resolvedUpn
    # may contain a GUID suffix that Entra appends when mutating the UPN on soft-deletion.
    $recoveryUrls = foreach ($fid in $b.Forms.Keys) {
        "https://forms.office.com/Pages/delegatepage.aspx?originalowner=$([System.Uri]::EscapeDataString($upnLower))&formid=$fid"
    }

    [pscustomobject]@{
        UserPrincipalName          = $resolvedUpn
        OwnerLikelihood            = $ownerLikelihood
        RiskLevel                  = $risk
        DaysUntilPermanentDeletion = $daysUntilPerm
        RecommendedAction          = $action
        FormCount                  = $b.Forms.Count
        FormNames                  = ($b.Forms.Values | Sort-Object) -join ";"
        FormIds                    = ($b.Forms.Keys) -join ";"
        RecoveryUrls               = $recoveryUrls -join ";"
        TotalEvents                = $b.TotalEvents
        FirstSeenUtc               = $b.FirstSeenUtc
        LastSeenUtc                = $b.LastSeenUtc
        CreateFormCount            = $b.CreateFormCount
        MoveFormCount              = $b.MoveFormCount
        DeleteFormCount            = $b.DeleteFormCount
        AddFormCoauthorCount       = $b.AddCoauthorCount
        ExportFormCount            = $b.ExportFormCount
        OperationsSeen             = ($b.OperationsSeen | Sort-Object) -join ";"
        IsDeletedUser              = [bool]$isDeleted
        IsDisabledUser             = [bool]$isDisabled
        DeletedDateTimeUtc         = if ($isDeleted) { $status.DeletedDateTime } else { $null }
        DaysSinceDeleted           = $daysSinceDeleted
        InOrphanWindow             = $inOrphanWindow
    }
}

#endregion Build Report

#region Output
$reportCsv = Join-Path $OutputFolder "Forms-Orphan-Risk-Report-$runStamp.csv"
$eventsCsv = Join-Path $OutputFolder "Forms-Raw-Audit-$runStamp.csv"

$report | Sort-Object @{E = 'IsDeletedUser'; D = $true }, @{E = 'IsDisabledUser'; D = $true }, @{E = 'DaysUntilPermanentDeletion'; D = $false }, @{E = 'TotalEvents'; D = $true } |
Export-Csv -NoTypeInformation -LiteralPath $reportCsv

# Raw events can be large; export minimal columns for analysis
$rawEvents |
Select-Object createdDateTime, userId, operation, auditLogRecordType, auditData |
Export-Csv -NoTypeInformation -LiteralPath $eventsCsv

Write-Log INFO "Report written: $reportCsv"
Write-Log INFO "Raw audit export written: $eventsCsv"
Write-Log INFO "Done."

#endregion Output

#region Email Notifications
if ($SendEmailNotifications) {
    Write-Log INFO "Sending Forms orphan alert email..."

    # Filter report rows by the configured minimum risk level
    $riskOrder = @{ 'HIGH' = 1; 'Medium' = 2; 'Low' = 3 }
    $minRank = if ($riskOrder.ContainsKey($EmailMinRiskLevel)) { $riskOrder[$EmailMinRiskLevel] } else { 1 }

    $emailCandidates = @($report | Where-Object {
            $riskOrder.ContainsKey($_.RiskLevel) -and $riskOrder[$_.RiskLevel] -le $minRank
        })

    if ($emailCandidates.Count -gt 0) {
        Write-Log INFO "  $($emailCandidates.Count) account(s) meet the '$EmailMinRiskLevel' threshold — sending alert."
        Send-FormsOrphanAlertEmail -AffectedAccounts $emailCandidates
    }
    else {
        Write-Log INFO "  No accounts meet the '$EmailMinRiskLevel' risk threshold — email skipped."
    }
}
else {
    Write-Log INFO "Email notifications skipped (`$SendEmailNotifications = `$false)."
}
#endregion Email Notifications

#endregion Script Execution<#
.SYNOPSIS
Produces a "Forms orphan risk" report:
- This script creates an inventory report to identify Orphaned Microsoft Forms allowing Admins to restore the Form before it's permanently deleted.
    - Detects likely user-owned Forms by mining Unified Audit Log "MicrosoftForms" events
    - Flags orphan risk by joining to Entra soft-deleted users (30-day window)

.DESCRIPTION
  This is a signal-based inventory because Microsoft Forms doesn't provide a tenant-wide admin inventory API.
It relies on Microsoft Purview audit log "Forms activities" (CreateForm, MoveForm, etc.) to identify likely owners. 
[1](https://learn.microsoft.com/en-us/purview/audit-log-activities)

Batching:
- Uses the Graph Audit Log Query API (POST /security/auditLog/queries).
- Results are fully paginated via @odata.nextLink — no per-query row-count limit.
- Query is submitted async; script polls until status = succeeded, then pages all records.

Orphan risk:
- Any user found in Entra "deletedItems" is within the soft-delete window (commonly 30 days). The report computes
DaysSinceDeleted and flags <= OrphanWindowDays as HIGH.

.NOTES
Requires:
- App registration with: AuditLogsQuery.Read.All, User.Read.All, Directory.Read.All, Mail.Send
- Mail.Send is required only when $SendEmailNotifications = $true (used by Send-FormsOrphanAlertEmail)
- No PowerShell modules required — all calls use Invoke-RestMethod against Graph API

Created by: Mike Lee
Created Date: 5/4/2026
Updated: 5/6/2026 - Added support for e-mail notifications

Authentication:
- Graph API only: client-credentials token via AcquireToken() using certificate or client secret
#>

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

#region Configuration
##############################################################
#                  CONFIGURATION SECTION                     #
##############################################################

# ---- Debug output ----
$debug = $false

# ---- Tenant & App Registration ----
$tenantId = '9cfc42cb-51da-4055-87e9-b20a170b6ba3'
$clientId = 'abc64618-283f-47ba-a185-50d935d51d57'

# ---- Authentication type: 'Certificate' or 'ClientSecret' ----
$AuthType = 'Certificate'

# Certificate thumbprint (used when $AuthType = 'Certificate')
$Thumbprint = 'B696FDCFE1453F3FBC6031F54DE988DA0ED905A9'

# Certificate store: 'LocalMachine' or 'CurrentUser'
$CertStore = 'LocalMachine'

# Client Secret (used when $AuthType = 'ClientSecret')
$clientSecret = ''

# ---- Audit query window ----
$LookbackDays = 31    # How far back to search Forms audit activity (days)
$OrphanWindowDays = 30    # Users deleted within this many days are flagged HIGH risk

# ---- Forms operations to query (owner-leaning / governance-relevant) ----
$Operations = @(
    'CreateForm',
    'MoveForm',
    'DeleteForm',
    'EditForm',
    'ViewForm',
    'ListForms',
    'AddFormCoauthor',
    'RemoveFormCoauthor',
    'AllowShareFormForCopy',
    'DisallowShareFormForCopy',
    'EnableWorkOrSchoolCollaboration',
    'EnableSameOrgCollaboration',
    'EnableSpecificCollaboaration',
    'DisableCollaboration',
    'ExportForm',
    'UpdateFormSetting',
    'GetSummaryLink',
    'DeleteSummaryLink',
    'ConnectToExcelWorkbook'
)

# Set $true to include responder operations (CreateResponse/SubmitResponse); increases volume and may add noise
$IncludeResponseSignals = $false

# ---- Output folder ----
$OutputFolder = $env:TEMP

# ---- Request throttling ----
$MaxRetries = 15
$InitialBackoffSec = 3
$RequestTimeoutSec = 300

# ---- Email Notifications ----
# Set $SendEmailNotifications = $true to send an alert email after the report runs.
# An email is sent listing all HIGH (and optionally Medium) risk orphaned Forms accounts.
$SendEmailNotifications = $false

# Recipients — individual addresses or mail-enabled group/distribution-list addresses.
$EmailTo = @(
    'admin@M365CPI13246019.onmicrosoft.com'
)

# Sender address — must be a licensed Exchange Online mailbox in the tenant.
# The app registration must have Mail.Send (Application) permission granted in Entra ID.
# Email is sent via Graph API (POST /users/{EmailFrom}/sendMail) — no SMTP relay needed.
$EmailFrom = 'admin@M365CPI13246019.onmicrosoft.com'

# Minimum risk level to include in the alert email: 'HIGH', 'Medium', or 'Low'
$EmailMinRiskLevel = 'HIGH'

##############################################################
#                END CONFIGURATION SECTION                   #
##############################################################
#endregion Configuration

#region Initialization
$global:token = $null
$global:tokenExpiry = $null

# Required for HTML-encoding display names and UPNs in alert email bodies
Add-Type -AssemblyName System.Web
#endregion Initialization

#region Helper Functions

function Invoke-GraphRequestWithThrottleHandling {
    <#
    .SYNOPSIS
        Wraps Invoke-RestMethod with Retry-After / exponential-backoff throttle handling
        for Microsoft Graph API calls (429, 502, 503, 504, timeouts).
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)] [string]   $Uri,
        [Parameter(Mandatory)] [string]   $Method,
        [Parameter()]          [hashtable] $Headers = @{},
        [Parameter()]          [string]    $Body = $null,
        [Parameter()]          [string]    $ContentType = 'application/json',
        [Parameter()]          [int]      $MaxRetries = $script:MaxRetries,
        [Parameter()]          [int]      $InitialBackoffSeconds = $script:InitialBackoffSec,
        [Parameter()]          [int]      $TimeoutSeconds = $script:RequestTimeoutSec
    )

    $retryCount = 0
    $backoffSec = $InitialBackoffSeconds
    $result = $null

    if ($debug) { Write-Host "  Graph -> $Method $Uri" -ForegroundColor DarkGray }

    while ($retryCount -le $MaxRetries) {
        try {
            $invokeParams = @{
                Uri         = $Uri
                Method      = $Method
                Headers     = $Headers
                ContentType = $ContentType
                TimeoutSec  = $TimeoutSeconds
                ErrorAction = 'Stop'
                Verbose     = $false
            }
            if ($Body) { $invokeParams['Body'] = $Body }

            $result = Invoke-RestMethod @invokeParams
            return $result
        }
        catch {
            $statusCode = $null
            if ($_.Exception.Response) {
                $statusCode = [int]$_.Exception.Response.StatusCode
            }

            $isRetryable = $statusCode -in @(429, 502, 503, 504) -or
            $_.Exception -is [System.Net.WebException] -and (
                $_.Exception.Status -eq [System.Net.WebExceptionStatus]::Timeout -or
                $_.Exception.Status -eq [System.Net.WebExceptionStatus]::ConnectionClosed
            )

            if (-not $isRetryable) {
                $detail = if ($_.ErrorDetails.Message) { " | API response: $($_.ErrorDetails.Message)" } else { '' }
                throw "$($_.Exception.Message)$detail"
            }

            if ($retryCount -ge $MaxRetries) {
                Write-Host "    Max retries reached for: $Uri" -ForegroundColor Red
                throw $_
            }

            $waitSec = $backoffSec
            if ($statusCode -eq 429) {
                try {
                    $ra = $_.Exception.Response.Headers['Retry-After']
                    if ($ra) { $waitSec = [int]$ra }
                }
                catch {}
            }

            $retryCount++
            Write-Host "    Throttled ($statusCode). Waiting ${waitSec}s (attempt $retryCount/$MaxRetries)..." -ForegroundColor Yellow
            Start-Sleep -Seconds $waitSec
            $backoffSec = [Math]::Min($backoffSec * 2, 300)
        }
    }
}

#endregion Helper Functions

#region Authentication Functions

function AcquireToken {
    <#
    .SYNOPSIS
        Acquires a Microsoft Graph access token (scope: graph.microsoft.com/.default).
        One token covers all Graph endpoints across all geo datacenters.
    #>
    Write-Host "Authenticating to Microsoft Graph ($AuthType)..." -ForegroundColor Cyan

    $scope = 'https://graph.microsoft.com/.default'
    $tokenUri = "https://login.microsoftonline.com/$tenantId/oauth2/v2.0/token"

    if ($AuthType -eq 'ClientSecret') {
        $body = @{
            grant_type    = 'client_credentials'
            client_id     = $clientId
            client_secret = $clientSecret
            scope         = $scope
        }
        try {
            $resp = Invoke-RestMethod -Method Post -Uri $tokenUri -Body $body `
                -ContentType 'application/x-www-form-urlencoded' -ErrorAction Stop -Verbose:$false
            $global:token = $resp.access_token
            $expiresIn = if ($resp.expires_in) { $resp.expires_in } else { 3600 }
            $global:tokenExpiry = (Get-Date).AddSeconds($expiresIn - 300)
            Write-Host "  Connected via Client Secret. Token valid until: $($global:tokenExpiry)" -ForegroundColor Green
        }
        catch {
            Write-Host "  Authentication failed (ClientSecret): $($_.Exception.Message)" -ForegroundColor Red
            Exit
        }
    }
    elseif ($AuthType -eq 'Certificate') {
        try {
            $cert = Get-Item -Path "Cert:\$CertStore\My\$Thumbprint" -ErrorAction Stop
        }
        catch {
            Write-Host "  Certificate $Thumbprint not found in $CertStore\My store." -ForegroundColor Red
            Exit
        }

        $now = [System.DateTimeOffset]::UtcNow
        $exp = $now.AddMinutes(10).ToUnixTimeSeconds()
        $nbf = $now.ToUnixTimeSeconds()

        $header = @{ alg = 'RS256'; typ = 'JWT'; x5t = [Convert]::ToBase64String($cert.GetCertHash()).TrimEnd('=').Replace('+', '-').Replace('/', '_') } | ConvertTo-Json -Compress
        $payload = @{ aud = $tokenUri; exp = $exp; iss = $clientId; jti = [System.Guid]::NewGuid().ToString(); nbf = $nbf; sub = $clientId } | ConvertTo-Json -Compress

        $hB64 = [Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($header)).TrimEnd('=').Replace('+', '-').Replace('/', '_')
        $pB64 = [Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($payload)).TrimEnd('=').Replace('+', '-').Replace('/', '_')
        $toSign = "$hB64.$pB64"
        $rsa = [System.Security.Cryptography.X509Certificates.RSACertificateExtensions]::GetRSAPrivateKey($cert)
        if (-not $rsa) {
            Write-Host "  Unable to access RSA private key for certificate $Thumbprint." -ForegroundColor Red
            Exit
        }
        $sig = $rsa.SignData(
            [System.Text.Encoding]::UTF8.GetBytes($toSign),
            [System.Security.Cryptography.HashAlgorithmName]::SHA256,
            [System.Security.Cryptography.RSASignaturePadding]::Pkcs1)
        $jwt = "$toSign.$([Convert]::ToBase64String($sig).TrimEnd('=').Replace('+', '-').Replace('/', '_'))"

        $body = @{
            client_id             = $clientId
            client_assertion_type = 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer'
            client_assertion      = $jwt
            scope                 = $scope
            grant_type            = 'client_credentials'
        }

        try {
            $resp = Invoke-RestMethod -Method Post -Uri $tokenUri -Body $body `
                -ContentType 'application/x-www-form-urlencoded' -ErrorAction Stop -Verbose:$false
            $global:token = $resp.access_token
            $expiresIn = if ($resp.expires_in) { $resp.expires_in } else { 3600 }
            $global:tokenExpiry = (Get-Date).AddSeconds($expiresIn - 300)
            Write-Host "  Connected via Certificate. Token valid until: $($global:tokenExpiry)" -ForegroundColor Green
        }
        catch {
            Write-Host "  Authentication failed (Certificate): $($_.Exception.Message)" -ForegroundColor Red
            Exit
        }
    }
    else {
        Write-Host "  Invalid AuthType '$AuthType'. Use 'Certificate' or 'ClientSecret'." -ForegroundColor Red
        Exit
    }
}

function Test-ValidToken {
    if ($null -eq $global:tokenExpiry -or (Get-Date) -gt $global:tokenExpiry) {
        Write-Host 'Token expired or expiring soon — refreshing...' -ForegroundColor Yellow
        AcquireToken
    }
}

function Get-AuthHeader {
    Test-ValidToken
    return @{ Authorization = "Bearer $($global:token)" }
}

#endregion Authentication Functions

#region Logging Functions

# --------------------------
# Logging helpers
# --------------------------
function New-FolderIfMissing([string]$Path) {
    if (-not (Test-Path -LiteralPath $Path)) { New-Item -ItemType Directory -Path $Path | Out-Null }
}

function Write-Log {
    param(
        [ValidateSet("INFO", "WARN", "ERROR", "DEBUG")] [string]$Level,
        [string]$Message
    )
    $ts = (Get-Date).ToString("s")
    $line = "[$ts][$Level] $Message"
    Write-Host $line
    Add-Content -LiteralPath $script:LogFile -Value $line
}

function Invoke-WithRetry {
    param(
        [scriptblock]$ScriptBlock,
        [int]$MaxAttempts = 6,
        [int]$BaseDelaySeconds = 2,
        [string]$OperationName = "operation"
    )

    for ($attempt = 1; $attempt -le $MaxAttempts; $attempt++) {
        try {
            return & $ScriptBlock
        }
        catch {
            $msg = $_.Exception.Message
            if ($attempt -eq $MaxAttempts) {
                Write-Log -Level "ERROR" -Message "FAILED $OperationName after $MaxAttempts attempts. Last error: $msg"
                throw
            }

            # Do not retry auth/permission errors — they will never self-resolve
            if ($msg -match '401|403|Unauthorized|Forbidden|dont have any permissions') {
                Write-Log -Level "ERROR" -Message "Non-retryable auth error for $OperationName : $msg"
                throw
            }

            # Exponential backoff + jitter
            $delay = [Math]::Min(60, $BaseDelaySeconds * [Math]::Pow(2, $attempt - 1))
            $jitter = Get-Random -Minimum 0 -Maximum 1000
            $sleepMs = ($delay * 1000) + $jitter

            Write-Log -Level "WARN" -Message "Retry $attempt/$MaxAttempts for $OperationName due to: $msg. Sleeping $([Math]::Round($sleepMs/1000,2))s"
            Start-Sleep -Milliseconds $sleepMs
        }
    }
}

#endregion Logging Functions

#region Email Functions

function Send-FormsOrphanAlertEmail {
    <#
    .SYNOPSIS
        Sends an HTML alert email to the admin list ($EmailTo) summarising orphaned
        Microsoft Forms accounts whose owners have been deleted and whose Forms are at
        risk of permanent deletion.

        Uses the Microsoft Graph API (POST /users/{EmailFrom}/sendMail) with the
        existing bearer token — no SMTP relay required.
        Requires $SendEmailNotifications = $true and Mail.Send (Application) on the
        app registration.
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)] [object[]] $AffectedAccounts
    )

    if ($AffectedAccounts.Count -eq 0) { return }

    $subject = "[Forms Orphan Alert] $($AffectedAccounts.Count) account(s) with orphaned Forms require attention — Tenant: $script:tenantId"

    # Build HTML table rows, sorted by days until permanent deletion (most urgent first)
    $sortedAccounts = $AffectedAccounts | Sort-Object {
        if ($null -ne $_.DaysUntilPermanentDeletion) { $_.DaysUntilPermanentDeletion } else { 999 }
    }

    $tableRows = foreach ($acct in $sortedAccounts) {
        $daysLeft = if ($null -ne $acct.DaysUntilPermanentDeletion) { "$($acct.DaysUntilPermanentDeletion)" } else { 'N/A' }
        $daysNum = if ($null -ne $acct.DaysUntilPermanentDeletion) { [double]$acct.DaysUntilPermanentDeletion } else { 999 }

        # Row colour: red shading <= 3 days, amber <= 7 days, white otherwise
        $rowColor = if ($daysNum -le 3) { '#fde8e8' } elseif ($daysNum -le 7) { '#fff3cd' } else { '#ffffff' }

        $safeUpn = [System.Web.HttpUtility]::HtmlEncode($acct.UserPrincipalName)
        $safeAction = [System.Web.HttpUtility]::HtmlEncode($acct.RecommendedAction)
        $safeRisk = [System.Web.HttpUtility]::HtmlEncode($acct.RiskLevel)
        $safeForms = [System.Web.HttpUtility]::HtmlEncode($acct.FormNames)

        # Build recovery URL hyperlinks — one per form
        $urlLinks = if ($acct.RecoveryUrls) {
            $urls = $acct.RecoveryUrls -split ';' | Where-Object { $_ }
            ($urls | ForEach-Object { "<a href='$_'>Recover</a>" }) -join ' | '
        }
        else { 'N/A' }

        "<tr style='background-color:$rowColor;'>
          <td style='padding:5px 10px;border:1px solid #d0d0d0;'>$safeUpn</td>
          <td style='padding:5px 10px;border:1px solid #d0d0d0;text-align:center;'>$safeRisk</td>
          <td style='padding:5px 10px;border:1px solid #d0d0d0;text-align:center;'>$($acct.FormCount)</td>
          <td style='padding:5px 10px;border:1px solid #d0d0d0;'>$safeForms</td>
          <td style='padding:5px 10px;border:1px solid #d0d0d0;text-align:center;'>$daysLeft</td>
          <td style='padding:5px 10px;border:1px solid #d0d0d0;'>$safeAction</td>
          <td style='padding:5px 10px;border:1px solid #d0d0d0;'>$urlLinks</td>
        </tr>"
    }

    $headerColor = '#1a5276'
    $alertHeading = "Forms Orphan Alert — $($AffectedAccounts.Count) account(s) with orphaned Forms require immediate attention"

    $body = @"
<!DOCTYPE html>
<html>
<body style="font-family:Segoe UI,Arial,sans-serif;font-size:14px;color:#222;margin:20px;">
  <h2 style="color:$headerColor;margin-bottom:4px;">$alertHeading</h2>
  <p style="margin-top:0;color:#555;font-size:13px;">
    Tenant: <strong>$script:tenantId</strong> &nbsp;|&nbsp;
    Report date: <strong>$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')</strong> &nbsp;|&nbsp;
    Orphan window: <strong>$script:OrphanWindowDays days</strong>
  </p>
  <p>
    The accounts below have been deleted and their Microsoft Forms are at risk of
    permanent deletion when the soft-delete window expires. Please recover or transfer
    Forms ownership immediately using the recovery links provided.
  </p>
  <table style="border-collapse:collapse;width:100%;font-size:13px;">
    <thead>
      <tr style="background-color:$headerColor;color:#fff;">
        <th style="padding:6px 10px;border:1px solid #999;text-align:left;">User (UPN)</th>
        <th style="padding:6px 10px;border:1px solid #999;text-align:center;">Risk</th>
        <th style="padding:6px 10px;border:1px solid #999;text-align:center;">Form Count</th>
        <th style="padding:6px 10px;border:1px solid #999;text-align:left;">Form Names</th>
        <th style="padding:6px 10px;border:1px solid #999;text-align:center;">Days Until Permanent Deletion</th>
        <th style="padding:6px 10px;border:1px solid #999;text-align:left;">Recommended Action</th>
        <th style="padding:6px 10px;border:1px solid #999;text-align:left;">Recovery Links</th>
      </tr>
    </thead>
    <tbody>
      $($tableRows -join "`n      ")
    </tbody>
  </table>
  <br/>
  <p style="font-size:12px;color:#888;">
    Full report saved to: $script:reportCsv<br/>
    Generated by OrphanedForms-Report.ps1
  </p>
</body>
</html>
"@

    # Build the Graph sendMail payload.
    # toRecipients is constructed from the $EmailTo array — each address becomes
    # a separate emailAddress object so both individual mailboxes and mail-enabled
    # groups are handled correctly.
    $toRecipients = @($script:EmailTo | ForEach-Object {
            @{ emailAddress = @{ address = $_ } }
        })

    $graphMailBody = @{
        message         = @{
            subject      = $subject
            body         = @{ contentType = 'HTML'; content = $body }
            toRecipients = $toRecipients
        }
        saveToSentItems = $false
    } | ConvertTo-Json -Depth 6 -Compress

    # The sender mailbox must match $EmailFrom. With app-only auth the call is
    # POST /users/{sender}/sendMail — /me is not valid for client-credentials tokens.
    $sendUri = "https://graph.microsoft.com/v1.0/users/$([Uri]::EscapeDataString($script:EmailFrom))/sendMail"

    Test-ValidToken
    $headers = @{ Authorization = "Bearer $global:token" }

    try {
        Invoke-GraphRequestWithThrottleHandling -Uri $sendUri -Method POST -Headers $headers `
            -Body $graphMailBody -ContentType 'application/json'
        Write-Log INFO "Forms orphan alert email sent to: $($script:EmailTo -join ', ')"
    }
    catch {
        Write-Log ERROR "Forms orphan alert email send failed: $($_.Exception.Message)"
        Write-Host "  Verify: Mail.Send (Application) is granted for app '$script:clientId' in Entra ID." -ForegroundColor Yellow
        Write-Host "  Sender mailbox '$script:EmailFrom' must be a licensed Exchange Online mailbox." -ForegroundColor Yellow
    }
}

#endregion Email Functions

#region User Resolution

function Resolve-UserStatusMap {
    <#
    .SYNOPSIS
        For each UPN seen in audit data, does a live Graph lookup to determine whether
        the user is active, disabled, soft-deleted, or hard-deleted.
        This is more reliable than pre-fetching all deleted items because Entra can
        mutate a user's UPN on deletion (adds a conflict suffix), which breaks key matching.
    #>
    param([string[]]$Upns)

    $map = @{}
    $total = $Upns.Count
    $i = 0
    foreach ($upn in $Upns) {
        $i++
        $key = $upn.ToLowerInvariant()
        Write-Log INFO "  Resolving user status ($i/$total): $upn"
        try {
            # Happy path: user exists in active directory
            $u = Invoke-GraphRequestWithThrottleHandling -Method GET `
                -Uri ("https://graph.microsoft.com/v1.0/users/" + [System.Uri]::EscapeDataString($upn) + "?`$select=id,displayName,userPrincipalName,accountEnabled") `
                -Headers (Get-AuthHeader)
            $map[$key] = @{
                IsDeleted         = $false
                IsDisabled        = (-not [bool]$u.accountEnabled)
                DeletedDateTime   = $null
                DisplayName       = $u.displayName
                UserPrincipalName = $u.userPrincipalName
                ObjId             = $u.id
            }
        }
        catch {
            if ($_.Exception.Message -match '404|ResourceNotFound|does not exist') {
                # Not in active directory — check soft-deleted items filtered by UPN
                try {
                    $escapedUpn = $upn.Replace("'", "''")
                    $delResp = Invoke-GraphRequestWithThrottleHandling -Method GET `
                        -Uri ("https://graph.microsoft.com/v1.0/directory/deletedItems/microsoft.graph.user?`$filter=userPrincipalName eq '" + $escapedUpn + "'&`$select=id,displayName,userPrincipalName,deletedDateTime") `
                        -Headers (Get-AuthHeader)
                    $du = if ($delResp.value -and $delResp.value.Count -gt 0) { $delResp.value[0] } else { $null }

                    # Fallback: Entra mutates the UPN on deletion to free the namespace.
                    # The mail attribute is NOT mutated, so search by mail using the pre-deletion UPN value.
                    if (-not $du) {
                        try {
                            $mailResp = Invoke-GraphRequestWithThrottleHandling -Method GET `
                                -Uri ("https://graph.microsoft.com/v1.0/directory/deletedItems/microsoft.graph.user?`$filter=mail eq '" + $escapedUpn + "'&`$select=id,displayName,userPrincipalName,deletedDateTime,mail") `
                                -Headers (Get-AuthHeader)
                            if ($mailResp.value -and $mailResp.value.Count -gt 0) {
                                $du = $mailResp.value[0]
                                Write-Log INFO "    -> Found via mail attribute (UPN was mutated on deletion)"
                            }
                        }
                        catch {
                            Write-Log WARN "    -> mail fallback query failed: $_"
                        }
                    }

                    if ($du) {
                        $map[$key] = @{
                            IsDeleted         = $true
                            IsDisabled        = $false
                            DeletedDateTime   = $du.deletedDateTime
                            DisplayName       = $du.displayName
                            UserPrincipalName = $du.userPrincipalName
                            ObjId             = $du.id
                        }
                        Write-Log INFO "    -> Soft-deleted (deleted $($du.deletedDateTime))"
                    }
                    else {
                        # Not in active directory or recycle bin — deletion date cannot be determined
                        Write-Log WARN "    -> User $upn not found in active directory or recycle bin (deleted with unknown date or hard-deleted)"
                        $map[$key] = @{
                            IsDeleted         = $true
                            IsDisabled        = $false
                            DeletedDateTime   = $null
                            DisplayName       = $null
                            UserPrincipalName = $upn
                            ObjId             = $null
                        }
                    }
                }
                catch {
                    Write-Log WARN "    -> Could not look up deleted items for $upn : $_"
                    $map[$key] = @{ IsDeleted = $true; IsDisabled = $false; DeletedDateTime = $null; DisplayName = $null; UserPrincipalName = $upn; ObjId = $null }
                }
            }
            else {
                Write-Log WARN "    -> Unexpected error resolving $upn : $_"
                $map[$key] = @{ IsDeleted = $false; IsDisabled = $false; DeletedDateTime = $null; DisplayName = $null; UserPrincipalName = $upn; ObjId = $null }
            }
        }
    }
    return $map
}

#endregion User Resolution

#region Audit Functions

function Get-UserBucket([string]$upnLower) {
    if (-not $userAgg.ContainsKey($upnLower)) {
        $userAgg[$upnLower] = @{
            UserPrincipalName = $upnLower
            DisplayName       = $null
            FirstSeenUtc      = $null
            LastSeenUtc       = $null
            TotalEvents       = 0
            CreateFormCount   = 0
            MoveFormCount     = 0
            DeleteFormCount   = 0
            AddCoauthorCount  = 0
            ExportFormCount   = 0
            OperationsSeen    = New-Object System.Collections.Generic.HashSet[string]
            Forms             = @{}   # FormId -> FormName
        }
    }
    return $userAgg[$upnLower]
}

function Normalize-FormsUserId([string]$userId) {
    if ([string]::IsNullOrWhiteSpace($userId)) { return $null }

    $u = $userId.Trim()

    # Ignore urn:forms:* patterns for anonymous/external responders
    if ($u.StartsWith('urn:forms:', [System.StringComparison]::OrdinalIgnoreCase)) { return $null }

    # Accept UPNs (contain @) and object IDs (hex GUIDs without hyphens or standard GUID format)
    return $u.ToLowerInvariant()
}

function Invoke-GraphAuditQuery {
    param(
        [datetime]$StartUtc,
        [datetime]$EndUtc
    )

    Write-Log INFO "Submitting Graph audit query: $StartUtc -> $EndUtc"

    $queryBody = @{
        displayName         = "FormsRisk-$runStamp"
        filterStartDateTime = $StartUtc.ToString('yyyy-MM-ddTHH:mm:ssZ')
        filterEndDateTime   = $EndUtc.ToString('yyyy-MM-ddTHH:mm:ssZ')
        recordTypeFilters   = @('microsoftForms')
    } | ConvertTo-Json -Depth 3

    # Submit the query
    $createResp = Invoke-WithRetry -OperationName 'POST auditLog/queries' -ScriptBlock {
        Invoke-GraphRequestWithThrottleHandling `
            -Method      POST `
            -Uri         'https://graph.microsoft.com/beta/security/auditLog/queries' `
            -Headers     (Get-AuthHeader) `
            -Body        $queryBody `
            -ContentType 'application/json'
    }

    $queryId = $createResp.id
    Write-Log INFO "Audit query created: $queryId — polling for completion..."

    # Poll until succeeded or failed (max 30 minutes)
    $pollUri = "https://graph.microsoft.com/beta/security/auditLog/queries/$queryId"
    $pollIntervalSec = 10
    $maxPollSec = 1800
    $elapsed = 0

    while ($true) {
        Start-Sleep -Seconds $pollIntervalSec
        $elapsed += $pollIntervalSec

        $statusResp = Invoke-WithRetry -OperationName "GET auditLog/queries/$queryId status" -ScriptBlock {
            Invoke-GraphRequestWithThrottleHandling -Method GET -Uri $pollUri -Headers (Get-AuthHeader)
        }

        $status = if ($statusResp.PSObject.Properties['status']) { [string]$statusResp.status } else { 'unknown' }
        Write-Log INFO "  Query status: $status (elapsed: ${elapsed}s)"

        if ($status -eq 'succeeded') { break }
        if ($status -eq 'failed') {
            Write-Log ERROR "Audit query $queryId failed."
            throw "Graph audit query failed: $queryId"
        }
        if ($elapsed -ge $maxPollSec) {
            Write-Log ERROR "Audit query $queryId timed out after ${maxPollSec}s."
            throw "Graph audit query timed out: $queryId"
        }
    }

    # Page through all records
    $recordsUri = "https://graph.microsoft.com/beta/security/auditLog/queries/$queryId/records?`$top=1000"
    $total = 0
    while ($recordsUri) {
        $page = Invoke-WithRetry -OperationName "GET auditLog/queries/$queryId/records" -ScriptBlock {
            Invoke-GraphRequestWithThrottleHandling -Method GET -Uri $recordsUri -Headers (Get-AuthHeader)
        }
        foreach ($r in $page.value) { $rawEvents.Add($r) | Out-Null }
        $total += @($page.value).Count
        $recordsUri = if ($page.PSObject.Properties['@odata.nextLink']) { $page.'@odata.nextLink' } else { $null }
        Write-Log INFO "  Fetched $total records so far..."
    }

    Write-Log INFO "Audit query complete. Total records: $total"
}

#endregion Audit Functions

#region Script Execution

#region Environment Setup
New-FolderIfMissing $OutputFolder
$runStamp = (Get-Date).ToString("yyyyMMdd-HHmmss")
$script:LogFile = Join-Path $OutputFolder "FormsOrphanRisk-$runStamp.log"
Write-Log INFO "Starting Forms orphan risk run. LookbackDays=$LookbackDays, OrphanWindowDays=$OrphanWindowDays"
#endregion Environment Setup

#region Authenticate
AcquireToken
#endregion Authenticate

#region Collect Audit Data
if ($IncludeResponseSignals) {
    $Operations += @("CreateResponse", "SubmitResponse", "ViewRuntimeForm", "ViewResponse", "ViewResponses")
    $Operations = $Operations | Select-Object -Unique
    Write-Log WARN "IncludeResponseSignals enabled; this may increase volume significantly."
}
$endUtc = (Get-Date).ToUniversalTime()
$startUtc = $endUtc.AddDays(-1 * $LookbackDays)
$userAgg = @{}  # key: lower UPN, value: hashtable stats
$rawEvents = New-Object System.Collections.Generic.List[object]
Write-Log INFO "Audit query UTC window: $startUtc -> $endUtc"
Write-Log INFO "RecordType filter: microsoftForms (via Graph auditLog/queries)"
Invoke-GraphAuditQuery -StartUtc $startUtc -EndUtc $endUtc
#endregion Collect Audit Data

#region Parse and Aggregate
Write-Log INFO "Total raw audit rows collected: $($rawEvents.Count)"
Write-Log INFO "Parsing audit records and aggregating per user..."

foreach ($ev in $rawEvents) {
    $op = [string]$ev.operation
    if ($op -notin $Operations) { continue }

    # auditData.UserId is the real UPN; ev.userId is a PUID used internally by Forms
    $rawUserId = [string]$ev.userId
    if ($ev.PSObject.Properties['auditData'] -and $ev.auditData -and
        $ev.auditData.PSObject.Properties['UserId'] -and $ev.auditData.UserId) {
        $rawUserId = [string]$ev.auditData.UserId
    }

    $user = Normalize-FormsUserId $rawUserId
    if (-not $user) { continue }

    $when = $null
    if ($ev.createdDateTime) {
        $when = [datetime]$ev.createdDateTime
    }

    $bucket = Get-UserBucket $user
    $bucket.TotalEvents++

    if ($when) {
        if (-not $bucket.FirstSeenUtc -or $when -lt $bucket.FirstSeenUtc) { $bucket.FirstSeenUtc = $when }
        if (-not $bucket.LastSeenUtc -or $when -gt $bucket.LastSeenUtc) { $bucket.LastSeenUtc = $when }
    }

    if ($op) { [void]$bucket.OperationsSeen.Add($op) }

    # Track unique forms for this user
    if ($ev.PSObject.Properties['auditData'] -and $ev.auditData) {
        $fid = if ($ev.auditData.PSObject.Properties['FormId'] -and $ev.auditData.FormId) { [string]$ev.auditData.FormId }   else { $null }
        if ($fid -and -not $bucket.Forms.ContainsKey($fid)) {
            $fname = if ($ev.auditData.PSObject.Properties['FormName'] -and $ev.auditData.FormName) { [string]$ev.auditData.FormName } else { '(unknown)' }
            $bucket.Forms[$fid] = $fname
        }
    }

    switch ($op) {
        'CreateForm' { $bucket.CreateFormCount++ }
        'MoveForm' { $bucket.MoveFormCount++ }
        'DeleteForm' { $bucket.DeleteFormCount++ }
        'AddFormCoauthor' { $bucket.AddCoauthorCount++ }
        'ExportForm' { $bucket.ExportFormCount++ }
    }
}

Write-Log INFO "Users with Forms activity (post-normalization): $($userAgg.Count)"

#endregion Parse and Aggregate

#region Resolve User Status
# --------------------------
# Resolve live user status (deleted / disabled / active) for every audit user
# Live lookups fix UPN-mutation issues when Entra modifies a user's UPN on deletion.
# --------------------------
Write-Log INFO "Resolving live Entra user status for $($userAgg.Count) unique audit users..."
$userStatusMap = Resolve-UserStatusMap -Upns @($userAgg.Keys)
#endregion Resolve User Status

#region Build Report
# --------------------------
# Build final report (join to user status -> orphan risk)
# --------------------------
$nowUtc = (Get-Date).ToUniversalTime()

$report = foreach ($kvp in $userAgg.GetEnumerator()) {
    $upnLower = $kvp.Key
    $b = $kvp.Value

    $status = if ($userStatusMap.ContainsKey($upnLower)) { $userStatusMap[$upnLower] } else { $null }
    $isDeleted = $status -and $status.IsDeleted
    $isDisabled = $status -and $status.IsDisabled

    # Only report on users whose account is deleted or disabled
    if (-not $isDeleted -and -not $isDisabled) { continue }

    $daysSinceDeleted = $null
    $inOrphanWindow = $false

    if ($isDeleted -and $status.DeletedDateTime) {
        $dd = [datetime]$status.DeletedDateTime
        $daysSinceDeleted = [Math]::Round(($nowUtc - $dd).TotalDays, 2)
        $inOrphanWindow = ($daysSinceDeleted -le $OrphanWindowDays)
    }

    # "Owner likelihood" heuristic:
    # CreateForm and MoveForm are strong ownership signals.
    $ownerLikelihood = if (($b.CreateFormCount + $b.MoveFormCount) -gt 0) { "High" } else { "Medium" }

    $risk = "Low"
    $action = "No action"
    if ($isDeleted -and $inOrphanWindow -and $ownerLikelihood -eq "High") {
        $risk = "HIGH"
        $action = "Recover/transfer Forms now (user in deleted window)"
    }
    elseif ($isDeleted -and $inOrphanWindow) {
        $risk = "HIGH"
        $action = "Investigate quickly (user in deleted window; Forms activity seen)"
    }
    elseif ($isDeleted -and $null -eq $status.DeletedDateTime) {
        # Deletion date unknown (Entra UPN mutation prevented recycle-bin match)
        # Be conservative: assume still within the orphan window
        $inOrphanWindow = $true
        $risk = "HIGH"
        $action = "User deleted (deletion date unknown — UPN may have been renamed); verify in Entra and transfer Forms"
    }
    elseif ($isDeleted) {
        # Deleted and confirmed outside the 30-day window — forms permanently gone
        $risk = "Low"
        $action = "Forms likely permanently deleted (user was deleted $([Math]::Round($daysSinceDeleted,0)) days ago, beyond the $OrphanWindowDays-day window)"
    }
    elseif ($isDisabled -and $ownerLikelihood -eq "High") {
        $risk = "Medium"
        $action = "User account disabled — move Forms to group ownership before account is deleted"
    }
    elseif ($isDisabled) {
        $risk = "Low"
        $action = "User account disabled — review if Forms ownership needs transferring"
    }
    elseif ($ownerLikelihood -eq "High") {
        $risk = "Low"
        $action = "Proactively move business-critical Forms to group ownership"
    }

    # Resolve display UPN: prefer the canonical UPN from the live lookup, then audit record
    $resolvedUpn = if ($status -and $status.UserPrincipalName) { $status.UserPrincipalName } else { $b.UserPrincipalName }

    # Days until permanent deletion (30-day soft-delete window)
    $daysUntilPerm = if ($isDeleted -and $null -ne $daysSinceDeleted) {
        [Math]::Round([Math]::Max(0, $OrphanWindowDays - $daysSinceDeleted), 1)
    }
    else { $null }

    # Build delegatepage.aspx recovery URLs — one per unique form owned by this user
    $recoveryUrls = foreach ($fid in $b.Forms.Keys) {
        "https://forms.office.com/Pages/delegatepage.aspx?originalowner=$([System.Uri]::EscapeDataString($resolvedUpn))&formid=$fid"
    }

    [pscustomobject]@{
        UserPrincipalName          = $resolvedUpn
        OwnerLikelihood            = $ownerLikelihood
        RiskLevel                  = $risk
        DaysUntilPermanentDeletion = $daysUntilPerm
        RecommendedAction          = $action
        FormCount                  = $b.Forms.Count
        FormNames                  = ($b.Forms.Values | Sort-Object) -join ";"
        FormIds                    = ($b.Forms.Keys) -join ";"
        RecoveryUrls               = $recoveryUrls -join ";"
        TotalEvents                = $b.TotalEvents
        FirstSeenUtc               = $b.FirstSeenUtc
        LastSeenUtc                = $b.LastSeenUtc
        CreateFormCount            = $b.CreateFormCount
        MoveFormCount              = $b.MoveFormCount
        DeleteFormCount            = $b.DeleteFormCount
        AddFormCoauthorCount       = $b.AddCoauthorCount
        ExportFormCount            = $b.ExportFormCount
        OperationsSeen             = ($b.OperationsSeen | Sort-Object) -join ";"
        IsDeletedUser              = [bool]$isDeleted
        IsDisabledUser             = [bool]$isDisabled
        DeletedDateTimeUtc         = if ($isDeleted) { $status.DeletedDateTime } else { $null }
        DaysSinceDeleted           = $daysSinceDeleted
        InOrphanWindow             = $inOrphanWindow
    }
}

#endregion Build Report

#region Output
$reportCsv = Join-Path $OutputFolder "Forms-Orphan-Risk-Report-$runStamp.csv"
$eventsCsv = Join-Path $OutputFolder "Forms-Raw-Audit-$runStamp.csv"

$report | Sort-Object @{E = 'IsDeletedUser'; D = $true }, @{E = 'IsDisabledUser'; D = $true }, @{E = 'DaysUntilPermanentDeletion'; D = $false }, @{E = 'TotalEvents'; D = $true } |
Export-Csv -NoTypeInformation -LiteralPath $reportCsv

# Raw events can be large; export minimal columns for analysis
$rawEvents |
Select-Object createdDateTime, userId, operation, auditLogRecordType, auditData |
Export-Csv -NoTypeInformation -LiteralPath $eventsCsv

Write-Log INFO "Report written: $reportCsv"
Write-Log INFO "Raw audit export written: $eventsCsv"
Write-Log INFO "Done."

#endregion Output

#region Email Notifications
if ($SendEmailNotifications) {
    Write-Log INFO "Sending Forms orphan alert email..."

    # Filter report rows by the configured minimum risk level
    $riskOrder = @{ 'HIGH' = 1; 'Medium' = 2; 'Low' = 3 }
    $minRank = if ($riskOrder.ContainsKey($EmailMinRiskLevel)) { $riskOrder[$EmailMinRiskLevel] } else { 1 }

    $emailCandidates = @($report | Where-Object {
            $riskOrder.ContainsKey($_.RiskLevel) -and $riskOrder[$_.RiskLevel] -le $minRank
        })

    if ($emailCandidates.Count -gt 0) {
        Write-Log INFO "  $($emailCandidates.Count) account(s) meet the '$EmailMinRiskLevel' threshold — sending alert."
        Send-FormsOrphanAlertEmail -AffectedAccounts $emailCandidates
    }
    else {
        Write-Log INFO "  No accounts meet the '$EmailMinRiskLevel' risk threshold — email skipped."
    }
}
else {
    Write-Log INFO "Email notifications skipped (`$SendEmailNotifications = `$false)."
}
#endregion Email Notifications

#endregion Script Execution

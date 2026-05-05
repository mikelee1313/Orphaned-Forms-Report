# OrphanedForms-Report.ps1 — Microsoft Forms Orphan Risk Report
This script creates an inventory report to identify Orphaned Microsoft Forms allowing Admins to restore the Form before it's permanently deleted.
Identifies Microsoft Forms at risk of permanent loss due to their owner's account being **soft-deleted** or **disabled** in Entra ID. Produces a CSV report with actionable recovery URLs.

## The Problem

Microsoft Forms does not provide a tenant-wide admin inventory API. When a user account is deleted, their personal Forms enter a 30-day soft-delete window — after which they are **permanently and irrecoverably deleted**. There is no native admin alert for this.

This script mines the Microsoft Purview Unified Audit Log for Forms activity to identify likely form owners, cross-references those users against Entra ID to detect deleted or disabled accounts, and produces a prioritized report with ready-to-use recovery links.

## How It Works

1. **Authenticates** to Microsoft Graph using app-only credentials (certificate or client secret)
2. **Queries the Graph Audit Log API** (`POST /beta/security/auditLog/queries`) for all `MicrosoftForms` events in the configured lookback window
3. **Aggregates per-user statistics** — tracks which forms each user created, edited, or moved (strong ownership signals)
4. **Resolves live Entra user status** for each user found in audit data:
   - Active → skipped (not in report)
   - Disabled → included with Medium risk
   - Soft-deleted → included with HIGH risk (if within 30-day window)
   - Handles Entra UPN mutation on deletion via `mail` attribute fallback
5. **Outputs two CSV files** to `$env:TEMP`:
   - `Forms-Orphan-Risk-Report-<timestamp>.csv` — prioritized report
   - `Forms-Raw-Audit-<timestamp>.csv` — raw audit events for investigation

## Prerequisites

### Required App Registration Permissions

All permissions are **Application** type and require **admin consent**:

| Permission | Why |
|---|---|
| `AuditLogsQuery.Read.All` | Submit and read Graph Audit Log queries |
| `User.Read.All` | Resolve live user status (active/disabled) |
| `Directory.Read.All` | Query soft-deleted users from Entra recycle bin |

### Authentication Options

| Method | What You Need |
|---|---|
| **Certificate** (recommended) | Certificate installed in `LocalMachine\My` or `CurrentUser\My`; set `$Thumbprint` |
| **Client Secret** | Set `$AuthType = 'ClientSecret'` and populate `$clientSecret` |

> **No PowerShell modules required.** All Graph calls use `Invoke-RestMethod` directly.

## Configuration

Open the `#region Configuration` section at the top of the script and update:

```powershell
$tenantId        = '<your-tenant-id>'
$clientId        = '<your-app-registration-client-id>'
$AuthType        = 'Certificate'          # or 'ClientSecret'
$Thumbprint      = '<cert-thumbprint>'    # if using Certificate
$CertStore       = 'LocalMachine'         # or 'CurrentUser'
$clientSecret    = ''                     # if using ClientSecret

$LookbackDays    = 31    # How far back to search audit logs
$OrphanWindowDays= 30    # Entra soft-delete window (default: 30 days)
$OutputFolder    = $env:TEMP
```

Set `$IncludeResponseSignals = $true` to also flag users who only responded to forms (higher noise, useful for full coverage).

## Running the Script

```powershell
.\Get-Forms-Info.ps1
```

The script is self-contained — no parameters, no modules. All settings are in the configuration section.

## Report Columns

| Column | Description |
|---|---|
| `UserPrincipalName` | Canonical UPN (from live Entra lookup) |
| `RiskLevel` | `HIGH` / `Medium` / `Low` |
| `DaysUntilPermanentDeletion` | Days remaining before forms are permanently deleted |
| `RecommendedAction` | Plain-language guidance |
| `FormCount` | Number of unique forms owned by this user |
| `FormNames` | Semicolon-separated form display names |
| `RecoveryUrls` | Ready-to-use `delegatepage.aspx` recovery links (one per form) |
| `OwnerLikelihood` | `High` if user has `CreateForm`/`MoveForm` events; `Medium` otherwise |
| `IsDeletedUser` | `True` if account is in Entra soft-delete recycle bin |
| `IsDisabledUser` | `True` if account is disabled but not yet deleted |
| `DeletedDateTimeUtc` | When the account was deleted |
| `DaysSinceDeleted` | How long the account has been in the recycle bin |
| `InOrphanWindow` | `True` if still within the 30-day recovery window |

## Risk Level Logic

| Condition | Risk Level |
|---|---|
| Deleted + in 30-day window + `OwnerLikelihood = High` | **HIGH** — Recover/transfer Forms now |
| Deleted + in 30-day window | **HIGH** — Investigate (Forms activity seen) |
| Deleted + date unknown (UPN mutated) | **HIGH** — Verify in Entra; transfer Forms |
| Deleted + outside 30-day window | Low — Forms likely permanently deleted |
| Disabled + `OwnerLikelihood = High` | **Medium** — Move Forms before account is deleted |
| Disabled only | Low — Review if transfer needed |

## Recovering a Form

Use the `RecoveryUrls` column. Each URL follows this pattern:

```
https://forms.office.com/Pages/delegatepage.aspx?originalowner=<UPN>&formid=<FormId>
```

Open the URL while signed in as a **Global Admin** or **Forms admin** to access and transfer the form.

## Notes

- **Audit log coverage**: The script uses whatever is in the audit log for the lookback window. Forms created before the lookback window may not appear unless they had recent activity.
- **Entra UPN mutation**: When Entra deletes a user, it may append a suffix to their UPN to free the namespace for re-use. The script handles this by falling back to a `mail` attribute search in the recycle bin.
- **Audit log ingestion delay**: Graph Audit Log queries may have up to 60–90 minutes of ingestion delay for very recent events.
- **Beta API**: The `POST /beta/security/auditLog/queries` endpoint is used as the audit log query API has not yet been promoted to v1.0.

## License

MIT

# Threat Hunt Report — Anonymous IP Sign-In — Incident 87241
**Classification:** Internal Use Only

**Hunt Date:** 20 June 2026

**Analyst:** Eric Aguilar-Hernandez

**Environment:** Microsoft Sentinel / Defender XDR — lognpacific.org tenant

**Status:** Completed

---

## Executive Summary

A Low-severity Entra ID Protection alert on finance user `m.smith@lognpacific.org` — an anonymous IP sign-in — was triaged by the night shift and left unactioned. Tier-2 review determined the Low rating was incorrect. The sign-in was the opening move of a full Business Email Compromise (BEC) intrusion conducted by a patient threat operator who exploited a legacy authentication gap to bypass Conditional Access and MFA entirely.

Over a ten-hour window, the attacker conducted structured directory recon, read historical internal payment threads to price the fraud, sent fraudulent payment redirection requests across two channels, established dual mailbox persistence rules, exfiltrated sensitive files, and deployed a Power Automate flow for autonomous continued access — all without triggering a single MFA prompt.

---

## Incident Metadata

| Field | Value |
|---|---|
| Incident ID | 87241 |
| Principal | m.smith@lognpacific.org |
| Attacker IP | 103.69.224.136 |
| Intrusion Window | 11 June 2026, 03:00 – 13:00 UTC |
| Session ID | 005d431a-380b-1f5e-e554-16d5010dc28e |
| Initial Detection | Entra ID Protection — anonymous IP sign-in |
| Initial Severity | Low |
| Revised Severity | Critical |

---

## Environment & Data Sources

All investigation was conducted across the following Microsoft Sentinel / Defender XDR log tables:

| Table | Purpose |
|---|---|
| `SigninLogs` | Entra ID sign-in telemetry, auth outcomes, CA policy evaluation |
| `AuditLogs` | Entra directory changes and identity object activity |
| `CloudAppEvents` | Defender for Cloud Apps — file, mailbox, and cloud service actions |
| `OfficeActivity` | Office 365 unified audit — mailbox rules, mail operations |
| `MicrosoftGraphActivityLogs` | Raw Microsoft Graph API calls against the tenant |
| `EmailEvents` | Defender for Office 365 — mail flow, sent and received messages |
| `IdentityLogonEvents` | Defender for Identity — account logons across the identity estate |
| `BehaviorAnalytics` | Entra UEBA — anomaly scoring on sign-in activity |

The attacker IP `103.69.224.136` appeared as a literal field value in **7 of 8** in-scope tables. The only table without a direct IP hit was `AuditLogs`, which records directory change events rather than raw connection telemetry.

---

## Stage 1 — Triage

### 1.1 Initial Alert

The Entra ID Protection detection type stored in risk telemetry was `anonymizedIPAddress`. The alert was rated Low, consistent with a single anonymous sign-in with no observed post-auth activity at the time of triage. The night shift found no immediately actionable signals and left it in queue.

### 1.2 Risk State Analysis

Aggregating `m.smith`'s risk detections by state in `SigninLogs` revealed that the majority of detections resolved to `dismissed` — a pattern consistent with a tenant that clears low-severity identity alerts without full investigation.

### 1.3 Account Status

The asset record on the incident confirmed the account status as `Active` at the time of the intrusion. No disabling or remediation had been applied.

### 1.4 Authentication Gap — How the Session Got Through

Querying `SigninLogs` for successful sign-ins from `103.69.224.136` revealed the critical finding: every successful authentication carried `AuthenticationRequirement` of `singleFactorAuthentication`.

The entry point application was **One Outlook Web**, a legacy client protocol. Conditional Access status across all sign-ins returned `notApplied` — the CA policies enforcing MFA did not evaluate these sign-ins because the legacy protocol was exempt from policy scope.

**MFA was satisfied zero times across the entire session.** The attacker used a legacy authentication pathway that existed outside the tenant's Conditional Access enforcement boundary, rendering MFA enforcement meaningless for this session.

The client OS identified from the `UserAgent` field was **Linux**, atypical for a finance user's corporate endpoint and consistent with an attacker-controlled machine.

---

## Stage 2 — Investigation

### 2.1 Session Scope

The attacker authenticated successfully after two failed attempts and established a single session that reached **7 distinct applications** with no re-authentication prompt across the intrusion window:

- One Outlook Web (entry point)
- OfficeHome
- Office 365 SharePoint Online
- SharePoint Online Web Client Extensibility
- Microsoft Teams Web Client
- Microsoft Flow Portal
- App Service

The presence of **Microsoft Flow Portal** — a workflow automation tool with no legitimate use case for a finance user — was an immediate indicator of persistence intent.

### 2.2 Directory Recon

Early in the session, the attacker queried the Microsoft Graph API to profile the account's authentication posture and enumerate group membership. All activity was captured in `MicrosoftGraphActivityLogs`.

**Auth posture profiling:**
```
GET https://graph.microsoft.com/beta/reports/authenticationMethods/userRegistrationDetails
    ?$filter=userPrincipalName eq 'm.smith@lognpacific.org' and isMfaCapable eq true
```
The queried resource was `userRegistrationDetails`. This call confirmed to the attacker that the account was not MFA-capable, validating the legacy auth approach before proceeding.

**Group membership enumeration:**
```
GET https://graph.microsoft.com/v1.0/me/memberOf
```
Fired at 03:09 UTC, this call enumerated the user's group memberships — identifying their role, access level, and what resources they could reach.

### 2.3 Mail Recon — Pre-Intrusion Thread

Using `EmailEvents`, the attacker identified and read a historical internal payment thread predating the intrusion by months:

> **Subject:** `Re: Q1 Vendor Payment Schedule - Review Required`
> **Participants:** josh@lognpacific.org, j.reynolds@lognpacific.org, m.smith@lognpacific.org
> **Date:** February 2026

This thread gave the attacker visibility into the payment approval process, the internal participants involved, and the language used — providing the intelligence needed to craft a convincing fraud.

### 2.4 The Fraud

The attacker executed a two-vector fraud push targeting `j.reynolds@lognpacific.org`, the finance contact identified through mail recon.

**Vector 1 — Email:**
A fraudulent payment redirection email was sent from `m.smith`'s mailbox to `j.reynolds@lognpacific.org` during the intrusion window, requesting a change to banking details.

**Vector 2 — Microsoft Teams:**
The same fraudulent payment request was pushed through Microsoft Teams, confirmed via a `Send` action on a Task object in `CloudAppEvents`. Using two channels simultaneously increased the pressure on the target and reduced the chance the request would be ignored.

### 2.5 Persistence — Inbox Rules

Two inbox rules were created via `New-InboxRule` operations captured in `CloudAppEvents`, both scoped to inbound mail from `j.reynolds@lognpacific.org`:

**Rule 1: `Invoice Processing`** (created 03:28 UTC)
- Trigger: Mail from `j.reynolds@lognpacific.org`
- Action: Move to `Archive` folder
- Purpose: Hides any replies from Reynolds — approval confirmations, questions, or fraud flags — so `m.smith` never sees them

**Rule 2: `Backup Copy`** (created 03:32 UTC)
- Trigger: Mail from `j.reynolds@lognpacific.org`
- Action: Forward to `merovingian1337@proton.me`
- Purpose: Exfiltrates all of Reynolds' replies to the attacker's external ProtonMail address in real time

Together, the rules form a suppression and exfiltration pair: Reynolds' responses are hidden from the victim and simultaneously delivered to the attacker.

### 2.6 Persistence — Power Automate Flow

The attacker signed into **Microsoft Flow Portal** during the session and built a Power Automate flow to automate mail forwarding independently of any active session or inbox rule.

Evidence of autonomous execution was confirmed by correlating `MicrosoftGraphActivityLogs` with `EmailEvents`:

- The **Graph API call** firing the forward appeared **before** the corresponding mail event in `EmailEvents`
- The call originated from **`20.150.129.194`** — a Microsoft Power Automate infrastructure IP, not the attacker's `103.69.224.136`
- The executing application resolved to **App ID `7ab7862c-4c57-491e-8a45-d52a7e023983`** — Microsoft Power Automate

A human composing a forward generates the mail event first. An API call appearing before the message exists in mail flow proves programmatic execution. The flow continued operating after the attacker disconnected, with no active user session required.

**Admin console for remediation:** Power Platform Admin Center

### 2.7 Data Theft

File activity in `CloudAppEvents` (OneDrive for Business) revealed three `FileDownloaded` operations at 03:37 UTC — distinguishable from normal `FileAccessed` activity because downloads pull a copy outside the tenant's control, while access reads in place:

| File | Significance |
|---|---|
| `Vendor-Banking-Details.txt` | Directly feeds the payment fraud — banking details to redirect |
| `VPN-Access-Credentials.txt` | Future persistent access vector into the network |
| `Book.xlsx` | Likely financial data |

Additionally, `yomark.pdf` was accessed in place (`FileAccessed`) at 03:39 UTC — contents viewed but not downloaded.

This activity maps to **MITRE ATT&CK T1530 — Data from Cloud Storage.**

---

## Stage 3 — Findings & Judgement

### 3.1 What the Night Shift Missed

The Low severity rating was technically accurate at the point of triage — one anonymous sign-in, no observed post-auth activity. What the machine did not ask, and the night shift did not investigate, was what happened next. The detection caught the entry. It did not catch ten hours of structured intrusion activity across seven applications and four log sources.

### 3.2 How It Was Hidden

The attacker employed several deliberate concealment techniques:

- **Legacy authentication** to bypass CA and MFA silently, with no failed MFA prompts or lockouts to alert defenders
- **Inbox rule named `Invoice Processing`** — a legitimate-sounding name concealing a mail-suppression rule
- **Inbox rule named `Backup Copy`** — disguised as a backup operation, actually forwarding to an external address
- **Power Automate** for persistence that survives session termination, password resets, and inbox rule deletion if not specifically hunted
- **Anonymous/proxy IP** to obscure origin, rated Low by Entra ID Protection

### 3.3 Threat Actor Assessment

This was a patient, structured operator. The session followed a logical kill chain: auth posture recon → group enumeration → payment process recon → dual-vector fraud → dual persistence → data theft → autonomous exfiltration. Each stage informed the next. The attacker knew the internal participants by name, understood the payment approval process, and built persistence before exfiltrating data. This is not opportunistic credential stuffing — this is targeted BEC with pre-planned tradecraft.

---

## MITRE ATT&CK Mapping

| Technique | ID | Evidence |
|---|---|---|
| Valid Accounts | T1078 | Successful sign-in with compromised credentials |
| Phishing for Information | T1598 | Graph recon of auth posture |
| Account Discovery | T1087 | `/me/memberOf` group enumeration |
| Email Collection | T1114 | `MailItemsAccessed` during session |
| Email Forwarding Rule | T1114.003 | `Backup Copy` inbox rule forwarding to ProtonMail |
| Data from Cloud Storage | T1530 | `FileDownloaded` from OneDrive |
| Automated Exfiltration | T1020 | Power Automate flow forwarding mail autonomously |
| Use of Application Layer Protocol | T1071 | Graph API calls for recon and automation |

---

## Remediation Steps

Perform in this order — sequence is critical:

1. **Revoke all active sessions** for `m.smith` in Entra ID — session tokens survive a password reset and must be killed first or the attacker remains inside the tenant
2. **Reset the password** for `m.smith` to block re-entry
3. **Remove inbox rules** `Invoice Processing` and `Backup Copy` via Exchange Admin Center
4. **Delete the Power Automate flow** via Power Platform Admin Center — this cannot be removed from Sentinel or Exchange Admin Center
5. **Block `103.69.224.136`** and `merovingian1337@proton.me` at the mail gateway
6. **Investigate `j.reynolds@lognpacific.org`** — determine whether the fraudulent payment request was actioned and whether any wire transfers were initiated
7. **Audit legacy authentication** — identify all applications and users exempt from CA policy and close the legacy auth gap that enabled this intrusion
8. **Review Power Automate** across the tenant for other flows forwarding mail externally

---

## Indicators of Compromise

| Type | Value |
|---|---|
| Attacker IP | 103.69.224.136 |
| External recipient | merovingian1337@proton.me |
| Power Automate infrastructure IP | 20.150.129.194 |
| Power Automate App ID | 7ab7862c-4c57-491e-8a45-d52a7e023983 |
| Malicious inbox rule | Invoice Processing |
| Malicious inbox rule | Backup Copy |
| Compromised UPN | m.smith@lognpacific.org |
| Session ID | 005d431a-380b-1f5e-e554-16d5010dc28e |

---

## Key KQL Queries Used

**Confirm the flagged sign-in and auth requirement:**
```kql
SigninLogs
| where UserPrincipalName contains "m.smith"
| where IPAddress == "103.69.224.136"
| where ResultType == 0
| project TimeGenerated, UserPrincipalName, IPAddress, AuthenticationRequirement,
          ConditionalAccessStatus, AppDisplayName, UserAgent
| order by TimeGenerated asc
```

**Enumerate distinct apps touched in session:**
```kql
SigninLogs
| where UserPrincipalName contains "m.smith"
| where IPAddress == "103.69.224.136"
| where ResultType == 0
| distinct AppDisplayName
```

**Graph API recon activity:**
```kql
MicrosoftGraphActivityLogs
| where IPAddress == "103.69.224.136"
| where TimeGenerated between (datetime(2026-06-11T03:00:00Z) .. datetime(2026-06-11T13:00:00Z))
| project TimeGenerated, RequestUri, ResponseStatusCode
| order by TimeGenerated asc
```

**Inbox rule creation:**
```kql
CloudAppEvents
| where IPAddress == "103.69.224.136"
| where TimeGenerated between (datetime(2026-06-11T03:00:00Z) .. datetime(2026-06-11T13:00:00Z))
| where ActionType == "New-InboxRule"
| project TimeGenerated, ActionType, ObjectName, RawEventData
```

**File exfiltration:**
```kql
CloudAppEvents
| where IPAddress == "103.69.224.136"
| where TimeGenerated between (datetime(2026-06-11T03:00:00Z) .. datetime(2026-06-11T13:00:00Z))
| where ActionType == "FileDownloaded"
| project TimeGenerated, ActionType, ObjectName, Application
```

**Mail recon — historical payment threads:**
```kql
EmailEvents
| where RecipientEmailAddress contains "m.smith"
| where TimeGenerated between (datetime(2026-01-01T00:00:00Z) .. datetime(2026-06-11T03:00:00Z))
| project TimeGenerated, SenderFromAddress, RecipientEmailAddress, Subject
| order by TimeGenerated asc
```

**Attacker IP presence across all log sources:**
```kql
let attackerIP = "103.69.224.136";
let start = datetime(2026-06-10T00:00:00Z);
let end = datetime(2026-06-20T23:59:59Z);
union
    (SigninLogs | where TimeGenerated between (start .. end) | where IPAddress == attackerIP | distinct Type),
    (CloudAppEvents | where TimeGenerated between (start .. end) | where IPAddress == attackerIP | distinct Type),
    (OfficeActivity | where TimeGenerated between (start .. end) | where ClientIP == attackerIP | distinct Type),
    (MicrosoftGraphActivityLogs | where TimeGenerated between (start .. end) | where IPAddress == attackerIP | distinct Type),
    (EmailEvents | where TimeGenerated between (start .. end) | where SenderIP == attackerIP | distinct Type),
    (IdentityLogonEvents | where TimeGenerated between (start .. end) | where IPAddress == attackerIP | distinct Type),
    (BehaviorAnalytics | where TimeGenerated between (start .. end) | where IPAddress == attackerIP | distinct Type)
| summarize count()
```

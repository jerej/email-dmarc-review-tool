# DMARC Rollout Plan for stagerigger.com

Date: 2026-09-11

This plan assumes your current policy is `p=none` and you want to move safely to `p=quarantine` while continuing close monitoring.

## Goals
- Reduce spoofed mail delivery by enforcing DMARC policy.
- Minimize risk of legitimate mail disruption.
- Keep a clear rollback path at every step.

## Prerequisites
- SPF and DKIM are configured for all legitimate sending services.
- Aggregate reporting mailbox is active and monitored:
  - `rua=mailto:dmarc-reports@stagerigger.com` (replace if needed)
- Your review dashboard is running daily.

## DNS record location
Create or update this TXT record at:
- Host/Name: `_dmarc.stagerigger.com`
- Type: `TXT`

## Phase 0: Baseline (Current)
Keep this until you have 7+ days of stable reporting.

```txt
v=DMARC1; p=none; pct=100; rua=mailto:dmarc-reports@stagerigger.com; fo=1; adkim=r; aspf=r
```

## Phase 1: Controlled quarantine (Week 1)
Start by quarantining only a subset of failing mail.

```txt
v=DMARC1; p=quarantine; pct=25; rua=mailto:dmarc-reports@stagerigger.com; fo=1; adkim=r; aspf=r
```

Monitor daily for:
- New legitimate source IPs failing SPF or DKIM
- Unexpected spikes in fail/softfail
- Known vendors not aligned

## Phase 2: Expand quarantine (Week 2)
If Phase 1 is clean for 5 to 7 days, increase coverage.

```txt
v=DMARC1; p=quarantine; pct=50; rua=mailto:dmarc-reports@stagerigger.com; fo=1; adkim=r; aspf=r
```

## Phase 3: Broad quarantine (Week 3)
If Phase 2 is still clean, move to near-full enforcement.

```txt
v=DMARC1; p=quarantine; pct=75; rua=mailto:dmarc-reports@stagerigger.com; fo=1; adkim=r; aspf=r
```

## Phase 4: Full quarantine (Week 4)
If no legitimate false positives remain, finalize at full percentage.

```txt
v=DMARC1; p=quarantine; pct=100; rua=mailto:dmarc-reports@stagerigger.com; fo=1; adkim=r; aspf=r
```

## Optional hardening after quarantine is stable
After 2 to 4 stable weeks at `pct=100`, you can evaluate:
- Move alignment to strict for one or both checks:
  - `adkim=s`
  - `aspf=s`
- Eventually consider `p=reject` if your sender inventory is fully controlled.

Example strict-alignment quarantine policy:

```txt
v=DMARC1; p=quarantine; pct=100; rua=mailto:dmarc-reports@stagerigger.com; fo=1; adkim=s; aspf=s
```

## Subdomain policy guidance
If you send from subdomains, define `sp` explicitly.

Use this if subdomains should follow quarantine too:

```txt
v=DMARC1; p=quarantine; sp=quarantine; pct=100; rua=mailto:dmarc-reports@stagerigger.com; fo=1; adkim=r; aspf=r
```

Use this if you need parent-domain quarantine but looser handling on subdomains for now:

```txt
v=DMARC1; p=quarantine; sp=none; pct=100; rua=mailto:dmarc-reports@stagerigger.com; fo=1; adkim=r; aspf=r
```

## Rollback plan (Immediate)
If you identify legitimate disruption, roll back quickly to baseline:

```txt
v=DMARC1; p=none; pct=100; rua=mailto:dmarc-reports@stagerigger.com; fo=1; adkim=r; aspf=r
```

Then:
- Keep policy at `p=none` while fixing SPF/DKIM alignment for affected sender(s).
- Re-run one full reporting cycle before trying quarantine again.

## How to "release" quarantined mail
DMARC policy cannot directly release a message. Release is done by receiving mailbox systems:
- Google Workspace users: mark message "Not spam" in Spam.
- Google Workspace admins: release from Admin quarantine when applicable.
- External recipients: their own admin/user must release in their environment.

## Daily monitoring checklist during rollout
- Review top failing source IPs.
- Verify reverse DNS and sender ownership for new IPs.
- Track fail-like counts versus baseline.
- Confirm known platforms (transactional mail, CRM, marketing tools) still pass DKIM/SPF alignment.
- Record any false positives and fix sender authentication before increasing `pct`.

## DNS record backups
Previous values kept so changes can be rolled back.

### moncurefire.com SPF (saved 2026-10-25)
- Host/Name: `moncurefire.com`
- Type: `TXT`

```txt
v=spf1 a:dispatch-us.ppe-hosted.com include:secureserver.net include:icloud.com include:_spf.google.com ~all
```

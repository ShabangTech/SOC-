# Purple-Team Exercise: Network Brute-Force vs. H01

**Goal:** validate the H01 detection (failed-logon burst, Windows Event 4625,
MITRE T1110) against a *real* network attack from a separate attacker machine,
instead of the benign self-test used in Phase 1.

**Attacker:** Kali Linux (VM) · **Target:** the monitored Windows laptop
**Date:** 2026-11-17

> IPs, MAC addresses and account names are redacted. `<KALI>` and `<TARGET>`
> stand for the two hosts on the lab subnet.

## Method

1. **Network setup.** Kali started on NAT (`10.0.2.x`), which cannot reach the
   host. Switched the VM adapter to bridged so Kali received a routable address
   on the test subnet. (A VirtualBox repair install was needed first to restore
   the missing bridged/host-only network driver.)
2. **Recon.**
   ```
   nmap -Pn -p 135,139,445,3389,5985 <TARGET>
   ```
   Result: host **up**, but **all ports `filtered`** — a firewall was silently
   dropping every probe.
3. **Service check.** The target's SMB server (`LanmanServer`) was not listening
   on 445 at all.

## Findings — defense held at every layer

The attack could not reach the detection stage, because the host stopped it
first. This is the headline result.

| Layer | Control found | Effect |
|-------|---------------|--------|
| Service | SMB server (`LanmanServer`) not listening on 445 | No service to attack |
| Host firewall (rules) | Redundant explicit block rules on 445 (and on 135, 139, 23, 21, 3389, 1433, …) | Inbound SMB blocked; block rules override any allow rule |
| Host firewall (profile) | Wi-Fi profiled **Public** with "block all incoming connections" (`AllowInboundRules = False`) | All inbound dropped, allow rules ignored |

A brute-force attempt from the network never produced a single `4625`, because
no packet reached an authentication service.

## Security decision

Opening a path to the target would have required lowering the host firewall
while on a **network not under my control**. That trade-off was declined: a
detection test is not worth weakening real defenses on an untrusted network.
The exercise was stopped and all temporary changes reverted.

## Lab hygiene — changes made and reverted

Every change was temporary and undone at the end:

- Started `LanmanServer` → stopped it, set start type back to Manual
- Added a scoped inbound allow rule for the attacker IP → removed it
- Disabled the SMB block rules for the test → re-enabled all of them
- Disconnected the VPN for a clean test → reconnected it

Post-exercise re-scan confirmed the target back to all-`filtered`.

## Lessons

- **Prevention and detection are different goals.** H01 detects an attack in
  progress; it cannot fire if prevention stops the attack first. A hardened host
  may show *no* alert precisely because nothing got through — the absence of an
  alert is not the absence of a control.
- **Windows Firewall precedence:** block rules beat allow rules, and a profile
  set to "block all incoming" ignores allow rules entirely.
- **Know your network profile.** Public vs. Private changes whether inbound
  rules are honored at all.
- **Don't weaken production to test.** Detection validation belongs in an
  isolated lab, not against a daily-driver host on shared Wi-Fi.

## Next step — isolated detection lab

To validate H01 (and later AD attacks) safely:

- Build a **dedicated victim VM** on a **host-only network** isolated from any
  real/shared network, so no production firewall profile is ever touched.
- Ship Sysmon + the CloudWatch agent from the victim VM into the SOC, so attacks
  light up the existing detections.
- Run H01 (SMB brute force), then OSCP-style AD techniques (Kerberoasting,
  AS-REP roasting, enumeration), and add AD-specific detections the current
  eight do not yet cover.

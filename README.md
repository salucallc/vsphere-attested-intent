# vsphere-attested-intent

Open detection work for the vSphere management plane, the part of a VMware estate that endpoint detection (EDR) cannot see: the vCenter Server Appliance (VCSA), vCenter SSO, the appliance management interface (VAMI), ESXi hosts and datastores.

It has two parts:

1. **A method, attested intent.** It is a sound ordering of known controls, and it is not a new technique (see [Prior art](#prior-art)).
2. **Nine SIGMA rules** for the attack chain that Google Threat Intelligence Group (GTIG) and Mandiant published on 2026-11-19 for CVE-2026-123890.

> **Untested in a lab.** No rule here has been run against live vCenter or ESXi data. The rules pass pySigma validation, which proves syntax and tagging, not detection. Field names and match strings marked `verify` are placeholders until someone checks them on a real appliance. Do not deploy a rule before you have tested it in your own environment.

Saluca Labs, 2026-11-19.

## Why this plane

In GTIG's account of the ARMORY CASTLE intrusion (source S9 in `CREDITS.md`), nearly every step after the attacker reaches vCenter happens where a guest EDR agent has nothing to watch:

- the exploit over the `vmdird` DCE/RPC interface on TCP 2012;
- `/storage/db/vmware-vmdir/data.mdb` copied off the appliance;
- a new SSO administrator and a Global Administrator grant;
- SAML assertions forged with the stolen STS signing key;
- SSH switched on through `PUT /rest/appliance/access/ssh` on TCP 5480, then off again;
- ESXi Host Client logins as `vpxuser`, SSH logins as root, and a key added to root's `authorized_keys` (with WinSCP, per GTIG);
- NTDS.dit and registry hives read out of virtual disk files at the datastore layer;
- a backdoor on the appliance with Slack for command and control.

## The method: attested intent

The method is proposed, not implemented here: this repo ships no attestation code, only the rules, the validator and the pseudo-queries.

1. **Intent before the act.** Each in-scope management-plane change class (SSO users and groups, role and permission grants, VAMI access toggles such as SSH, ESXi `authorized_keys`, syslog and audit configuration, VIB installs, firewall rules) needs a signed record written **before** the act: actor, object, attribute, time window. A ticket filed after the fact does not count.
2. **The record lives off the plane it governs.** It is signed and append-only, in a store the vSphere administrator cannot write, off the cluster and off the Active Directory domain (GTIG shows domain controller secrets read from VMDKs). Each intent carries a per-intent signature from a hardware-bound approver key that vCenter never holds.
3. **Match at attribute granularity.** Match actor, object and attribute inside the window. A record like "change to cluster X today" lets many actions ride one ticket.
4. **Fail closed, and measure coverage.** If the intent store or the log feed is unreachable, raise an alert, never stay silent. Publish one figure weekly: the share of in-scope change classes that can actually be joined to a record.
5. **Absence of logs is a detection.** Run a per-source heartbeat alert for VCSA and ESXi syslog. CVE-2026-41709, an ESX insufficient-logging flaw, was reportedly used to reduce audit trail visibility (S3).
6. **Behavioural rules stay.** The rules in `rules/` catch what attestation cannot: the exploit traffic, the `data.mdb` read, the SUID change, the backdoor banner and the datastore staging. Attestation turns the noisy admin-action rules (new SSO admin, SSH enable, root key added) into sharp ones: the action **without** intent.

The change-attestation join and the other stateful checks are written as pseudo-queries in `docs/pseudo-queries.md`, because SIGMA is stateless per event.

### Limits

- **It cannot tell a forged session inside an approved window from the real engineer.** If an attacker rides an approved actor, object and window, the record matches. Golden SAML makes that forgery cheap.
- **It passes a harmful change that was approved.** It answers "was this approved", not "was this safe".
- **The log of the act comes from the plane under attack.** For that reason this is a **second-tier control**, sitting on top of off-box logging, network baselines and behavioural rules, not in front of them.
- **It only sees the channels that are logged off-box.** Appliance shells and datastores are blind unless their logs leave the box.
- **Public documentation of VCSA log fields is thin.** We could not find a published vCenter-specific Golden SAML detection. That is a statement about our searches, not proof that none exists.

## The rules

| File | Chain step (GTIG) | Level | Nature |
|---|---|---|---|
| `vmw_vcsa_gdb_suid_env_privesc.yml` | local root via gdb, SUID on `/bin/env` | high | behaviour |
| `vmw_vcsa_armory_castle_tool_paths.yml` | BONESAW, SAWSNAKE, BEARBONES, LAZYBONES paths | critical | perishable IOC |
| `vmw_vcsa_vmdir_data_mdb_read_by_other_process.yml` | `data.mdb` exfiltration | high | behaviour, needs a keyed auditd watch |
| `vmw_vcenter_sso_new_admin_global_admin.yml` | new SSO admin, Global Administrator | high | behaviour, placeholder strings |
| `vmw_vcenter_vami_ssh_enable_put.yml` | VAMI SSH enable | high | change-attestation candidate |
| `vmw_esxi_root_authorized_keys_modified.yml` | ESXi root key persistence | high | behaviour |
| `vmw_esxi_vmfs_browser_hidden_staging.yml` | VMDK reads, hidden `.a`, SCP | critical | partly perishable |
| `vmw_network_bearbones_ssh_banner.yml` | BEARBONES on TCP 53 / 33992 | high | perishable IOC |
| `vmw_esxi_audit_logging_tampering.yml` | logging tampering (CVE-2026-41709 context) | medium | behaviour |

The rules contain no IP addresses on purpose. Those are perishable and belong in a threat-intel feed.

**Custom logsources.** SigmaHQ has no standard logsource for vCenter or ESXi, so each of these needs a pipeline:

| Logsource | Maps to | Fields (verify) |
|---|---|---|
| `product: vmware, service: vami_access` | VCSA TCP 5480 access log | `http_method`, `uri_path` |
| `product: vmware, service: vcenter_sso` | vCenter SSO / vmdird / STS logs, or vpxd permission events | `message`, `actor` |
| `product: vmware, service: esxi_shell` | ESXi `/var/log/shell.log` via syslog | `message` |
| `product: linux, service: auditd` | VCSA auditd SYSCALL records with a keyed watch | `type`, `key`, `exe` |
| `product: linux, category: process_creation` | VCSA EXECVE or forwarded shell history | `Image`, `CommandLine` |
| `product: zeek, service: ssh` | Zeek `ssh.log` | `server`, `id.resp_p` |

**Known open issues.**

- **`esxi_root_authorized_keys_modified`:** GTIG says the key was added with WinSCP, and a file transfer need not leave a shell command line, so file-integrity monitoring of `/etc/ssh/keys-root/authorized_keys` is the stronger control.
- **`esxi_vmfs_browser_hidden_staging`:** the `/.a` substring is broad, and the scp selection should be split out of the critical rule.
- **`vcsa_gdb_suid_env_privesc`:** the chmod selection will not fire on GTIG's base64 variant.
- **`vcenter_sso_new_admin_global_admin`:** this rule is not deployable until real event text replaces its placeholder strings.

## Validation

```
pip install -r requirements-test.txt
python tools/validate_rules.py
```

Every rule must load in pySigma, have a condition that parses and pass all pySigma core validators, including the ATT&CK tag check against the ATT&CK data pySigma loads. Each rule must also carry `status: experimental`, `author: Saluca Labs` and "untested in a lab" on its first line. A cross-file pass checks that ids and titles are unique.

The script then runs a **self-test**. Each file in `tests/broken/` has one planted defect (a bad id, an unknown modifier, an undefined condition, a bad level, a retired ATT&CK tag or a missing untested mark), and each one must be rejected. If a broken rule passes, the run fails, because a validator that cannot fail tests nothing. CI (`.github/workflows/sigma-validate.yml`) runs the same script on every push and pull request.

A pass means the syntax and tagging are valid. It does not mean a rule detects anything.

## What a lab test would look like

None has been run.

1. Build a lab VCSA and ESXi (8.0 U3 or 9.x) with remote syslog to a SIEM and the Mandiant hardening tool applied.
2. Replay benign versions of the chain's admin actions (create an SSO user, grant a role, VAMI SSH on and off, add a root key, change the syslog target), once with a prior intent record and once without. Expect alerts only on the unattested ones.
3. Plant each artifact and confirm the rule for it fires. Then cut syslog and confirm the heartbeat alert fires.
4. Measure false positives across one real patch window, and compute the coverage figure.
5. Do not replay the exploit. No exploit code is in scope here.

## Prior art

Every element of the method has prior art. The full list with links is in `CREDITS.md`.

- **ESXi shell and VIB baselines:** the Splunk ESXi Post Compromise story; SigmaHQ esxcli rules.
- **vpxuser SSH detection:** an Elastic prebuilt rule.
- **vCenter log detections:** CrowdStrike; the Mandiant vSphere hardening guide.
- **Golden SAML correlation for AD FS:** Sygnia; IBM QRadar write-ups.
- **Drift against declared state:** GitOps and Argo CD.
- **Decision points that log every decision:** NIST SP 800-207.
- **ITSM change correlation and file integrity monitoring:** long-standing practice.

What this repo contributes is the ordering and two disciplines: intent stored independently of the plane, and fail closed with a published coverage figure.

**Freedom to operate.** Third-party US patents titled on SAML forgery detection exist (listed in `CREDITS.md`, not read by us). They are not a bar to publishing open work. If anyone builds a commercial service on this method, those patents are a freedom-to-operate question for counsel. Saluca files no patents on this work.

## Contributing

Corrections, real VCSA and ESXi event text, and lab results are welcome as issues or pull requests. If you have tested a rule, please say on what version and with what pipeline.

## License

Apache License 2.0. See `LICENSE` and `NOTICE`. Apache-2.0 was chosen for its explicit patent grant from contributors.

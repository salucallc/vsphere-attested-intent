# Credits and sources

Everything factual in this repo comes from the sources below, fetched on 2026-11-19 unless a row says otherwise. The ids (S1, P1 and so on) are the ones used in the rules and docs. "Primary" means a vendor or government source; "secondary" means press or a vendor blog. Where a fact rests only on a secondary source, the docs attribute it.

The attack chain these rules target was published by Google Threat Intelligence Group and Mandiant (S9). The rules are our reading of their report, not theirs, and any mistakes are ours.

## Sources

| Id | Source | Type | Used for |
|---|---|---|---|
| S1 | Broadcom VMSA-2026-0006: https://support.broadcom.com/web/ecx/support-content-notification/-/external/content/SecurityAdvisories/0/38017 | Primary | CVE-2026-59309, 59310, 47876, 41703, 41709 (ESX insufficient logging, 2.7) |
| S2 | CISA alert, 2026-10-28: https://www.cisa.gov/news-events/alerts/2026/10/28/cisa-adds-two-known-exploited-vulnerabilities-catalog | Primary | CVE-2026-41709 added to KEV |
| S3 | The Hacker News: https://thehackernews.com/2026/10/china-linked-hackers-exploited-vmware.html | Secondary | 41709 used as a zero-day "to reduce audit trail visibility", citing CrowdStrike |
| S6 | VMware VMSA-2026-0009 Q&A: https://github.com/vmware/vcf-security-and-compliance-guidelines/blob/main/security-advisories/vmsa-2026-0009/README.md | Primary | Quick Patch eligibility, upgrade-path block, Enhanced Linked Mode scope |
| S9 | GTIG / Mandiant, ARMORY CASTLE and vSphere: https://cloud.google.com/blog/topics/threat-intelligence/armory-castle-exploits-vsphere | Primary | The full attack chain, tool names and paths, ports, banner, compensating controls |
| S10 | Broadcom VMSA-2026-0009: https://support.broadcom.com/web/ecx/support-content-notification/-/external/content/SecurityAdvisories/0/39495 | Primary | CVE-2026-123890 to 123894, fixed versions, no workaround |
| S11 | CISA KEV JSON feed: https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json | Primary | KEV status (catalog version 2026.11.18, read 2026-11-19 18:15 PT) |
| S15 | Broadcom VMSA-2026-0008: https://support.broadcom.com/web/ecx/support-content-notification/-/external/content/SecurityAdvisories/0/39445 | Primary | CVE-2026-111497 (SDDC Manager, Brotli decoder) |

## Prior art

| Id | Source | What it shows |
|---|---|---|
| P1 | Splunk, ESXi Post Compromise: https://research.splunk.com/stories/esxi_post_compromise/ | ESXi shell, VIB and audit-tampering detections are established practice |
| P2 | Splunk blog, detecting ESXi ransomware activity: https://www.splunk.com/en_us/blog/security/detecting-esxi-ransomware-activity-splunk.html | Pre-ransomware ESXi activity |
| P3 | SigmaHQ esxcli rules (mirror): https://detection.fyi/sigmahq/sigma/linux/process_creation/proc_creation_lnx_esxcli_vm_discovery/ | esxcli rules use `product: linux, category: process_creation` |
| P4 | Elastic, ESXi SSH Session from vpxuser: https://www.elastic.co/guide/en/security/8.19/prebuilt-rule-8-19-36-esxi-ssh-session-from-vpxuser.html | vpxuser SSH detection |
| P5 | CrowdStrike, vCenter SIEM detections: https://crowdstrike.com/en-us/blog/falcon-next-gen-siem-protects-against-vmware-vcenter-attacks | Management-plane log detection is vendor practice |
| P6 | Mandiant, vSphere detection, containment and hardening: https://cloud.google.com/blog/topics/threat-intelligence/vmware-detection-containment-hardening | vSphere hardening guidance |
| P7 | Mandiant, vcsa-hardening-tool (Apache-2.0): https://github.com/mandiant/vcsa-hardening-tool | Default-deny iptables and shell logging on the VCSA |
| P8 | IBM Community, detecting Golden SAML in QRadar: https://community.ibm.com/community/user/blogs/mutaz-alsallal1/2021/01/12/detecting-golden-saml-attack-in-qradar ; Sygnia on Golden SAML: https://sygnia.co/?p=1488 | Golden SAML detection by correlating AD FS issuance with sign-ins (AD FS, not vCenter) |
| P9 | US patents titled on detecting Golden SAML or SAML forgery: https://image-ppubs.uspto.gov/dirsearch-public/print/downloadPdf/11818150 , https://image-ppubs.uspto.gov/dirsearch-public/print/downloadPdf/12095785 , https://image-ppubs.uspto.gov/dirsearch-public/print/downloadPdf/12598197 | Titles from search results only, not read. A freedom-to-operate question for counsel if a commercial service is built on this method, not a bar to open work |
| P10 | Octopus Deploy, Argo CD git drift detection: https://octopus.com/docs/argo-cd/live-object-status/git-drift-detection | Live state compared with declared state |
| P11 | NIST SP 800-207, Zero Trust Architecture: https://csrc.nist.gov/pubs/sp/800/207/final | Policy decision and enforcement points |

Further rule references are listed in each rule's `references` field.

## Tools

- pySigma (LGPL-2.1), used only to validate the rules; it is installed in CI, not vendored: https://github.com/SigmaHQ/pySigma
- MITRE ATT&CK, loaded by pySigma for tag validation (ATT&CK v19.2 on 2026-11-19): https://attack.mitre.org/

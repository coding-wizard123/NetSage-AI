# NetSage AI - Responsible AI & Human-in-the-Loop (HITL) Audit Log

**Project:** NetSage AI (AI-Assisted Cisco Network Troubleshooting Assistant)  
**Document Version:** 1.0  
**Framework:** NIST AI Risk Management Framework & Responsible AI Principles in Network Automation  

---

## 1. Overview & Policy Statement

Autonomous AI network management introduces critical operational risks if AI suggestions are applied directly without validation. NetSage AI implements a **Human-in-the-Loop (HITL)** architecture where the AI serves as an advisory assistant. 

### Core Safeguards:
1. **Mandatory Human Sign-Off:** Any remediation involving routing protocol state changes, ACL re-ordering, security boundaries, or interface administrative resets requires manual review.
2. **Confidence Thresholding:** Diagnoses with confidence below `0.90` automatically trigger an alert recommending human verification.
3. **Deterministic Fallback:** The deterministic rule engine (`checker.py`) cross-verifies LLM outputs against exact Cisco IOS regex patterns to eliminate hallucinations.
4. **Audit Trail:** Every human intervention, override, and correction is permanently logged to refine future diagnostic rules.

---

## 2. Detailed Human Review Correction Logs (5 Cases)

Below are the 5 benchmark cases where human network engineers identified incomplete, misleading, or potentially disruptive AI recommendations and applied expert corrections.

---

### Case 1: Case ID `C012` — OSPF Adjacency Failure (Passive Interface)

- **Symptom:** OSPF neighbors are not forming between R1 and R2 across the point-to-point link.
- **Show Output:** `show ip ospf neighbor is empty; show run interface Gi0/0 has passive-interface effect`
- **Initial AI Output:**
  - *Diagnosed Root Cause:* OSPF process configuration error or Area ID mismatch.
  - *Suggested Fix:* `clear ip ospf process` and re-enter `network 10.0.0.0 0.0.0.3 area 0`.
  - *AI Confidence:* `0.78`
- **Human Reviewer Assessment:**
  - *Review Decision:* ❌ **CORRECTED / REFINED**
  - *Engineering Evaluation:* The AI's suggestion to clear the OSPF process causes unnecessary network flapping and packet drops without addressing the root cause. The `passive-interface` command suppresses OSPF Hello packets on that link, preventing neighbor state transition to INIT/2-WAY/FULL.
- **Corrected Action & Remediation:**
  ```text
  Router(config)# router ospf 1
  Router(config-router)# no passive-interface GigabitEthernet0/0
  Router(config-router)# end
  Router# show ip ospf neighbor
  ```
- **Responsible AI Takeaway:** Added rule `_check_ospf_passive_interface` to deterministic engine to prevent invasive OSPF process restarts.

---

### Case 2: Case ID `C015` — SSH Access Failure via VTY Lines

- **Symptom:** Administrator SSH to router fails with connection refused, but ICMP ping to the router's IP works.
- **Show Output:** `show access-lists VTY-ACL denies tcp host 192.168.5.10 any eq 22`
- **Initial AI Output:**
  - *Diagnosed Root Cause:* Missing RSA crypto keys or SSH version 1 disabled.
  - *Suggested Fix:* `crypto key generate rsa modulus 2048` and `ip ssh version 2`.
  - *AI Confidence:* `0.75`
- **Human Reviewer Assessment:**
  - *Review Decision:* ❌ **CORRECTED**
  - *Engineering Evaluation:* Ping reachability proved Layer 3 connectivity, and the show output clearly displayed a VTY `access-class` ACL actively dropping TCP port 22 from the source IP `192.168.5.10`. Regenerating crypto keys would disrupt existing SSH sessions without fixing the ACL denial.
- **Corrected Action & Remediation:**
  ```text
  Router(config)# ip access-list extended VTY-ACL
  Router(config-ext-nacl)# permit tcp host 192.168.5.10 any eq 22
  Router(config-ext-nacl)# end
  ```
- **Responsible AI Takeaway:** Guardrail added: when `show access-lists` displays explicit TCP 22 drops, prioritize ACL inspection before crypto subsystem reconfiguration.

---

### Case 3: Case ID `C018` — NAT Translations Working but Internet Unreachable

- **Symptom:** Inside clients cannot browse external websites; NAT translations exist in the table.
- **Show Output:** `show ip nat translations shows translated address; default route absent`
- **Initial AI Output:**
  - *Diagnosed Root Cause:* NAT overload access-list misconfiguration or DNS failure.
  - *Suggested Fix:* `ip nat inside source list 1 interface Gi0/0 overload`.
  - *AI Confidence:* `0.80`
- **Human Reviewer Assessment:**
  - *Review Decision:* ❌ **CORRECTED**
  - *Engineering Evaluation:* The presence of active NAT translation records proves that `ip nat inside/outside` and ACL matching are functioning properly. The underlying issue is that the edge router does not possess a default gateway (`0.0.0.0/0`) route to forward the translated packets toward the ISP.
- **Corrected Action & Remediation:**
  ```text
  Router(config)# ip route 0.0.0.0 0.0.0.0 203.0.113.1
  Router(config)# end
  Router# show ip route
  ```
- **Responsible AI Takeaway:** Disambiguated NAT translation verification from egress routing prerequisites.

---

### Case 4: Case ID `C020` — Wireless Guest Isolation Failure

- **Symptom:** Guest Wi-Fi clients on VLAN 40 can access sensitive corporate servers in 10.0.0.0/8.
- **Show Output:** `show vlan brief shows Guest VLAN 40; ACL has no isolation rule`
- **Initial AI Output:**
  - *Diagnosed Root Cause:* Wireless Access Point (AP) client isolation setting disabled.
  - *Suggested Fix:* Enable Layer 2 Client Isolation on the Wireless LAN Controller (WLC).
  - *AI Confidence:* `0.82`
- **Human Reviewer Assessment:**
  - *Review Decision:* ❌ **CORRECTED**
  - *Engineering Evaluation:* While L2 client isolation stops peer-to-peer communication among guests on the same AP, it does *not* prevent Inter-VLAN routing to internal corporate subnets. A Layer 3 Access Control List must be applied to the Gateway/SVI.
- **Corrected Action & Remediation:**
  ```text
  Router(config)# ip access-list extended GUEST_RESTRICTIONS
  Router(config-ext-nacl)# deny ip any 10.0.0.0 0.255.255.255
  Router(config-ext-nacl)# deny ip any 172.16.0.0 0.15.255.255
  Router(config-ext-nacl)# deny ip any 192.168.0.0 0.0.255.255
  Router(config-ext-nacl)# permit ip any any
  Router(config-ext-nacl)# exit
  Router(config)# interface Vlan40
  Router(config-if)# ip access-group GUEST_RESTRICTIONS in
  Router(config-if)# end
  ```
- **Responsible AI Takeaway:** Integrated zero-trust network segmentation guidelines into Layer 3/4 security prompt rules.

---

### Case 5: Case ID `C029` — Port-Security Err-Disable State on Access Port

- **Symptom:** PC has valid IP address and can ping localhost, but cannot reach local printer in the same VLAN.
- **Show Output:** `show vlan brief is correct; show interfaces printer-port is err-disabled`
- **Initial AI Output:**
  - *Diagnosed Root Cause:* Faulty physical Ethernet patch cord or duplex mismatch.
  - *Suggested Fix:* Replace physical Ethernet cable and re-negotiate auto-speed.
  - *AI Confidence:* `0.70`
- **Human Reviewer Assessment:**
  - *Review Decision:* ❌ **CORRECTED**
  - *Engineering Evaluation:* The interface is in an `err-disabled` operational state caused by a Cisco Port-Security violation (e.g. MAC address spoofing or exceeding maximum allowed MACs). Replacing the cable will not restore the port until the admin clears the errdisable latch.
- **Corrected Action & Remediation:**
  ```text
  Switch# show port-security interface GigabitEthernet0/10
  Switch(config)# interface GigabitEthernet0/10
  Switch(config-if)# shutdown
  Switch(config-if)# no shutdown
  Switch(config-if)# switchport port-security violation restrict
  Switch(config-if)# end
  ```
- **Responsible AI Takeaway:** Hardcoded `err-disabled` signature detection in `checker.py` to immediately trigger the `shutdown / no shutdown` recovery workflow rather than attributing the fault to hardware.

---

## 3. Summary Metrics & Continuous Improvement

| Case ID | Issue Type | AI Initial Suggestion | Human Corrected Action | Risk Prevented |
| :--- | :--- | :--- | :--- | :--- |
| **C012** | OSPF Routing | Restart OSPF Process | Remove `passive-interface` | Network wide flapping & packet drops |
| **C015** | ACL / Security | Re-generate RSA keys | Permit source in VTY ACL | Service disruption / Management lockout |
| **C018** | NAT / Routing | Reconfigure NAT pool | Add default route `0.0.0.0/0` | False configuration churn |
| **C020** | Wireless / ACL | L2 Client Isolation | Apply Layer 3 SVI boundary ACL | Corporate data breach via guest VLAN |
| **C029** | Interface / Security | Replace physical cable | Port-security bounce cycle | Unnecessary hardware replacement downtime |

---

## 4. Verification & Approval Checklist

- [x] All 5 cases include exact symptoms, show outputs, initial AI answers, human rationales, and verified CLI remediation scripts.
- [x] Rule checker (`checker.py`) updated with deterministic regex for each failure mode.
- [x] Prompt engineering guidelines (`prompts/diagnose_prompt.md`) fortified with negative constraints.
- [x] Human agreement rate tracked in `evaluation_results.json` and dashboard metrics.

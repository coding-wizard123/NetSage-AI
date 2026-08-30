# NetSage AI: Demo Video Script & Walkthrough Outline

**Project:** NetSage AI (AI Troubleshooting Helper with Human Review for Cisco Packet Tracer)  
**Target Duration:** 3 to 5 Minutes  
**Audience:** Network Engineering Mentors, CCNA/CCNP Instructors, Applied AI Evaluators  

---

## Part 1: Video Outline & Timestamp Guide

| Timestamp | Phase | Visual Cue | Key Talking Points |
| :--- | :--- | :--- | :--- |
| **0:00 - 0:45** | **Introduction & Problem** | Title Slide / NetSage AI Banner | Problem: Network lab troubleshooting is tedious; pure LLMs can hallucinate invalid IOS commands or disrupt live networks. NetSage AI solves this with a **Hybrid Rule Engine + LLM + Human Review Loop**. |
| **0:45 - 1:30** | **Dataset & Coverage** | Streamlit Dataset Explorer (`cases.csv`) | 30 structured Packet Tracer test cases spanning **VLANs, Gateway, DHCP, DNS, Routing, ACLs, NAT, Wireless, and Interfaces**. |
| **1:30 - 2:30** | **Live Diagnostic Demo (Case C001)** | Interactive Troubleshooter tab | Demo Scenario: PC in VLAN 10 cannot ping default gateway. Input show output `interface Gi0/1 trunk allowed VLANs 20,30`. NetSage instantly catches missing VLAN 10 and generates verified CLI remediation. |
| **2:30 - 3:30** | **Responsible AI in Action (Case C012)** | HITL Review Console (`responsible_ai_log.md`) | Demo Edge Case: OSPF neighbor failure. Show how human reviewer overrides AI restart advice to remove `passive-interface Gi0/0`, preventing routing flapping. |
| **3:30 - 4:15** | **Analytics & Agreement Metrics** | Metrics & Analytics Dashboard | Review key performance indicators: **100% Rule Engine accuracy**, **83.3% Human Agreement Rate**, OSI Layer breakdown, and Severity distribution. |
| **4:15 - 4:30** | **Conclusion & Impact** | Summary Slide & GitHub Repository Link | Wrap-up: NetSage AI demonstrates trustworthy, grounded AI in networking education and enterprise NOC environments. |

---

## Part 2: Step-by-Step Spoken Script

### [0:00 - 0:45] Intro
> **Speaker:**  
> "Hello and welcome to the demonstration of **NetSage AI** — an intelligent, human-in-the-loop troubleshooting assistant designed for Cisco Packet Tracer and enterprise networking labs.  
> When students and junior network engineers troubleshoot connectivity failures, diagnosing across the 7 layers of the OSI model can be daunting. While Large Language Models are helpful, unconstrained AI can hallucinate commands or recommend disruptive actions like clearing entire routing tables.  
> NetSage AI bridges this gap with a hybrid architecture: pairing a deterministic Cisco rule engine with structured LLM reasoning and an explicit Human-in-the-Loop review gate."

---

### [0:45 - 1:30] Dataset & Architecture
> **Speaker:**  
> "Let's first look at our benchmark dataset in the **Dataset Explorer**. NetSage AI is trained and evaluated on 30 diverse network failure scenarios covering all core networking domains: VLAN trunks, default gateways, DHCP pools and relays, DNS resolution, OSPF and static routing, access control lists, NAT overload, and wireless SSID mappings.  
> Every case is categorized by OSI layer, severity, expected fault, and realistic Cisco IOS `show` command outputs."

---

### [1:30 - 2:30] Live Troubleshooting Demonstration
> **Speaker:**  
> "Now let's head over to the **Interactive Troubleshooter**.  
> Here, we select Case `C001`: A PC in VLAN 10 is unable to reach another VLAN. The show command output reveals `interface Gi0/1 trunk allowed VLANs 20, 30`.  
> When we click **Run NetSage AI Diagnostic**, our deterministic engine detects the signature in under 10 milliseconds: *'VLAN 10 is missing from the trunk allowed list'*.  
> On the right, NetSage AI synthesizes the complete diagnosis at Layer 2, outputs a confidence score of 98%, and provides copy-pasteable, hierarchical Cisco IOS configuration steps: `switchport trunk allowed vlan add 10` followed by verification commands."

---

### [2:30 - 3:30] Responsible AI & Human Review Loop
> **Speaker:**  
> "What makes NetSage AI truly production-grade is its **Human-in-the-Loop safeguards**.  
> Let's look at Case `C012` in our **Responsible AI Log**. In this scenario, OSPF neighbors were failing to form. An unconstrained AI suggested restarting the OSPF routing process — a disruptive action that causes network-wide route flapping.  
> Our Human Review Console flagged the case, allowing the network engineer to correct the root cause: the physical link was suppressed by a `passive-interface` statement. The human approved the safe fix: `no passive-interface Gi0/0`.  
> We have documented 5 comprehensive case studies in our `responsible_ai_log.md` covering OSPF, VTY SSH access-classes, NAT egress routes, wireless guest segmentation, and port-security err-disable recovery."

---

### [3:30 - 4:30] Analytics & Wrap-up
> **Speaker:**  
> "Finally, let's look at the **Metrics & Analytics Dashboard**.  
> Across all 30 benchmark cases, NetSage AI achieves a **100% Rule Engine hit rate**, an **83.3% automated Human Agreement Rate**, and an average confidence score of 0.95.  
> The dashboard provides interactive visualizations of fault distributions across the OSI model, severity ratings, and real-time human decision audits.  
> NetSage AI proves how AI and domain engineering principles combine to build safe, accurate, and explainable network assistants. Thank you!"

---

## Part 3: Recording Checklist for Video Producer

- [ ] Ensure Streamlit app is running (`streamlit run app.py`).
- [ ] Open browser at `http://localhost:8501` in 1080p full-screen view (Dark Theme).
- [ ] Have Cisco Packet Tracer open side-by-side (optional for visual enhancement).
- [ ] Test microphone audio levels.
- [ ] Walk through the 5 pages sequentially according to the timestamp guide.

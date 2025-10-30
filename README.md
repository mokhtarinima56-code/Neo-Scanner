# Neo Scanner – Real-World Applications in Reconnaissance & Cyber Operations

**Neo Scanner** is not a toy.  
It’s a **precision reconnaissance instrument** built for operators who need **fast, reliable, and visually clear intel** in high-pressure environments — whether you're hunting bugs, mapping attack surfaces, or teaching the next generation of hackers.

---

## Core Use Cases (With Tactical Context)

| Use Case | Scenario | How Neo Scanner Wins |
|--------|----------|----------------------|
| ### **1. Bug Bounty Recon** | You're in a live program. Target scope: `*.example.com`. Time: 2 hours. | **Lock on `api.example.com` → instant matrix shows `8080` open with `Node.js` + missing `HSTS`** → immediate RCE or SSRF vector identified. |
| | | **Speed + clarity = faster payouts.** |

| | | |
| ### **2. Red Team Target Profiling** | Phase 1 of a 2-week engagement. Need to map **all web entry points** across 50+ subdomains. | Run Neo Scanner in **batch mode (future)** → export JSON → feed into Burp/Nuclei. |
| | | **No noise. Only live HTTP/S services.** |

| | | |
| ### **3. CTF Web Challenges** | 30-minute web challenge. Need to find the **admin panel** or **debug endpoint**. | Scan `target.ctf` → `8443` open → `title: "Internal Dashboard"` → **direct path to flag**. |
| | | **Sub-3-second scans = speedrunning edge.** |

| | | |
| ### **4. Penetration Test Scoping** | Client says: *"Just test the main site."* But you know better. | Scan `client.com` → discovers `dev.client.com:8080` running **WordPress 4.7** → **out-of-scope critical finding**. |
| | | **Expands scope. Justifies budget.** |

| | | |
| ### **5. Security Training & Labs** | Teaching "Web Enumeration 101" to students or new analysts. | **DOS CRT GUI = instant immersion.** Students *feel* like hackers while learning real `nmap` + HTTP logic. |
| | | **No setup. No browser. Pure terminal mindset.** |

| | | |
| ### **6. Live Incident Response Triage** | Alert: possible web shell on `server47.prod`. Need to confirm exposure. | Point Neo Scanner at IP → **port 80 open, title: "Uploader v2", server: Apache/2.2.3** → **confirmed legacy app, likely compromised**. |
| | | **Fast triage = faster containment.** |

| | | |
| ### **7. Personal Lab & Homelab Mapping** | You run 15 services in Docker. Want a **live topology dashboard**. | Run Neo Scanner locally → **ASCII map updates in real time** → see `traefik:8080`, `grafana:3000`, `vault:8200` all at once. |
| | | **Your network, in green phosphor.** |

---

## Why It Fits These Workflows

| Requirement | Neo Scanner Solution |
|-----------|---------------------|
| **Speed** | 4-port scan + HTTP probe = **under 5 seconds** |
| **Clarity** | **Matrix table + color logs** = no parsing raw output |
| **Focus** | **Only web ports** = no 65k noise |
| **Stealth** | `-Pn -T4 -n` + 5s timeout = **low footprint** |
| **Portability** | Single `.py` + `fonts/` folder = **drop and run** |
| **Teachability** | **Every step logged** = perfect for walkthroughs |

---

## Tactical Workflow Example (Bug Bounty)

```text
1. [INPUT] https://sub.example.com
2. [RESOLVE] → 203.0.113.45
3. [SCAN] → 443 open (https), 8080 open (http)
4. [PROBE 443] → Title: "API Gateway" | Server: nginx/1.18 | Tech: React
   → SEC: HSTS present, X-Frame-Options missing
5. [PROBE 8080] → Title: "Debug Console" | Server: Jetty/9.4 | X-Powered-By: Spring
   → SEC: ALL MISSING
6. [ACTION] → Target 8080 for open redirect / SSRF

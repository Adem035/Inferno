<tool_protocols>
## CRITICAL: Docker vs Local Execution

**`generic_linux_command`** = Runs in Kali Docker container (USE FOR PENTEST TOOLS!)
- Has: nmap, gobuster, ffuf, sqlmap, searchsploit, hydra, nuclei, nikto, etc.
- Paths: /usr/share/seclists/, /usr/share/wordlists/, /wordlists/
- Workspace: /workspace/

**`execute_command`** = Runs locally on host machine
- Use for: file ops, git, local scripts
- Does NOT have: pentest tools, seclists, wordlists

**ALWAYS use `generic_linux_command` for:**
- Port scanning (nmap, masscan)
- Web fuzzing (gobuster, ffuf, dirb)
- Vulnerability scanning (nuclei, nikto)
- Exploitation (sqlmap, searchsploit, hydra)
- Any command needing /usr/share/seclists/ or /usr/share/wordlists/

## Tool Selection Hierarchy

1. **High confidence (>80%)** → Specialized tools (sqlmap, nuclei, hydra)
2. **Medium confidence (50-80%)** → Generic tools with targeted payloads
3. **Low confidence (<50%)** → Information gathering, reconnaissance
4. **Version detected** → NVD lookup before exploitation

**Core Rule**: Use Tool Search to discover specialized wrappers. They provide structured parameters, auto wordlists, and better error handling.

## Tool Search

Use Tool Search to find specialized tool wrappers:
```
- nmap_scan → Port scanning with service detection
- gobuster → Directory enumeration with auto-wordlist
- sqlmap → SQL injection with auto-configuration
- nuclei → CVE and template scanning
- nikto → Web server misconfiguration
- hydra → Credential brute forcing
- hashcracker → Hash identification and cracking
- nvd_lookup → CVE database queries
- git_dumper → Exposed .git repository dumping
```

## Shell Commands

For tools without wrappers, use shell directly:
- Use appropriate timeouts (default 5 min for scans)
- Parse output to extract actionable information
- Save verbose output to files for later reference

**Timeout Guidance**:
| Tool | Typical Time | Max Timeout |
|------|--------------|-------------|
| nmap quick | 1-2 min | 5 min |
| nmap full | 5-15 min | 20 min |
| gobuster | 2-5 min | 10 min |
| nuclei | 5-30 min | 30 min |
| amass | 10-60 min | AVOID - use subfinder |
| subfinder | 1-2 min | 5 min |

## Memory Tools

**CRITICAL**: Store findings immediately when discovered.

```
memory_store(content, memory_type, severity, tags)
- content: What you found
- memory_type: finding | credential | vulnerability | recon | context
- severity: critical | high | medium | low | info
- tags: List of relevant tags

memory_list(memory_type)
- Retrieve all memories of a type

memory_search(query)
- Search across all memories
```

**When to store**:
- Vulnerability confirmed → Store immediately
- Credentials found → Store immediately
- Important recon data → Store for later reference
- At 90% budget → Dump everything

## NVD Lookup + Exploit Search

**MANDATORY** when you detect any version:

```
nvd_lookup(software="X", version="Y")
nvd_lookup(auto_detect="nginx/1.18.0")
```

Response interpretation:
- 🔥 EXPLOIT = Public exploit available, check URL
- ⚡ EXPLOITABLE = High exploitability, worth trying
- CVSS 9.0+ = Critical, prioritize immediately

**IMMEDIATELY AFTER finding a CVE, search for exploits:**
```bash
# Step 1: Search local exploit-db
searchsploit CVE-2024-XXXX
searchsploit <software> <version>

# Step 2: Copy exploit locally
searchsploit -m exploits/php/webapps/51234.py

# Step 3: Only if searchsploit has nothing, then try GitHub
# git clone https://github.com/... (LAST RESORT)
```

## HTTP Requests

For API testing and web requests:
- Test all HTTP methods (GET, POST, PUT, DELETE, PATCH)
- Check response codes, headers, body
- Look for: authentication bypass, IDOR, data exposure

## Code Execution

When shell isn't enough:
- Python for complex payload generation
- For HTTP request sequences
- For data processing and analysis

## Output Management

**Large outputs** (sqlmap, nmap -A, nuclei):
- Pipe to file when possible
- Extract only relevant information for context
- Reference file path in findings

**Evidence collection**:
- Save request/response pairs
- Screenshot important findings
- Document exact commands used
</tool_protocols>

<tool_specific_guidance>
## Reconnaissance Tools (ALL RUN IN DOCKER!)

**REMEMBER**: Use `generic_linux_command()` for ALL these tools. They run in the Kali Docker container.

**subfinder** (preferred for subdomains):
```bash
generic_linux_command("subfinder -d target.com -silent")
```

**nmap** (port scanning):
```bash
generic_linux_command("nmap -sV -sC target.com")        # Quick service scan
generic_linux_command("nmap -p- target.com")            # Full port scan
generic_linux_command("nmap -sU --top-ports 100 target.com")  # UDP scan
```

## Web Testing Tools

**gobuster** (directory enumeration):
```bash
# Common wordlist
generic_linux_command("gobuster dir -u http://target -w /usr/share/seclists/Discovery/Web-Content/common.txt")
# Medium wordlist (larger)
generic_linux_command("gobuster dir -u http://target -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt")
# With extensions
generic_linux_command("gobuster dir -u http://target -w /usr/share/wordlists/dirb/common.txt -x php,txt,html,bak")
```

**ffuf** (fast fuzzer):
```bash
# Directory fuzzing
generic_linux_command("ffuf -u http://target/FUZZ -w /usr/share/seclists/Discovery/Web-Content/common.txt -mc all -fc 404")
# API endpoint fuzzing
generic_linux_command("ffuf -u http://target/api/FUZZ -w /usr/share/seclists/Discovery/Web-Content/api/api-endpoints-res.txt -mc all -fc 404")
# Parameter fuzzing
generic_linux_command("ffuf -u 'http://target/page?FUZZ=test' -w /usr/share/seclists/Discovery/Web-Content/burp-parameter-names.txt -mc all -fc 404")
```

**nikto** (web server scan):
```bash
generic_linux_command("nikto -h http://target")
```

**nuclei** (vulnerability scanning):
```bash
generic_linux_command("nuclei -u http://target -severity critical,high")
generic_linux_command("nuclei -u http://target -tags cve")
```

## Exploitation Tools

**searchsploit** (ALWAYS USE FIRST for exploits!):
```bash
# Search for exploits by software/CVE
generic_linux_command("searchsploit wordpress givewp")
generic_linux_command("searchsploit CVE-2024-5932")
generic_linux_command("searchsploit apache 2.4")
generic_linux_command("searchsploit nginx 1.18")

# Copy exploit to workspace
generic_linux_command("searchsploit -m exploits/php/webapps/51234.py")

# Show exploit info
generic_linux_command("searchsploit -x exploits/php/webapps/51234.py")
```
**CRITICAL**: ALWAYS use searchsploit BEFORE cloning from GitHub!
- Local database = faster, no network required
- Has curated, working exploits from Exploit-DB
- Use `searchsploit -m` to copy exploits to /workspace/

**sqlmap** (SQL injection):
```bash
generic_linux_command("sqlmap -u 'http://target/page?id=1' --batch --dbs")
generic_linux_command("sqlmap -u 'http://target/page?id=1' --batch --tables -D dbname")
generic_linux_command("sqlmap -u 'http://target/page?id=1' --batch --dump -T users")
```

**hydra** (brute force):
```bash
# SSH brute force
generic_linux_command("hydra -l admin -P /usr/share/wordlists/rockyou.txt ssh://target")
# HTTP POST form
generic_linux_command("hydra -l admin -P /usr/share/seclists/Passwords/Common-Credentials/10k-most-common.txt target http-post-form '/login:user=^USER^&pass=^PASS^:Invalid'")
```

## Hash Cracking

**john** (password cracker):
```bash
generic_linux_command("john --wordlist=/usr/share/wordlists/rockyou.txt hashes.txt")
generic_linux_command("john --show hashes.txt")
```

**hashcat** (GPU-accelerated):
```bash
generic_linux_command("hashcat -m 0 -a 0 hash.txt /usr/share/wordlists/rockyou.txt")  # MD5
generic_linux_command("hashcat -m 1000 hash.txt /usr/share/wordlists/rockyou.txt")   # NTLM
```

## Git Exposure

```bash
# Check for exposed .git
generic_linux_command("curl -s http://target/.git/HEAD")
# If found, use git-dumper
generic_linux_command("git-dumper http://target/.git/ /workspace/dumped_repo")
```

## Common Wordlist Paths (IN DOCKER)

| Type | Path |
|------|------|
| Directories | `/usr/share/seclists/Discovery/Web-Content/common.txt` |
| Directories (large) | `/usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt` |
| API endpoints | `/usr/share/seclists/Discovery/Web-Content/api/api-endpoints-res.txt` |
| Parameters | `/usr/share/seclists/Discovery/Web-Content/burp-parameter-names.txt` |
| Subdomains | `/usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt` |
| Passwords | `/usr/share/wordlists/rockyou.txt` |
| Dirb common | `/usr/share/wordlists/dirb/common.txt` |
</tool_specific_guidance>

<human_methodology_tools>
## Human-Like Pentesting Tools (USE THESE!)

These tools make you think and act like a skilled human pentester, not an automated scanner.

### browse (Application Explorer)
Explore applications like a human would. Build understanding before attacking.

```
# Start exploring a page
browse(action="explore", url="https://target.com/login")

# Analyze response content
browse(action="analyze", url="https://target.com/login", content=<html_content>)

# Get your application map (mental model)
browse(action="map")

# Check recon completeness (must be >70% before exploitation!)
browse(action="score")

# Track a hypothesis
browse(action="hypothesis", hypothesis={
    "target": "/api/users?id=1",
    "vulnerability": "IDOR",
    "evidence_for": ["ID visible in URL"],
    "confidence": 70,
    "next_test": "Try id=2",
    "status": "testing"
})

# Record notes (like a human pentester)
browse(action="note", note="Login has no rate limiting", note_type="interesting")
```

**IMPORTANT**: Recon score must be ≥70% before exploitation!

### target_profiler (Strategy Guide)
Profile targets to choose the right attack strategy based on industry and security posture.

```
# Create target profile
target_profiler(action="profile", url="https://api.fintech.com",
    endpoints=["/api/v1/users", "/api/v1/transactions"])

# Analyze security headers
target_profiler(action="analyze_headers", headers={
    "Server": "nginx/1.18.0",
    "X-Frame-Options": "DENY",
    "Content-Security-Policy": "default-src 'self'"
})

# Get attack recommendations
target_profiler(action="recommend")

# List industry profiles
target_profiler(action="industries")
```

**Industry Profiles**: fintech, ecommerce, saas, healthcare, social, api_service, ctf

## Human Pentester Workflow

**START EVERY ASSESSMENT LIKE THIS:**

```
1. Profile the target
   target_profiler(action="profile", url="...", endpoints=[...])

2. Explore the application
   browse(action="explore", url="...")
   browse(action="analyze", content=<response>)

3. Check recon score
   browse(action="score")
   # If <70%, keep exploring!

4. Get strategy recommendations
   target_profiler(action="recommend")

5. Only then start exploitation
   # Follow the prioritized vulnerability list
```

## Memory Types for Human-Like Tracking

Store different types of information like a real pentester's notes:

### Core Memory Types
| Type | Use For | Example |
|------|---------|---------|
| `findings` | Confirmed vulnerabilities | "SQLi on /api/users - UNION-based" |
| `hypothesis` | Potential vulns to test | "user_id might be IDOR, 70% confidence" |
| `todo` | Follow-up tests | "Test all IDs on /api/orders" |
| `dead_end` | Failed approaches | "SQLi blocked by WAF after 15 tries" |
| `interesting` | Observations | "Different errors for valid/invalid users" |
| `identifier` | IDs for cross-testing | "user_id=47 found in JWT" |

### Pentester-Focused Memory Types (IMPORTANT!)

| Type | Use For | Auto-Store When... |
|------|---------|-------------------|
| `credential` | Password/token vault with testing state | You find ANY credential (passwords, API keys, tokens, hashes) |
| `attack_chain` | Multi-step exploitation paths | You complete an attack sequence (e.g., SQLi → creds → login) |
| `foothold` | Active shells/sessions/access | You establish ANY remote access (shell, SSH, RDP) |
| `defense` | WAF/security bypass notes | You detect WAF/firewall or find bypass techniques |
| `payload` | Successful payloads for reuse | A payload successfully exploits a vulnerability |
| `enumeration` | Track enumeration progress | Track what's been scanned vs pending |
| `evidence` | Request/response pairs | You confirm a vulnerability with PoC |
| `false_positive` | Things that weren't exploitable | Something looked vulnerable but wasn't |

### AUTO-STORE RULES (MANDATORY!)

**When you find credentials:**
```
memory_store(content="admin:Summer2024!", memory_type="credential", metadata={
    "credential_type": "password",  # password, hash, token, api_key, ssh_key
    "username": "admin",
    "secret": "Summer2024!",
    "found_at": "/backup/db.sql",
    "tested_on": {"ssh:22": "failed", "webapp:/login": "untested"}
})
```

**When you establish a foothold:**
```
memory_store(content="Reverse shell as www-data", memory_type="foothold", metadata={
    "type": "reverse_shell",  # reverse_shell, web_shell, ssh, rdp
    "target": "10.10.10.5",
    "user": "www-data",
    "privilege": "low",
    "status": "active"
})
```

**When you detect WAF/defense:**
```
memory_store(content="Cloudflare WAF detected", memory_type="defense", metadata={
    "defense_type": "WAF",
    "product": "Cloudflare",
    "blocks": ["UNION SELECT", "script>"],
    "bypasses_found": ["case switching", "/**/ comments"]
})
```

**When you complete an attack chain:**
```
memory_store(content="SQLi to admin access", memory_type="attack_chain", metadata={
    "steps": [
        {"step": 1, "action": "SQLi on /api/users", "result": "DB access"},
        {"step": 2, "action": "Extract admin hash", "result": "Found MD5"},
        {"step": 3, "action": "Crack hash", "result": "admin:password123"},
        {"step": 4, "action": "Login", "result": "Admin access"}
    ],
    "objective_achieved": "admin_access"
})
```

**When a payload works:**
```
memory_store(content="XSS payload bypassing CSP", memory_type="payload", metadata={
    "payload_type": "XSS",
    "payload": "<img src=x onerror=alert(1)>",
    "works_on": ["/comment", "/profile"],
    "bypasses": ["input filter"]
})
```

**ALWAYS check dead_ends before trying an approach!**
```
memory_list(memory_type="dead_end")
```

**Before testing credentials, check what's already tested:**
```
memory_search(query="credentials", memory_type="credential")
```
</human_methodology_tools>

<meta_tool_guide>
## Meta Tool - Create Custom Tools On-The-Fly

Like a real hacker writing quick scripts and reusing them. Create tools during runtime!

### Create a Tool
```
meta_tool(action="create", tool_name="my_encoder", description="Custom encoder",
    code='''
import base64

def run(payload: str, iterations: int = 1) -> str:
    result = payload
    for _ in range(iterations):
        result = base64.b64encode(result.encode()).decode()
    return result
''')
```

### Call Your Tool
```
meta_tool(action="call", tool_name="my_encoder",
    parameters={"payload": "<script>alert(1)</script>", "iterations": 2})
```

### List All Custom Tools
```
meta_tool(action="list")
```

### Example Tools to Create

**JWT Decoder**:
```python
def run(token: str) -> dict:
    import base64, json
    parts = token.split(".")
    def decode(p):
        p += "=" * (4 - len(p) % 4)
        return json.loads(base64.urlsafe_b64decode(p))
    return {"header": decode(parts[0]), "payload": decode(parts[1])}
```

**IDOR ID Generator**:
```python
def run(start: int, count: int = 20) -> list:
    return [str(start + i) for i in range(count)]
```

**Hash Generator**:
```python
def run(value: str) -> dict:
    import hashlib
    return {
        "md5": hashlib.md5(value.encode()).hexdigest(),
        "sha1": hashlib.sha1(value.encode()).hexdigest(),
        "sha256": hashlib.sha256(value.encode()).hexdigest()
    }
```

**Payload Encoder Chain**:
```python
def run(payload: str, encodings: list) -> str:
    import base64, html, urllib.parse
    result = payload
    for enc in encodings:
        if enc == "base64": result = base64.b64encode(result.encode()).decode()
        elif enc == "url": result = urllib.parse.quote(result)
        elif enc == "html": result = html.escape(result)
        elif enc == "double_url": result = urllib.parse.quote(urllib.parse.quote(result))
    return result
```

### Allowed Imports
`re, json, base64, hashlib, urllib, html, binascii, struct, zlib, time, random, string, itertools, collections, functools, math, datetime, uuid, secrets, hmac`

### Rules
- Code MUST define a `run()` function
- No file/network/OS access (sandboxed)
- Tools persist for the session
- Reuse tools instead of rewriting code!
</meta_tool_guide>

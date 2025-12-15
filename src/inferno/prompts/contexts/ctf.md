<context_ctf>
## CTF Challenge Mode

### CTF Mindset

- **Flag is the objective** - Everything leads to the flag
- **Challenges are solvable** - There IS a path
- **Hints matter** - Challenge names, descriptions contain clues
- **Think laterally** - Unusual solutions are common

### Flag Recognition

**Common Flag Formats**:
```
FLAG{...}
flag{...}
CTF{...}
picoCTF{...}
HTB{...}
THM{...}
XBEN{...}
```

**Flag Locations**:
- /flag.txt, /home/*/flag.txt
- Database records
- Environment variables
- Memory
- Base64/Hex encoded in responses

### CTF Categories

**Web**:
- SQLi, XSS, SSRF, SSTI
- Authentication bypass
- Business logic flaws
- Source code analysis

**Crypto**:
- Weak ciphers
- Key reuse
- Padding oracles
- Hash collisions

**Forensics**:
- File carving
- Memory analysis
- Steganography
- Log analysis

**Pwn/Binary**:
- Buffer overflow
- Format string
- ROP chains
- Heap exploitation

**Reverse Engineering**:
- Static analysis
- Dynamic analysis
- Obfuscation bypass
- Patching

### CTF Techniques

**Quick Wins**:
```
1. View source code
2. Check robots.txt, .git, .env
3. Inspect headers
4. Try admin:admin, admin:password
5. Check for backup files (.bak, ~, .old)
```

**Web CTF Pattern**:
```
1. Enumerate (gobuster, nikto)
2. Find vulnerability type (SQLi, SSTI, etc.)
3. Exploit to read files or get shell
4. Find and submit flag
```

**SQLi CTF Pattern**:
```
1. Confirm SQLi exists (error or behavioral difference)
2. ANALYZE CONTEXT: Test for each technique in order of speed:
   - Is output visible? → UNION SELECT (fastest - 1 request!)
   - Are errors visible? → Error-based: updatexml(), extractvalue()
   - Response differs? → Boolean-blind (slower - 50+ requests)
   - No difference? → Time-based SLEEP (slowest - last resort)
3. Extract flag directly when possible:
   - ' UNION SELECT flag,2,3 FROM flags--
   - ' AND updatexml(1,concat(0x7e,(SELECT flag FROM flags),0x7e),1)--
4. DO NOT use blind injection if UNION/error-based works!
```

**CRITICAL SQLi Technique Priority** (ALWAYS follow this order):
| Priority | Technique | Speed | Use When |
|----------|-----------|-------|----------|
| 1st | UNION SELECT | 1-3 requests | Output visible |
| 2nd | Error-based (updatexml) | 1-5 requests | Errors visible |
| 3rd | Boolean-blind | 50-500 requests | Response differs |
| 4th | Time-based SLEEP | 50-500 requests | Last resort only |

**Error-based payloads by database**:
- MySQL: `' AND updatexml(1,concat(0x7e,@@version,0x7e),1)--`
- PostgreSQL: `' AND 1=cast((SELECT version()) as int)--`
- MSSQL: `' AND 1=convert(int,(SELECT @@version))--`

**SSTI CTF Pattern**:
```
1. Confirm template engine
2. Escape sandbox
3. Get code execution
4. Read /flag.txt
```

### Success Detection

When you find the flag:
1. Validate format matches expected pattern
2. Submit/record immediately
3. Store in memory with exact value
4. Stop if this was the objective

### CTF-Specific Termination

**Valid stop conditions**:
- Flag captured and validated
- All challenges in scope completed
- Budget exhausted after exhaustive attempts

**Continue until**:
- Flag found OR
- All techniques exhausted on all challenges
</context_ctf>

#!/usr/bin/env python3
"""Portable regex-based source checker; rules are advisory and reviewable."""
import argparse,re
from pathlib import Path

RULES=[
 ("C001","HIGH",r"\bgets\s*\(","gets is unsafe; use a bounded input function"),("C002","HIGH",r"\bstrcpy\s*\(","strcpy can overflow; validate bounds or use a bounded alternative"),("C003","HIGH",r"\bsprintf\s*\(","sprintf can overflow; use snprintf with a checked size"),("C004","MEDIUM",r"\bstrcat\s*\(","strcat requires careful destination-size validation"),("C005","MEDIUM",r"\bscanf\s*\(\s*\"[^\"]*%s","scanf %s needs a field width"),("C006","MEDIUM",r"\bmalloc\s*\(","Check allocation result and release ownership"),("C007","MEDIUM",r"\bfree\s*\(","Review ownership and ensure pointer is not reused"),("C008","LOW",r"\bprintf\s*\(\s*[^\"\s]","Non-literal printf format may be unsafe"),
 ("PY001","MEDIUM",r"except\s*:","Bare except catches process-control exceptions"),("PY002","MEDIUM",r"\beval\s*\(","eval executes input as code"),("PY003","MEDIUM",r"\bexec\s*\(","exec executes dynamic code"),("PY004","LOW",r"\bprint\s*\(","Review debug output before release"),("PY005","LOW",r"\bTODO\b","TODO marker remains"),("PY006","MEDIUM",r"\bassert\s+False\b","Unconditional assertion fails at runtime"),("PY007","LOW",r"\bglobal\s+[A-Za-z_]","Global state complicates isolation"),("PY008","MEDIUM",r"except\s+Exception\s*:","Broad exception handler may hide defects"),
 ("SEC001","HIGH",r"\b(password|secret|api[_-]?key)\s*=\s*['\"][^'\"]+","Possible hard-coded credential"),("SEC002","HIGH",r"verify\s*=\s*False","TLS certificate verification disabled"),("SEC003","HIGH",r"shell\s*=\s*True","Review command construction for shell injection"),("SEC004","MEDIUM",r"\bmd5\s*\(","MD5 is unsuitable for security-sensitive hashing"),("SEC005","MEDIUM",r"\brandom\.random\s*\(","Use a cryptographic RNG for security-sensitive tokens"),("SEC006","MEDIUM",r"https?://[^\s'\"]+","Review whether endpoint requires TLS"),("SEC007","HIGH",r"\bchmod\s*\([^\n]*0o777","World-writable permissions"),("SEC008","MEDIUM",r"\bpickle\.loads?\s*\(","Untrusted pickle data can execute code"),
 ("REL001","MEDIUM",r"\bwhile\s+True\s*:","Check loop termination and cancellation"),("REL002","LOW",r"time\.sleep\s*\(","Fixed sleep can make tests slow or flaky"),("REL003","MEDIUM",r"except[^\n]*:\s*pass","Exception is silently discarded"),("REL004","LOW",r"\bTODO\b|\bFIXME\b","Unresolved work marker"),("REL005","LOW",r"\bprint\s*\(","Use a configurable logger for operational output"),("REL006","MEDIUM",r"open\s*\([^\n]*\)\s*as\s+","Confirm file encoding is explicit where text portability matters"),("REL007","LOW",r"\bexcept\s+Exception\b","Prefer handling expected exception types"),("REL008","LOW",r"\bpass\s*$","Empty block requires explanation"),
 ("API001","MEDIUM",r"request\.get\s*\(","Set a timeout on outbound HTTP requests"),("API002","MEDIUM",r"urlopen\s*\([^\n]*\)","Set a timeout for outbound URL requests"),("API003","LOW",r"\bjson\.loads\s*\(","Validate untrusted JSON schema"),("API004","LOW",r"\bexcept\s+KeyError\b","Avoid using missing fields without schema validation"),("API005","MEDIUM",r"\brequests\.(get|post)\s*\(","Check timeout and response status"),("API006","LOW",r"\bTODO\b","Document API contract before completion"),("API007","MEDIUM",r"\btimeout\s*=\s*None","Unbounded timeout can hang a worker"),("API008","LOW",r"\bprint\s*\(","Review output for sensitive data"),
 ("STYLE001","LOW",r"\t","Tab indentation can be inconsistent"),("STYLE002","LOW",r"[ \t]+$","Trailing whitespace"),("STYLE003","LOW",r".{121,}","Line exceeds 120 characters"),("STYLE004","LOW",r"\b(?:foo|bar|baz)\b","Placeholder identifier remains"),("STYLE005","LOW",r"\b(?:temp|tmp)\b","Use a descriptive name if this is production logic"),("STYLE006","LOW",r"\b(?:HACK|XXX)\b","Review unresolved marker"),("STYLE007","LOW",r"\bpass\s*$","Empty implementation block"),("STYLE008","LOW",r"\bprint\s*\(","Replace temporary output with structured logging where needed"),
]
def scan(paths):
 findings=[]
 for path in paths:
  try: lines=path.read_text(encoding="utf-8").splitlines()
  except (UnicodeDecodeError,OSError):continue
  for number,line in enumerate(lines,1):
   for rule,severity,pattern,message in RULES:
    if re.search(pattern,line):findings.append({"file":str(path),"line":number,"rule":rule,"severity":severity,"message":message,"source":line.strip()[:240]})
 return findings
def main():
 p=argparse.ArgumentParser();p.add_argument("paths",nargs="+",type=Path);p.add_argument("--fail-on-high",action="store_true");a=p.parse_args();files=[x for pth in a.paths for x in ([pth] if pth.is_file() else pth.rglob("*")) if x.is_file() and x.suffix in {".py",".c",".h",".cc",".cpp",".js",".ts"}]; findings=scan(files)
 for f in findings:print(f"{f['file']}:{f['line']}: {f['severity']} {f['rule']} {f['message']}")
 print(f"Scanned {len(files)} file(s); {len(findings)} finding(s); {len(RULES)} regex rules loaded")
 raise SystemExit(1 if a.fail_on_high and any(f["severity"]=="HIGH" for f in findings) else 0)
if __name__=="__main__":main()

#!/usr/bin/env bash
# ZMSF Linux Audit Toolkit | non-invasive host baseline | v0.1.0
# No exploitation, no automatic updates, no database operations, no telemetry.
set -Eeuo pipefail
umask 077
export LC_ALL=C

VERSION='0.1.0'
APP_DIR=''
OUTPUT_DIR=''
STDOUT_ONLY=0
SKIP_UPDATES=0
MAX_SIGNALS=25

usage() {
  cat <<'EOF'
ZMSF Linux Audit Toolkit v0.1.0
Usage: zmsf-linux-audit.sh [--app-dir PATH] [--output-dir PATH] [--stdout-only] [--no-update-check] [--help]

  --app-dir PATH      Optional local application source directory for limited static triage.
  --output-dir PATH   Store a private timestamped audit report here (default below).
  --stdout-only       Write report to stdout only; does not create a report directory.
  --no-update-check   Skip package update queries; still inventory versions.

Default report directory: /var/lib/zmsf-audit (root), or ~/.local/state/zmsf-audit (user).
Audit only systems you own or have authorization to examine. This is not a vulnerability
scanner or proof of OWASP/ZMSF compliance. No network scanning and no upgrades.
EOF
}

while (($#)); do
  case "$1" in
    --app-dir|--output-dir)
      (($# >= 2)) || { echo "ERROR=ARGUMENT_REQUIRED:$1" >&2; exit 2; }
      if [[ "$1" == --app-dir ]]; then APP_DIR=$2; else OUTPUT_DIR=$2; fi
      shift 2 ;;
    --stdout-only) STDOUT_ONLY=1; shift ;;
    --no-update-check) SKIP_UPDATES=1; shift ;;
    --help|-h) usage; exit 0 ;;
    *) echo "ERROR=UNKNOWN_OPTION:$1" >&2; usage >&2; exit 2 ;;
  esac
done

if [[ -n "$APP_DIR" && ( ! -d "$APP_DIR" || -L "$APP_DIR" ) ]]; then
  echo 'ERROR=APP_DIRECTORY_MISSING_OR_SYMLINK' >&2
  exit 2
fi

have() { command -v "$1" >/dev/null 2>&1; }
run_version() {
  local label=$1; shift
  if have "$1"; then
    local ver
    ver=$("$@" 2>&1 | head -n 1 || true)
    ver=${ver//$'\r'/ }
    [[ -n "$ver" ]] && printf 'VERSION_%s=%s\n' "$label" "$ver" || true
  fi
}

static_app_review() {
  [[ -n "$APP_DIR" ]] || { echo 'APP_STATIC_REVIEW=NOT_REQUESTED'; return 0; }
  if ! have python3; then
    echo 'APP_STATIC_REVIEW=PYTHON3_UNAVAILABLE'
    return 0
  fi
  # No source snippets or secret values are printed. No arbitrary application code is executed.
  python3 - "$APP_DIR" <<'PY'
import ast
import os
import re
import sys
from pathlib import Path

root = Path(sys.argv[1]).resolve()
ignore = {'.git','.venv','venv','node_modules','.tox','dist','build',
          '__pycache__','.mypy_cache','.pytest_cache','coverage','vendor',
          'secrets','backups','backup','.next','.cache'}
patterns = [
 ('HTML_INJECTION_SINK', re.compile(r'\b(?:innerHTML\s*=|insertAdjacentHTML\s*\(|document\.write\s*\()')),
 ('JAVASCRIPT_DYNAMIC_EVAL', re.compile(r'\b(?:eval|Function)\s*\(')),
 ('REACT_RAW_HTML', re.compile(r'\bdangerouslySetInnerHTML\b')),
 ('POSSIBLE_PRIVATE_KEY_IN_SOURCE', re.compile(r'-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----')),
 ('POTENTIAL_EMBEDDED_API_KEY', re.compile(r'(?:sk-proj-|AKIA[0-9A-Z]{16})')),
]
dangerous = {'eval','exec','os.system','os.popen','pickle.loads',
             'marshal.loads','yaml.unsafe_load'}
results = []
checked = 0
max_files = 1000
max_size = 300_000

def fname(expr):
    if isinstance(expr, ast.Name): return expr.id
    if isinstance(expr, ast.Attribute): return fname(expr.value)+'.'+expr.attr
    return ''

for base, dirs, files in os.walk(root, followlinks=False):
    dirs[:] = sorted(d for d in dirs if d not in ignore and
                     not (Path(base)/d).is_symlink())
    for name in sorted(files):
        p = Path(base)/name
        if p.suffix not in {'.py','.js','.jsx','.ts','.tsx','.html','.jinja','.j2'} or p.is_symlink():
            continue
        if checked >= max_files:
            print('APP_SCAN_LIMIT_REACHED=YES')
            break
        try:
            if p.stat().st_size > max_size:
                continue
            data = p.read_text(encoding='utf-8', errors='replace')
        except (OSError, UnicodeError):
            continue
        checked += 1
        rel = str(p.relative_to(root))
        # Never print a matching source line: it could include credentials/PHI.
        for rule, rx in patterns:
            if rule.startswith(('HTML','JAVASCRIPT','REACT')) and p.suffix not in {'.js','.jsx','.ts','.tsx','.html','.jinja','.j2'}:
                continue
            for m in rx.finditer(data):
                results.append((rel, data.count('\n',0,m.start())+1, rule))
                if len(results) >= 200: break
            if len(results) >= 200: break
        if p.suffix == '.py':
            try: tree = ast.parse(data, filename=rel)
            except SyntaxError:
                results.append((rel, 0, 'PYTHON_SYNTAX_ERROR'))
                continue
            for node in ast.walk(tree):
                if not isinstance(node, ast.Call): continue
                f = fname(node.func)
                line = getattr(node, 'lineno', 0)
                if f in dangerous or f == 'yaml.load':
                    results.append((rel,line,'DANGEROUS_CALL_REVIEW'))
                if f.startswith('subprocess.') and any(
                    k.arg == 'shell' and isinstance(k.value, ast.Constant)
                    and k.value.value is True for k in node.keywords
                ):
                    results.append((rel,line,'SHELL_EXECUTION_REVIEW'))
                if f.endswith(('.execute','.executemany')) and node.args and isinstance(node.args[0], (ast.JoinedStr,ast.BinOp)):
                    results.append((rel,line,'DYNAMIC_SQL_REVIEW'))
                if len(results) >= 200: break
        if len(results) >= 200: break
    if checked >= max_files or len(results) >= 200: break

print('APP_STATIC_REVIEW=HEURISTIC_ONLY')
print('APP_FILES_REVIEWED='+str(checked))
print('APP_REVIEW_SIGNALS='+str(len(results)))
for rel, lineno, rule in results[:25]:
    print('APP_REVIEW='+rel.replace('=','_')+':'+str(lineno)+':'+rule)
if len(results) > 25:
    print('APP_EXTRA_SIGNALS_NOT_SHOWN='+str(len(results)-25))
print('APP_SECURITY_CERTIFIED=NO')
PY
}

check_updates() {
  if (( SKIP_UPDATES )); then echo 'PACKAGE_UPDATES=SKIPPED'; return 0; fi
  if have apt; then
    local tmp count
    tmp=$(mktemp) || { echo 'APT_UPDATES=ERROR'; return 0; }
    if apt list --upgradable >"$tmp" 2>/dev/null; then
      count=$(grep -c '\[upgradable from:' "$tmp" || true)
      echo "APT_AVAILABLE_UPDATES_CACHED=$count"
      echo 'APT_STATUS=USING_CACHED_PACKAGE_METADATA'
      echo 'APT_REAL_SECURITY_CVE_SCAN=NOT_PERFORMED'
      # Identifiers only; no source configuration, credentials, or environment values.
      sed -n '/\[upgradable from:/s@/.*@@p' "$tmp" | sed 's/^/APT_PACKAGE_UPDATABLE=/' | head -n 100 || true
      if [[ -d /var/lib/apt/lists ]]; then
        local newest=0 t age
        while IFS= read -r -d '' f; do
          t=$(stat -c %Y "$f" 2>/dev/null || echo 0)
          (( t > newest )) && newest=$t
        done < <(find /var/lib/apt/lists -maxdepth 1 -type f -name '*InRelease' -print0 2>/dev/null)
        if (( newest > 0 )); then
          age=$(( ($(date +%s)-newest)/86400 ))
          (( age < 0 )) && age=0
          echo "APT_INDEX_AGE_DAYS=$age"
          (( age > 2 )) && echo 'APT_METADATA_FRESHNESS=STALE' || echo 'APT_METADATA_FRESHNESS=RECENT_CACHED'
        else
          echo 'APT_METADATA_FRESHNESS=UNKNOWN'
        fi
      fi
    else
      echo 'APT_UPDATES=UNAVAILABLE'
    fi
    rm -f -- "$tmp"
  elif have dnf; then
    local rc=0 updates
    updates=$(dnf --cacheonly -q check-update 2>/dev/null) || rc=$?
    if (( rc == 0 || rc == 100 )); then
      echo 'DNF_UPDATES=USING_CACHED_METADATA'
      echo "$updates" | awk '/^[a-zA-Z0-9_.+-]+\.[a-z0-9_]+[[:space:]]/ {print "DNF_PACKAGE_UPDATABLE=" $1}' | head -n 100 || true
    else
      echo 'DNF_UPDATES=UNAVAILABLE_OR_CACHE_MISSING'
    fi
  elif have yum; then
    echo 'PACKAGE_UPDATES=YUM_CACHE_ONLY_REVIEW_REQUIRED'
  elif have zypper; then
    echo 'PACKAGE_UPDATES=ZYPPER_CACHE_ONLY_REVIEW_REQUIRED'
  elif have apk; then
    echo 'PACKAGE_UPDATES=APK_INDEX_REVIEW_REQUIRED'
  elif have pacman; then
    echo 'PACKAGE_UPDATES=PACMAN_INDEX_REVIEW_REQUIRED'
  else
    echo 'PACKAGE_UPDATES=PACKAGE_MANAGER_UNKNOWN'
  fi
}

check_baseline() {
  echo '===== ZMSF LINUX AUDIT BASELINE ====='
  echo "TOOL_VERSION=$VERSION"
  echo "AUDIT_UTC=$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  echo "HOSTNAME=$(hostname 2>/dev/null || echo unknown)"
  echo "AUDIT_PRIVILEGE=$([[ $EUID -eq 0 ]] && echo ROOT || echo LIMITED_USER)"
  if [[ -r /etc/os-release ]]; then
    (. /etc/os-release; echo "OS_NAME=${PRETTY_NAME:-unknown}"; echo "OS_CODENAME=${VERSION_CODENAME:-unknown}")
  else
    echo 'OS_NAME=UNKNOWN'
  fi
  echo "KERNEL=$(uname -r)"
  echo "ARCH=$(uname -m)"
  run_version NGINX nginx -v
  run_version APACHE apache2 -v
  run_version OPENSSL openssl version
  run_version PYTHON python3 --version
  run_version NODE node --version
  run_version NPM npm --version
  run_version JAVA java -version
  run_version OPENSSH ssh -V
  run_version MONGOD mongod --version
  run_version POSTGRES postgres --version
  echo '===== UPDATE STATUS ====='
  check_updates
  if [[ -e /run/reboot-required ]]; then echo 'REBOOT_FLAG=YES'; else echo 'REBOOT_FLAG=NOT_SET'; fi
  if have systemctl; then
    for s in ssh.service sshd.service nginx.service apache2.service mongod.service postgresql.service docker.service; do
      if systemctl list-unit-files "$s" --no-legend 2>/dev/null | grep -q '^'; then
        echo "SERVICE_${s//./_}=$(systemctl is-active "$s" 2>/dev/null || true)"
      fi
    done
  else
    echo 'SERVICE_MANAGER=NO_SYSTEMCTL'
  fi
  echo '===== HOST SECURITY CONTROLS ====='
  if have ss; then
    local listeners
    listeners=$(ss -H -lnt 2>/dev/null | wc -l || true)
    echo "TCP_LISTENING_SOCKET_COUNT=${listeners//[[:space:]]/}"
    # Not a proof a port is reachable from the Internet.
    ss -H -lnt 2>/dev/null | awk '{print "TCP_LISTEN=" $4}' | head -n 30 || true
  else
    echo 'TCP_LISTEN=UNKNOWN_SS_UNAVAILABLE'
  fi
  if have sshd; then
    local sshcfg
    sshcfg=$(sshd -T 2>/dev/null || true)
    if [[ -n "$sshcfg" ]]; then
      printf '%s\n' "$sshcfg" | awk '/^(permitrootlogin|passwordauthentication|pubkeyauthentication|kbdinteractiveauthentication|authenticationmethods) / {print "SSH_" toupper($1) "=" $2}'
    else
      echo 'SSH_CONFIGURATION=NOT_VERIFIED'
    fi
  fi
  if have ufw; then
    echo "UFW_STATUS=$(ufw status 2>/dev/null | head -n 1 || true)"
  fi
  if have firewall-cmd; then
    echo "FIREWALLD_STATE=$(firewall-cmd --state 2>/dev/null || echo unknown)"
  fi
  if have getenforce; then
    echo "SELINUX=$(getenforce 2>/dev/null || echo unknown)"
  fi
  if [[ -r /sys/module/apparmor/parameters/enabled ]]; then
    echo "APPARMOR_KERNEL_ENABLED=$(cat /sys/module/apparmor/parameters/enabled)"
  fi
  if [[ -r /proc/sys/kernel/randomize_va_space ]]; then
    echo "ASLR_LEVEL=$(cat /proc/sys/kernel/randomize_va_space)"
  fi
  if have nginx; then
    if nginx -t >/dev/null 2>&1; then echo 'NGINX_SYNTAX=PASS'; else echo 'NGINX_SYNTAX=REVIEW_OR_INSUFFICIENT_PRIVILEGE'; fi
  fi
  echo '===== APPLICATION STATIC TRIAGE ====='
  static_app_review
  echo '===== ZMSF / OWASP GAPS ====='
  echo 'ZMSF_DATABASE_FIELD_ENCRYPTION=NOT_VERIFIED'
  echo 'ZMSF_EXTERNAL_KMS_HSM=NOT_VERIFIED'
  echo 'ZMSF_BACKUP_THEFT_EXERCISE=NOT_RUN'
  echo 'ZMSF_PLAINTEXT_WINDOW=NOT_TESTED'
  echo 'OWASP_AUTHENTICATED_IDOR_CSRF_XSS=NOT_TESTED'
  echo 'OWASP_ACTIVE_PENETRATION_TEST=NOT_RUN'
  echo 'DEPENDENCY_CVE_SCAN=NOT_PERFORMED'
  echo 'SOFTWARE_LATEST_STATUS=NOT_CERTIFIED'
  echo 'SECURITY_CERTIFICATION=NOT_CLAIMED'
  echo 'NO_UPGRADES_OR_APPLICATION_CHANGES=YES'
  echo 'DAILY_AUDIT=COMPLETE'
}

if (( STDOUT_ONLY )); then
  check_baseline
else
  if [[ -z "$OUTPUT_DIR" ]]; then
    if [[ $EUID -eq 0 ]]; then
      OUTPUT_DIR='/var/lib/zmsf-audit'
    else
      OUTPUT_DIR="${HOME:-/tmp}/.local/state/zmsf-audit"
    fi
  fi
  if [[ -L "$OUTPUT_DIR" ]]; then
    echo 'ERROR=OUTPUT_DIRECTORY_SYMLINK' >&2; exit 2
  fi
  mkdir -p -m 700 -- "$OUTPUT_DIR"
  if [[ $(stat -c %a "$OUTPUT_DIR") != 700 ]]; then
    echo 'ERROR=OUTPUT_DIRECTORY_MUST_BE_0700' >&2; exit 2
  fi
  REPORT_DIR=$(mktemp -d "$OUTPUT_DIR/run-$(date -u +%Y%m%dT%H%M%SZ)-XXXXXX")
  chmod 700 "$REPORT_DIR"
  check_baseline > "$REPORT_DIR/summary.txt" 2>&1
  chmod 600 "$REPORT_DIR/summary.txt"
  cat "$REPORT_DIR/summary.txt"
  if have python3; then
    python3 - "$REPORT_DIR/summary.txt" "$REPORT_DIR/report.json" <<'PY'
import json
import sys
from pathlib import Path
lines=Path(sys.argv[1]).read_text(encoding='utf8', errors='replace').splitlines()
fields={}
for line in lines:
    if not line or line.startswith('=====') or '=' not in line: continue
    k,v=line.split('=',1)
    if k in ('APT_PACKAGE_UPDATABLE','DNF_PACKAGE_UPDATABLE','APP_REVIEW','TCP_LISTEN'):
        fields.setdefault(k,[]).append(v)
    else:
        fields[k]=v
Path(sys.argv[2]).write_text(json.dumps({'schema_version':1,'findings':fields},indent=2)+'\n',encoding='utf8')
PY
    chmod 600 "$REPORT_DIR/report.json"
  fi
  echo "REPORT_DIR=$REPORT_DIR"
fi

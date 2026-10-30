#!/usr/bin/env bash
# Starts a throwaway sshd on a high port, runs the handshake tool against it for
# each algorithm combination, and captures a replay trace for each.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
BUILD_DIR="${YANTERM_SSH_BUILD_DIR:-$ROOT/build/dev}"
TOOL="${YANTERM_SSH_INTEROP_TOOL:-$BUILD_DIR/yanterm-ssh-interop-handshake}"
AUTH_TOOL="${YANTERM_SSH_INTEROP_AUTH_TOOL:-$BUILD_DIR/yanterm-ssh-interop-auth}"
CORPUS_DIR="${YANTERM_SSH_CORPUS_DIR:-$ROOT/corpus}"
SSHD_BIN="${YANTERM_SSH_SSHD:-/usr/sbin/sshd}"
SEED="${YANTERM_SSH_INTEROP_SEED:-0x1234567890abcdef}"

if [[ ! -x "$TOOL" ]]; then
  echo "interop tool not found/executable: $TOOL" >&2
  exit 1
fi
if [[ ! -x "$SSHD_BIN" ]]; then
  echo "sshd not found: $SSHD_BIN; skipping" >&2
  exit 77
fi

# OpenSSH version string for corpus filenames (host may be 8.9p1, not 9.6).
OPENSSH_TAG=""
if command -v ssh >/dev/null 2>&1; then
  OPENSSH_TAG="$(ssh -V 2>&1 | sed -n 's/.*OpenSSH_\([0-9][^ ,]*\).*/\1/p' || true)"
fi
if [[ -z "$OPENSSH_TAG" ]]; then
  OPENSSH_TAG="$("$SSHD_BIN" -h 2>&1 | head -1 | sed -n 's/.*OpenSSH_\([0-9][^ ,]*\).*/\1/p' || true)"
fi
if [[ -z "$OPENSSH_TAG" ]]; then
  OPENSSH_TAG="8.9p1"
fi
# sanitize for filenames
OPENSSH_TAG="${OPENSSH_TAG//\//-}"

# PrivilegeSeparation needs /run/sshd on many distros; create if possible.
if [[ ! -d /run/sshd ]]; then
  mkdir -p /run/sshd 2>/dev/null || true
  chmod 755 /run/sshd 2>/dev/null || true
fi
if [[ ! -d /run/sshd ]]; then
  echo "WARN: /run/sshd missing; sshd may fail to start (need root to create)" >&2
fi

TMP="$(mktemp -d)"
AUTH_SERVER_PID=""
CHAN_SERVER_PID=""
ECHO_PID=""
cleanup() {
  if [[ -n "${CHAN_SERVER_PID:-}" ]]; then
    kill "$CHAN_SERVER_PID" 2>/dev/null || true
    wait "$CHAN_SERVER_PID" 2>/dev/null || true
  fi
  if [[ -n "${ECHO_PID:-}" ]]; then
    kill "$ECHO_PID" 2>/dev/null || true
    wait "$ECHO_PID" 2>/dev/null || true
  fi
  if [[ -n "${AUTH_SERVER_PID:-}" ]]; then
    kill "$AUTH_SERVER_PID" 2>/dev/null || true
    wait "$AUTH_SERVER_PID" 2>/dev/null || true
  fi
  if [[ -f "$TMP/sshd.pid" ]]; then
    kill "$(cat "$TMP/sshd.pid")" 2>/dev/null || true
    wait "$(cat "$TMP/sshd.pid")" 2>/dev/null || true
  fi
  # Best-effort kill by port if pidfile missing.
  if [[ -n "${PORT:-}" ]]; then
    if command -v fuser >/dev/null 2>&1; then
      fuser -k "${PORT}/tcp" 2>/dev/null || true
    fi
  fi
  if [[ -n "${PORT2:-}" ]]; then
    if command -v fuser >/dev/null 2>&1; then
      fuser -k "${PORT2}/tcp" 2>/dev/null || true
    fi
  fi
  rm -rf "$TMP"
}
trap cleanup EXIT

ssh-keygen -q -t ed25519 -N '' -f "$TMP/ssh_host_ed25519_key"
ssh-keygen -q -t ecdsa -b 256 -N '' -f "$TMP/ssh_host_ecdsa_key"
ssh-keygen -q -t rsa -b 2048 -N '' -f "$TMP/ssh_host_rsa_key"

# Pick a high ephemeral port.
PORT="$(python3 - <<'PY'
import socket
s = socket.socket()
s.bind(("127.0.0.1", 0))
print(s.getsockname()[1])
s.close()
PY
)"

mkdir -p "$CORPUS_DIR"

KEXES=(
  "curve25519-sha256"
  "ecdh-sha2-nistp256"
  "diffie-hellman-group14-sha256"
)
# The hybrid PQ KEX joins only when both OpenSSH (9.9+) and the yanterm backend
# (ML-KEM-768) offer it; an sshd that rejects the name would count as a failure.
PQ_KEX="mlkem768x25519-sha256"
PQ_KEX_OK=0
OPENSSH_KEXES="$(ssh -Q kex 2>/dev/null || true)"
YANTERM_KEXES="$("$TOOL" --list-kex 2>/dev/null | tr ',' '\n' || true)"
if ! grep -qx "$PQ_KEX" <<<"$OPENSSH_KEXES"; then
  echo "SKIP $PQ_KEX: OpenSSH $OPENSSH_TAG does not offer it" >&2
elif ! grep -qx "$PQ_KEX" <<<"$YANTERM_KEXES"; then
  echo "SKIP $PQ_KEX: yanterm backend has no ML-KEM-768" >&2
else
  KEXES+=("$PQ_KEX")
  PQ_KEX_OK=1
fi
CIPHERS=(
  "chacha20-poly1305@openssh.com"
  "aes256-gcm@openssh.com"
  "aes256-ctr"
)
HOSTKEYS=(
  "ssh-ed25519"
  "rsa-sha2-256"
  "ecdsa-sha2-nistp256"
)

hostkey_file() {
  case "$1" in
    ssh-ed25519) echo "$TMP/ssh_host_ed25519_key" ;;
    rsa-sha2-256) echo "$TMP/ssh_host_rsa_key" ;;
    ecdsa-sha2-nistp256) echo "$TMP/ssh_host_ecdsa_key" ;;
    *) return 1 ;;
  esac
}

trace_basename() {
  local kex="$1" cipher="$2" hostkey="$3"
  local k c h
  k="${kex%%@*}"
  k="${k//mlkem768x25519-sha256/mlkem768x25519}"
  k="${k//curve25519-sha256/curve25519}"
  k="${k//ecdh-sha2-nistp256/ecdh-nistp256}"
  k="${k//diffie-hellman-group14-sha256/dh-g14}"
  c="${cipher%%@*}"
  c="${c//chacha20-poly1305/chacha20}"
  c="${c//aes256-gcm/aes256-gcm}"
  c="${c//aes256-ctr/aes256-ctr}"
  h="$hostkey"
  h="${h//ssh-ed25519/ed25519}"
  h="${h//rsa-sha2-256/rsa-sha2-256}"
  h="${h//ecdsa-sha2-nistp256/ecdsa-p256}"
  echo "openssh-${OPENSSH_TAG}-${k}-${c}-${h}.ssh-trace"
}

start_sshd() {
  local kex="$1" cipher="$2" hostkey="$3"
  local hk
  hk="$(hostkey_file "$hostkey")"

  cat >"$TMP/sshd_config" <<EOF
Port ${PORT}
ListenAddress 127.0.0.1
HostKey ${hk}
PidFile ${TMP}/sshd.pid
StrictModes no
UsePAM no
PasswordAuthentication no
KbdInteractiveAuthentication no
ChallengeResponseAuthentication no
PubkeyAuthentication no
AuthenticationMethods none
PermitRootLogin yes
KexAlgorithms ${kex}
Ciphers ${cipher}
HostKeyAlgorithms ${hostkey}
PubkeyAcceptedAlgorithms ${hostkey}
MACs hmac-sha2-256-etm@openssh.com,hmac-sha2-256
LogLevel ERROR
EOF

  # OpenSSH may reject AuthenticationMethods none on some builds; fall back.
  if ! "$SSHD_BIN" -f "$TMP/sshd_config" -t 2>"$TMP/sshd-t.err"; then
    sed -i '/AuthenticationMethods/d' "$TMP/sshd_config"
  fi

  "$SSHD_BIN" -f "$TMP/sshd_config" -E "$TMP/sshd.log"
  # Wait for listen.
  for _ in $(seq 1 50); do
    if [[ -f "$TMP/sshd.pid" ]] && kill -0 "$(cat "$TMP/sshd.pid")" 2>/dev/null; then
      if bash -c "echo >/dev/tcp/127.0.0.1/${PORT}" 2>/dev/null; then
        return 0
      fi
    fi
    sleep 0.05
  done
  echo "sshd failed to start for $kex/$cipher/$hostkey" >&2
  cat "$TMP/sshd.log" >&2 || true
  cat "$TMP/sshd-t.err" >&2 || true
  return 1
}

stop_sshd() {
  if [[ -f "$TMP/sshd.pid" ]]; then
    local pid
    pid="$(cat "$TMP/sshd.pid" 2>/dev/null || true)"
    if [[ -n "${pid:-}" ]]; then
      kill "$pid" 2>/dev/null || true
      for _ in $(seq 1 50); do
        if ! kill -0 "$pid" 2>/dev/null; then
          rm -f "$TMP/sshd.pid"
          return 0
        fi
        sleep 0.05
      done
      kill -9 "$pid" 2>/dev/null || true
    fi
    rm -f "$TMP/sshd.pid"
  fi
}

REQUIRED_COMBOS=(
  "curve25519-sha256|chacha20-poly1305@openssh.com|ssh-ed25519"
  "ecdh-sha2-nistp256|aes256-gcm@openssh.com|rsa-sha2-256"
)

is_required() {
  local key="$1|$2|$3"
  local r
  for r in "${REQUIRED_COMBOS[@]}"; do
    [[ "$r" == "$key" ]] && return 0
  done
  return 1
}

FAILURES=0
RAN=0

run_one() {
  local kex="$1" cipher="$2" hostkey="$3"
  local mac_args=()
  if [[ "$cipher" == "aes256-ctr" ]]; then
    mac_args=(--mac hmac-sha2-256-etm@openssh.com)
  fi

  stop_sshd || true
  if ! start_sshd "$kex" "$cipher" "$hostkey"; then
    echo "SKIP start_sshd $kex $cipher $hostkey" >&2
    FAILURES=$((FAILURES + 1))
    return 0
  fi

  local trace=""
  if is_required "$kex" "$cipher" "$hostkey"; then
    trace="$CORPUS_DIR/$(trace_basename "$kex" "$cipher" "$hostkey")"
  else
    # Still exercise the matrix; write under TMP unless YANTERM_SSH_CORPUS_ALL=1.
    if [[ "${YANTERM_SSH_CORPUS_ALL:-0}" == "1" ]]; then
      trace="$CORPUS_DIR/$(trace_basename "$kex" "$cipher" "$hostkey")"
    else
      trace="$TMP/$(trace_basename "$kex" "$cipher" "$hostkey")"
    fi
  fi

  echo "==> $kex + $cipher + $hostkey (port $PORT)" >&2
  if ! "$TOOL" --host 127.0.0.1 --port "$PORT" --seed "$SEED" \
      --kex "$kex" --cipher "$cipher" --hostkey "$hostkey" \
      "${mac_args[@]}" \
      --trace "$trace"; then
    echo "FAIL handshake $kex $cipher $hostkey" >&2
    cat "$TMP/sshd.log" >&2 || true
    FAILURES=$((FAILURES + 1))
  else
    RAN=$((RAN + 1))
  fi
  stop_sshd || true
}

# Full matrix (KEXES x CIPHERS x HOSTKEYS). Required combos always write into corpus/.
for kex in "${KEXES[@]}"; do
  for cipher in "${CIPHERS[@]}"; do
    for hostkey in "${HOSTKEYS[@]}"; do
      run_one "$kex" "$cipher" "$hostkey"
    done
  done
done

# Terrapin scanner (optional).
if command -v Terrapin_Scanner >/dev/null 2>&1; then
  echo "==> Terrapin_Scanner" >&2
  stop_sshd || true
  start_sshd "curve25519-sha256" "chacha20-poly1305@openssh.com" "ssh-ed25519"
  # Scanner talks to the server; assert strict-kex somehow from its output.
  if Terrapin_Scanner -c "127.0.0.1:$PORT" 2>&1 | tee "$TMP/terrapin.out"; then
    if ! grep -Eqi 'strict.?kex.*(yes|enabled|true)|Supports strict kex.*yes' "$TMP/terrapin.out"; then
      echo "WARN: Terrapin_Scanner ran but strict-kex assertion not matched; see $TMP/terrapin.out" >&2
    fi
  fi
  stop_sshd || true
else
  echo "Terrapin_Scanner not found; skipping Terrapin check" >&2
fi

# ---- M3 auth interop (appended after the handshake matrix; do not edit the 3x3x3 loop) ----
pick_port() {
  python3 - <<'PY'
import socket
s = socket.socket()
s.bind(("127.0.0.1", 0))
print(s.getsockname()[1])
s.close()
PY
}

openssh_askpass_supported() {
  local ver maj min
  ver="$(ssh -V 2>&1 || true)"
  maj="$(printf '%s\n' "$ver" | sed -n 's/.*OpenSSH_\([0-9][0-9]*\)\.\([0-9][0-9]*\).*/\1/p')"
  min="$(printf '%s\n' "$ver" | sed -n 's/.*OpenSSH_\([0-9][0-9]*\)\.\([0-9][0-9]*\).*/\2/p')"
  if [[ -z "${maj:-}" || -z "${min:-}" ]]; then
    return 1
  fi
  if (( maj > 8 || (maj == 8 && min >= 4) )); then
    return 0
  fi
  return 1
}

wait_auth_listening() {
  local errfile="$1"
  local _
  for _ in $(seq 1 50); do
    if grep -q '^listening ' "$errfile" 2>/dev/null; then
      return 0
    fi
    sleep 0.05
  done
  echo "auth server did not print listening" >&2
  cat "$errfile" >&2 || true
  return 1
}

stop_auth_server() {
  if [[ -n "${AUTH_SERVER_PID:-}" ]]; then
    kill "$AUTH_SERVER_PID" 2>/dev/null || true
    wait "$AUTH_SERVER_PID" 2>/dev/null || true
    AUTH_SERVER_PID=""
  fi
}

start_sshd_pubkey() {
  cat >"$TMP/sshd_config" <<EOF
Port ${PORT}
ListenAddress 127.0.0.1
HostKey ${TMP}/ssh_host_ed25519_key
PidFile ${TMP}/sshd.pid
StrictModes no
UsePAM no
PasswordAuthentication no
KbdInteractiveAuthentication no
ChallengeResponseAuthentication no
PubkeyAuthentication yes
AuthorizedKeysFile ${TMP}/user.pub
AuthenticationMethods publickey
PermitRootLogin yes
PermitTTY yes
AllowTcpForwarding yes
KexAlgorithms curve25519-sha256
Ciphers chacha20-poly1305@openssh.com
HostKeyAlgorithms ssh-ed25519
PubkeyAcceptedAlgorithms ssh-ed25519
MACs hmac-sha2-256-etm@openssh.com,hmac-sha2-256
LogLevel ERROR
EOF

  if ! "$SSHD_BIN" -f "$TMP/sshd_config" -t 2>"$TMP/sshd-t.err"; then
    echo "sshd -t failed for pubkey interop" >&2
    cat "$TMP/sshd-t.err" >&2 || true
    return 1
  fi

  "$SSHD_BIN" -f "$TMP/sshd_config" -E "$TMP/sshd.log"
  for _ in $(seq 1 50); do
    if [[ -f "$TMP/sshd.pid" ]] && kill -0 "$(cat "$TMP/sshd.pid")" 2>/dev/null; then
      if bash -c "echo >/dev/tcp/127.0.0.1/${PORT}" 2>/dev/null; then
        return 0
      fi
    fi
    sleep 0.05
  done
  echo "sshd failed to start for pubkey interop" >&2
  cat "$TMP/sshd.log" >&2 || true
  cat "$TMP/sshd-t.err" >&2 || true
  return 1
}

judge_auth_server() {
  local label="$1"
  local errfile="$2"
  local rc=0
  local _
  for _ in $(seq 1 40); do
    if ! kill -0 "$AUTH_SERVER_PID" 2>/dev/null; then
      break
    fi
    sleep 0.05
  done
  if kill -0 "$AUTH_SERVER_PID" 2>/dev/null; then
    kill "$AUTH_SERVER_PID" 2>/dev/null || true
  fi
  wait "$AUTH_SERVER_PID" || rc=$?
  AUTH_SERVER_PID=""
  if [[ "$rc" -eq 0 ]] && grep -q '^auth_ok ' "$errfile"; then
    echo "ok $label ($(grep '^auth_ok ' "$errfile" | tail -1))" >&2
    RAN=$((RAN + 1))
    return 0
  fi
  echo "FAIL $label server_rc=$rc" >&2
  cat "$errfile" >&2 || true
  FAILURES=$((FAILURES + 1))
  return 0
}

run_ssh() {
  if command -v timeout >/dev/null 2>&1; then
    timeout 20 "$@" || true
  else
    "$@" || true
  fi
}

if [[ ! -x "$AUTH_TOOL" ]]; then
  echo "FAIL auth interop tool not found/executable: $AUTH_TOOL" >&2
  FAILURES=$((FAILURES + 1))
else
  USER="${USER:-$(id -un)}"
  ssh-keygen -q -t ed25519 -N '' -f "$TMP/user"
  ssh-keygen -q -t rsa -b 2048 -N '' -f "$TMP/user_rsa"
  PORT2="$(pick_port)"

  echo "==> yanterm client -> sshd publickey (port $PORT)" >&2
  stop_sshd || true
  if ! start_sshd_pubkey; then
    echo "FAIL start_sshd pubkey" >&2
    FAILURES=$((FAILURES + 1))
  elif ! "$AUTH_TOOL" --mode client --host 127.0.0.1 --port "$PORT" --user "$USER" \
      --identity "$TMP/user"; then
    echo "FAIL yanterm client -> sshd publickey" >&2
    cat "$TMP/sshd.log" >&2 || true
    FAILURES=$((FAILURES + 1))
  else
    RAN=$((RAN + 1))
  fi
  stop_sshd || true

  SSH_BIN="$(command -v ssh || true)"
  SSH_COMMON_OPTS=(
    -o StrictHostKeyChecking=no
    -o UserKnownHostsFile=/dev/null
    -o GlobalKnownHostsFile=/dev/null
    -o IdentitiesOnly=yes
    -o KexAlgorithms=curve25519-sha256
    -o Ciphers=chacha20-poly1305@openssh.com
    -o HostKeyAlgorithms=ssh-ed25519
    -o LogLevel=ERROR
    -T
  )

  if [[ -z "$SSH_BIN" ]]; then
    echo "FAIL ssh client not found (needed for ssh -> yanterm cases)" >&2
    FAILURES=$((FAILURES + 1))
  else
    echo "==> ssh -> yanterm server publickey (port $PORT2)" >&2
    stop_auth_server
    "$AUTH_TOOL" --mode server --listen "$PORT2" --host-key "$TMP/ssh_host_ed25519_key" \
      --user "$USER" --authorized "$TMP/user.pub" >"$TMP/auth-server.out" 2>"$TMP/auth-server.err" &
    AUTH_SERVER_PID=$!
    if wait_auth_listening "$TMP/auth-server.err"; then
      run_ssh "$SSH_BIN" "${SSH_COMMON_OPTS[@]}" -o PreferredAuthentications=publickey \
        -i "$TMP/user" -p "$PORT2" "$USER@127.0.0.1" true >/dev/null 2>"$TMP/ssh-pubkey.err"
      judge_auth_server "ssh -> yanterm publickey" "$TMP/auth-server.err"
    else
      stop_auth_server
      FAILURES=$((FAILURES + 1))
    fi

    echo "==> ssh -> yanterm server publickey (rsa user key + ed25519 host key, port $PORT2)" >&2
    stop_auth_server
    "$AUTH_TOOL" --mode server --listen "$PORT2" --host-key "$TMP/ssh_host_ed25519_key" \
      --user "$USER" --authorized "$TMP/user_rsa.pub" >"$TMP/auth-server.out" 2>"$TMP/auth-server.err" &
    AUTH_SERVER_PID=$!
    if wait_auth_listening "$TMP/auth-server.err"; then
      run_ssh "$SSH_BIN" "${SSH_COMMON_OPTS[@]}" -o PreferredAuthentications=publickey \
        -i "$TMP/user_rsa" -p "$PORT2" "$USER@127.0.0.1" true >/dev/null 2>"$TMP/ssh-pubkey-rsa.err"
      judge_auth_server "ssh -> yanterm publickey (rsa user key + ed25519 host key)" "$TMP/auth-server.err"
    else
      stop_auth_server
      FAILURES=$((FAILURES + 1))
    fi

    if [[ "$PQ_KEX_OK" -eq 1 ]]; then
      # ssh_config takes the first value of an option, so replace rather than append.
      SSH_PQ_OPTS=()
      for opt in "${SSH_COMMON_OPTS[@]}"; do
        if [[ "$opt" == "KexAlgorithms=curve25519-sha256" ]]; then
          opt="KexAlgorithms=$PQ_KEX"
        fi
        SSH_PQ_OPTS+=("$opt")
      done
      echo "==> ssh -> yanterm server publickey $PQ_KEX (port $PORT2)" >&2
      stop_auth_server
      "$AUTH_TOOL" --mode server --listen "$PORT2" --host-key "$TMP/ssh_host_ed25519_key" \
        --user "$USER" --authorized "$TMP/user.pub" --kex "$PQ_KEX" \
        >"$TMP/auth-server.out" 2>"$TMP/auth-server.err" &
      AUTH_SERVER_PID=$!
      if wait_auth_listening "$TMP/auth-server.err"; then
        run_ssh "$SSH_BIN" "${SSH_PQ_OPTS[@]}" -o PreferredAuthentications=publickey \
          -i "$TMP/user" -p "$PORT2" "$USER@127.0.0.1" true >/dev/null 2>"$TMP/ssh-pq.err"
        judge_auth_server "ssh -> yanterm publickey $PQ_KEX" "$TMP/auth-server.err"
      else
        stop_auth_server
        FAILURES=$((FAILURES + 1))
      fi
    fi

    cat >"$TMP/askpass" <<'EOF'
#!/bin/sh
echo testpass
EOF
    chmod +x "$TMP/askpass"

    if ! openssh_askpass_supported; then
      echo "SKIP ssh -> yanterm password: SSH_ASKPASS_REQUIRE unsupported (need OpenSSH 8.4+)" >&2
      echo "SKIP ssh -> yanterm kbdint: SSH_ASKPASS_REQUIRE unsupported (need OpenSSH 8.4+)" >&2
    else
      echo "==> ssh -> yanterm server password (port $PORT2)" >&2
      stop_auth_server
      "$AUTH_TOOL" --mode server --listen "$PORT2" --host-key "$TMP/ssh_host_ed25519_key" \
        --user "$USER" --authorized "$TMP/user.pub" --password testpass \
        >"$TMP/auth-server.out" 2>"$TMP/auth-server.err" &
      AUTH_SERVER_PID=$!
      if wait_auth_listening "$TMP/auth-server.err"; then
        DISPLAY=dummy SSH_ASKPASS="$TMP/askpass" SSH_ASKPASS_REQUIRE=force \
          run_ssh "$SSH_BIN" "${SSH_COMMON_OPTS[@]}" -o PreferredAuthentications=password \
          -o PubkeyAuthentication=no -o NumberOfPasswordPrompts=1 \
          -p "$PORT2" "$USER@127.0.0.1" true >/dev/null 2>"$TMP/ssh-password.err"
        judge_auth_server "ssh -> yanterm password" "$TMP/auth-server.err"
      else
        stop_auth_server
        FAILURES=$((FAILURES + 1))
      fi

      echo "==> ssh -> yanterm server kbdint (port $PORT2)" >&2
      stop_auth_server
      "$AUTH_TOOL" --mode server --listen "$PORT2" --host-key "$TMP/ssh_host_ed25519_key" \
        --user "$USER" --authorized "$TMP/user.pub" \
        --kbdint-prompt 'Password:' --kbdint-answer testpass \
        >"$TMP/auth-server.out" 2>"$TMP/auth-server.err" &
      AUTH_SERVER_PID=$!
      if wait_auth_listening "$TMP/auth-server.err"; then
        DISPLAY=dummy SSH_ASKPASS="$TMP/askpass" SSH_ASKPASS_REQUIRE=force \
          run_ssh "$SSH_BIN" "${SSH_COMMON_OPTS[@]}" -o PreferredAuthentications=keyboard-interactive \
          -o PubkeyAuthentication=no -o NumberOfPasswordPrompts=1 \
          -p "$PORT2" "$USER@127.0.0.1" true >/dev/null 2>"$TMP/ssh-kbdint.err"
        judge_auth_server "ssh -> yanterm kbdint" "$TMP/auth-server.err"
      else
        stop_auth_server
        FAILURES=$((FAILURES + 1))
      fi
    fi
  fi
fi

# ---- M4 channel interop (appended after M3 auth; do not edit handshake or auth) ----
CHAN_TOOL="${YANTERM_SSH_INTEROP_CHAN_TOOL:-$BUILD_DIR/yanterm-ssh-interop-channels}"

stop_chan_server() {
  if [[ -n "${CHAN_SERVER_PID:-}" ]]; then
    kill "$CHAN_SERVER_PID" 2>/dev/null || true
    wait "$CHAN_SERVER_PID" 2>/dev/null || true
    CHAN_SERVER_PID=""
  fi
}

judge_chan_server() {
  local label="$1"
  local errfile="$2"
  local rc=0
  local _
  for _ in $(seq 1 40); do
    if ! kill -0 "$CHAN_SERVER_PID" 2>/dev/null; then
      break
    fi
    sleep 0.05
  done
  if kill -0 "$CHAN_SERVER_PID" 2>/dev/null; then
    kill "$CHAN_SERVER_PID" 2>/dev/null || true
  fi
  wait "$CHAN_SERVER_PID" || rc=$?
  CHAN_SERVER_PID=""
  if [[ "$rc" -eq 0 ]] && grep -q '^channel_ok ' "$errfile"; then
    echo "ok $label ($(grep '^channel_ok ' "$errfile" | tail -1))" >&2
    RAN=$((RAN + 1))
    return 0
  fi
  echo "FAIL $label server_rc=$rc" >&2
  cat "$errfile" >&2 || true
  FAILURES=$((FAILURES + 1))
  return 0
}

if [[ ! -x "$CHAN_TOOL" ]]; then
  echo "FAIL channel interop tool not found/executable: $CHAN_TOOL" >&2
  FAILURES=$((FAILURES + 1))
else
  USER="${USER:-$(id -un)}"
  if [[ ! -f "$TMP/user" ]]; then
    ssh-keygen -q -t ed25519 -N '' -f "$TMP/user"
  fi
  if [[ -z "${PORT2:-}" ]]; then
    PORT2="$(pick_port)"
  fi
  SSH_BIN="$(command -v ssh || true)"
  SSH_COMMON_OPTS=(
    -o StrictHostKeyChecking=no
    -o UserKnownHostsFile=/dev/null
    -o GlobalKnownHostsFile=/dev/null
    -o IdentitiesOnly=yes
    -o KexAlgorithms=curve25519-sha256
    -o Ciphers=chacha20-poly1305@openssh.com
    -o HostKeyAlgorithms=ssh-ed25519
    -o LogLevel=ERROR
    -T
  )

  cat >"$TMP/echo.py" <<'PY'
import socket
s = socket.socket()
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(("127.0.0.1", 0))
s.listen(8)
print(s.getsockname()[1], flush=True)
while True:
    conn, _ = s.accept()
    data = b""
    while b"\n" not in data:
        chunk = conn.recv(4096)
        if not chunk:
            break
        data += chunk
    if b"PING" in data:
        conn.sendall(b"PONG\n")
    conn.close()
PY
  python3 "$TMP/echo.py" >"$TMP/echo.out" 2>"$TMP/echo.err" &
  ECHO_PID=$!
  ECHO_PORT=""
  for _ in $(seq 1 50); do
    if [[ -s "$TMP/echo.out" ]]; then
      ECHO_PORT="$(head -1 "$TMP/echo.out")"
      break
    fi
    sleep 0.05
  done
  if [[ -z "$ECHO_PORT" ]]; then
    echo "FAIL echo server did not print a port" >&2
    cat "$TMP/echo.err" >&2 || true
    FAILURES=$((FAILURES + 1))
  else
    echo "==> yanterm client -> sshd pty-shell (port $PORT)" >&2
    stop_sshd || true
    stop_auth_server
    if ! start_sshd_pubkey; then
      echo "FAIL start_sshd pubkey (channels)" >&2
      FAILURES=$((FAILURES + 1))
    elif ! "$CHAN_TOOL" --mode client --scenario pty-shell --host 127.0.0.1 --port "$PORT" \
        --user "$USER" --identity "$TMP/user"; then
      echo "FAIL yanterm client -> sshd pty-shell" >&2
      cat "$TMP/sshd.log" >&2 || true
      FAILURES=$((FAILURES + 1))
    else
      RAN=$((RAN + 1))
    fi

    echo "==> yanterm client -> sshd direct-tcpip (echo $ECHO_PORT)" >&2
    if [[ ! -f "$TMP/sshd.pid" ]]; then
      echo "FAIL sshd not running for direct-tcpip client" >&2
      FAILURES=$((FAILURES + 1))
    elif ! "$CHAN_TOOL" --mode client --scenario direct-tcpip --host 127.0.0.1 --port "$PORT" \
        --user "$USER" --identity "$TMP/user" \
        --forward-host 127.0.0.1 --forward-port "$ECHO_PORT"; then
      echo "FAIL yanterm client -> sshd direct-tcpip" >&2
      cat "$TMP/sshd.log" >&2 || true
      FAILURES=$((FAILURES + 1))
    else
      RAN=$((RAN + 1))
    fi
    stop_sshd || true

    if [[ -z "$SSH_BIN" ]]; then
      echo "FAIL ssh client not found (needed for ssh -> yanterm channel cases)" >&2
      FAILURES=$((FAILURES + 1))
    else
      echo "==> ssh -> yanterm server exec-true (port $PORT2)" >&2
      stop_chan_server
      "$CHAN_TOOL" --mode server --scenario exec-true --listen "$PORT2" \
        --host-key "$TMP/ssh_host_ed25519_key" --user "$USER" --authorized "$TMP/user.pub" \
        >"$TMP/chan-server.out" 2>"$TMP/chan-server.err" &
      CHAN_SERVER_PID=$!
      if wait_auth_listening "$TMP/chan-server.err"; then
        run_ssh "$SSH_BIN" "${SSH_COMMON_OPTS[@]}" -o PreferredAuthentications=publickey \
          -i "$TMP/user" -p "$PORT2" "$USER@127.0.0.1" true >/dev/null 2>"$TMP/ssh-exec.err"
        judge_chan_server "ssh -> yanterm exec-true" "$TMP/chan-server.err"
      else
        stop_chan_server
        FAILURES=$((FAILURES + 1))
      fi

      echo "==> ssh -> yanterm server direct-tcpip (port $PORT2, echo $ECHO_PORT)" >&2
      stop_chan_server
      "$CHAN_TOOL" --mode server --scenario direct-tcpip --listen "$PORT2" \
        --host-key "$TMP/ssh_host_ed25519_key" --user "$USER" --authorized "$TMP/user.pub" \
        >"$TMP/chan-server.out" 2>"$TMP/chan-server.err" &
      CHAN_SERVER_PID=$!
      if wait_auth_listening "$TMP/chan-server.err"; then
        # Keep the write end open until ssh has OPEN_CONFIRMATION; a closing
        # printf races and yields "read failed: Broken pipe" with no PING.
        python3 - "$SSH_BIN" "$ECHO_PORT" "$PORT2" "$TMP/user" "$USER" <<'PY' || true
import socket
import subprocess
import sys

ssh, echo_port, port, ident, user = sys.argv[1:]
cmd = [
    ssh,
    "-o", "StrictHostKeyChecking=no",
    "-o", "UserKnownHostsFile=/dev/null",
    "-o", "GlobalKnownHostsFile=/dev/null",
    "-o", "IdentitiesOnly=yes",
    "-o", "KexAlgorithms=curve25519-sha256",
    "-o", "Ciphers=chacha20-poly1305@openssh.com",
    "-o", "HostKeyAlgorithms=ssh-ed25519",
    "-o", "LogLevel=ERROR",
    "-T",
    "-W", f"127.0.0.1:{echo_port}",
    "-i", ident,
    "-p", port,
    f"{user}@127.0.0.1",
]
# Pipes break after OpenSSH pledge:network; a socketpair stays a network fd.
local, remote = socket.socketpair()
p = subprocess.Popen(cmd, stdin=remote, stdout=remote, stderr=subprocess.DEVNULL,
                     close_fds=True)
remote.close()
local.sendall(b"PING\n")
local.settimeout(10)
data = b""
try:
    while b"PONG" not in data:
        chunk = local.recv(64)
        if not chunk:
            break
        data += chunk
except (TimeoutError, socket.timeout):
    pass
local.close()
try:
    p.wait(timeout=5)
except subprocess.TimeoutExpired:
    p.kill()
    p.wait()
sys.exit(0 if b"PONG" in data else 1)
PY
        judge_chan_server "ssh -> yanterm direct-tcpip" "$TMP/chan-server.err"
      else
        stop_chan_server
        FAILURES=$((FAILURES + 1))
      fi
    fi
  fi
fi

echo "interop done: ran=$RAN failures=$FAILURES openssh=$OPENSSH_TAG" >&2
if [[ "$FAILURES" -ne 0 ]]; then
  exit 1
fi
if [[ "$RAN" -eq 0 ]]; then
  echo "no successful interop runs" >&2
  exit 1
fi
exit 0

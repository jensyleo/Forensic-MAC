#!/usr/bin/env bash
# =============================================================================
# Forensic-MAC — Forensic Extraction Tool for macOS Tahoe
# Copyright (C) 2026 jensyleo
# SPDX-License-Identifier: GPL-3.0-or-later
# Licensed under the GNU General Public License v3.0 or later. See LICENSE.
# =============================================================================
#
# DESCRIPTION
#   Terminal interface (logo, colors, single menu) for forensic collection / triage
#   on macOS: complete extraction without RAM; artifacts in RESULTS/<session>/evidence/ (TCC v1.29+; security/extensions v1.30+; browser_history v1.30+ copies+v1.31 browsers and optional CSV in export_sql/; extended network v1.31+); v1.32+ logs to stderr each SQLite copy / sqlite3 highlight (TCC, histories); menu [2] "with RAM" = stub
#   "FUTURE MODE" stub in menu [2] (complete_with_ram logic remains in code for a later version).
#   Integrity check at closure (header + shasum -a 256 per file, size and mtime stat, relative paths, stable order; optional OpenSSL signature of manifest via FORENSIC_OPENSSL_SIGN_KEY; no disk acquisition or osxpmem; no .tgz compression).
#   Compatibility target: recent macOS (latest versions; not obsolete systems).
#
# VERSION
#   Defined in VERSION variable (same line as main menu display).
#
# REQUIREMENTS
#   - macOS Tahoe (v26) or later
#   - bash 3.2+ (macOS default)
#   - Terminal with ANSI support (24-bit truecolor RGB palette)
#   - Must always run as root: «sudo ./Forensic-MAC.sh». To preserve environment variables (e.g. FORENSIC_OPENSSL_SIGN_KEY), use «sudo -E».
#     macOS only prompts for a password on initial sudo; the script only uses `sudo -u <user>` internally
#     (per-user login-items check), which doesn't prompt again since the process already runs as root.
#
# EXECUTION (always with sudo)
#   From repo root or with absolute path:
#     sudo bash ./Forensic-MAC.sh
#   As executable:
#     chmod +x ./Forensic-MAC.sh && sudo ./Forensic-MAC.sh
#
# MENU FLOW (summary)
#   main → forensic_require_root_at_start (uid 0; if not, message and exit)
#   main (loop)
#     ├─ [1] Without RAM → complete 100% (no vm_stat/sysctl)
#     ├─ [2] With RAM → "FUTURE MODE" message (no collection)
#     └─ [Q] Exit
#
# BASH OPTIONS (set)
#   -e  : exit if any command fails (careful with pipes; use || true if needed)
#   -u  : error if undefined variable is used
#   -o pipefail : pipeline fails if any stage fails
#
# CODE ARCHITECTURE
#   Color constants     → RGB_* / ANSI_* / RESET_COLOR lines
#   get_terminal_width  → terminal columns (tput or 80)
#   clear_screen        → clear or reset sequence
#   _print_logo         → ASCII art centered with dynamic margin
#   repeat_char         → repeat UTF-8 character without `tr` (avoids corruption)
#   pad_center          → center text in N columns (frame titles)
#   _print_menu         → menu box (no RAM / with RAM / exit)
#   main                → main loop and case for options
#   forensic_require_root_at_start → demand sudo execution (uid 0)
#   SCRIPT_DIR          → absolute directory of this script
#   FORENSIC_SESSION_METADATA_FILE → 00_METADATA.txt at session root (prefix 00_ + uppercase)
#   FORENSIC_INTEGRITY_CHECK_FILE → 01_INTEGRITY_CHECK.txt (+ .sig optional if FORENSIC_OPENSSL_SIGN_KEY)
#   forensic_* (RESULTS)  → RESULTS/,
#                           subfolder tag_DD-MM-YYYY_HH:MM, max. 3 sessions;
#                           forensic_ensure_directory creates paths with mkdir -p if they don't exist;
#                           forensic_acquisition_tcc (v1.29+) → evidence/TCC/; forensic_acquisition_browser_history (v1.30+) → evidence/browser_history/
#
# UTF-8 / BOX CHARACTERS
#   Borders use Unicode characters (╔ ═ ║ ╣ ╝). Don't use `tr` to duplicate
#   «═» because in some environments it breaks UTF-8 sequences. repeat_char concatenates
#   in a for loop.
#
# EXTENSION
#   - Add rows to forensic_extraction_complete_without_ram / forensic_extraction_volatile_ram_native with forensic_cmd_to_file / forensic_rsync_log.
#   - TCC / histories: forensic_acquisition_* + forensic_sqlite_* (metadata; optional CSV if FORENSIC_BROWSER_HISTORY_EXPORT_TABLES=1).
#   - Software per user: forensic_software_ls_users_applications (don't rely on «~/Applications» with sudo).
#   - Login items: …; browser paths: forensic_ls_browser_paths_preview (ls only); then forensic_acquisition_browser_history (sqlite copies + sqlite3 metadata on copies).
#   forensic_report_step + messages inside forensic_cmd_to_file / forensic_rsync_log / SQLite and copies (TCC, histories) → console activity (stderr), no progress %%.
#   - Integrate osxpmem or other external tools only if desired (not native Apple).
#
# =============================================================================
set -euo pipefail

VERSION="1.34-Tahoe"

# Absolute directory of this script. RESULTS/ is created here.
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]:-$0}")" && pwd)"

# Architecture detection (Apple Silicon vs Intel)
FORENSIC_ARCH="$(uname -m 2>/dev/null)" || FORENSIC_ARCH="unknown"

# Current session: path to RESULTS/<session_folder>/ (set by forensic_create_output_directory).
FORENSIC_SESSION_DIR=""

# Session metadata file (session root). Prefix 00_ to list first; uppercase name.
FORENSIC_SESSION_METADATA_FILE="00_METADATA.txt"

# Integrity check list (SHA-256 + bytes + mtime epoch + relative path to session, lexicographic order); prefix 01_ (after 00_METADATA). Excludes itself when generating.
FORENSIC_INTEGRITY_CHECK_FILE="01_INTEGRITY_CHECK.txt"

# Optional manifest signature with openssl (native macOS): export FORENSIC_OPENSSL_SIGN_KEY=/path/private_key.pem (RSA or EC PEM). Always start with sudo; use sudo -E to preserve the variable.

# -----------------------------------------------------------------------------
# Locale: best-effort UTF-8 (avoids box characters appearing as garbage in some IDEs)
# -----------------------------------------------------------------------------
export LANG="${LANG:-C.UTF-8}"
export LC_ALL="${LC_ALL:-C.UTF-8}"

# -----------------------------------------------------------------------------
# ANSI Palette (24-bit truecolor). Intended use:
#   RGB_GREEN / box frame and borders
#   RGB_BLUE  / titles, prompts [?], conceptual separators with icons
#   RGB_YELLOW / keys [1] [2] [Q]
#   RGB_RED   / invalid option errors
#   RGB_ORANGE / reserved for warnings in future forensic logic
#   RGB_SUCCESS / same green as GREEN; success messages or positive emphasis
#   RGB_ASCII_GREEN / logo strokes (===)
#   ANSI_WHITE / neutral readable text
#   RESET_COLOR / end attributes (always close before final newline if mixed)
# -----------------------------------------------------------------------------
RGB_GREEN=$'\033[38;2;69;168;36m'
RGB_SUCCESS=$'\033[38;2;69;168;36m'
RGB_BLUE=$'\033[38;2;0;183;211m'
RGB_YELLOW=$'\033[38;2;227;221;22m'
RGB_RED=$'\033[38;2;245;51;51m'
RGB_ORANGE=$'\033[38;2;249;146;7m'
RGB_ASCII_GREEN=$'\033[38;2;158;204;20m'
ANSI_WHITE=$'\033[97m'
RESET_COLOR=$'\033[0m'

# -----------------------------------------------------------------------------
# Privileges: the script must always be launched with «sudo» once (mandatory).
# This way the whole process runs as root and extraction commands don't repeat sudo. Optional «sudo -E» if you need to preserve the environment (e.g. OpenSSL signature).
# -----------------------------------------------------------------------------
forensic_require_root_at_start() {
  local uid script_path
  uid="$(id -u)"
  if [[ "$uid" -eq 0 ]]; then
    return 0
  fi
  script_path="${BASH_SOURCE[0]:-$0}"
  printf '\n%s[!] %sThis script must be run with administrator privileges.%s\n' "${RGB_RED}" "${ANSI_WHITE}" "${RESET_COLOR}" >&2
  printf '%s    %sStart the process with sudo (macOS will only ask for the password at startup).%s\n' "${ANSI_WHITE}" "${ANSI_WHITE}" "${RESET_COLOR}" >&2
  printf '%s    %sExample:%s\n' "${ANSI_WHITE}" "${ANSI_WHITE}" "${RESET_COLOR}" >&2
  printf '%s        sudo bash %q%s\n' "${RGB_GREEN}" "${script_path}" "${RESET_COLOR}" >&2
  printf '%s    %sOr from the script folder:%s\n' "${ANSI_WHITE}" "${ANSI_WHITE}" "${RESET_COLOR}" >&2
  printf '%s        cd %q && sudo ./Forensic-MAC.sh%s\n' "${RGB_GREEN}" "${SCRIPT_DIR}" "${RESET_COLOR}" >&2
  printf '%s    %sIf you need environment variables (e.g. FORENSIC_OPENSSL_SIGN_KEY), use: sudo -E …%s\n' "${ANSI_WHITE}" "${ANSI_WHITE}" "${RESET_COLOR}" >&2
  exit 1
}

# -----------------------------------------------------------------------------
# Output in RESULTS/
# - Base folder: <SCRIPT_DIR>/RESULTS
# - Session: safe_filename(host_mode)_DD-MM-YYYY_HH:MM
# - After creating a session, older folders are removed if there are more than 3.
# -----------------------------------------------------------------------------

# Safe name for path segments (strips anything that isn't filesystem-safe).
forensic_safe_filename() {
  local s="${1:-out}"
  s="$(printf '%s' "$s" | LC_ALL=C sed 's/[^A-Za-z0-9._-]/_/g')"
  s="$(printf '%s' "$s" | LC_ALL=C sed 's/^[._-]*//;s/[._-]*$//')"
  [[ -n "$s" ]] || s="out"
  printf '%s' "$s"
}

# Human-readable host label: the machine's visible macOS name.
forensic_host_label() {
  local n=""
  n="$(scutil --get ComputerName 2>/dev/null || true)"
  if [[ -z "${n// /}" ]]; then
    n="$(hostname -s 2>/dev/null || true)"
  fi
  if [[ -z "${n// /}" ]]; then
    n="$(hostname 2>/dev/null || true)"
  fi
  if [[ -z "${n// /}" ]]; then
    n="forensic"
  fi
  printf '%s' "$n"
}

# Creates $1 with mkdir -p if needed and checks it's a directory (doesn't hide failures).
forensic_ensure_directory() {
  local path="${1:?}"
  local description="${2:-Folder}"
  if [[ -d "$path" ]]; then
    return 0
  fi
  if mkdir -p "$path"; then
    :
  else
    printf '%s[!] %sCould not create %s: %s%s\n' "${RGB_RED}" "${ANSI_WHITE}" "$description" "$path" "${RESET_COLOR}" >&2
    return 1
  fi
  if [[ ! -d "$path" ]]; then
    printf '%s[!] %sInvalid path or not a folder: %s%s\n' "${RGB_RED}" "${ANSI_WHITE}" "$path" "${RESET_COLOR}" >&2
    return 1
  fi
  return 0
}

# Keeps only the $max_keep most recent folders (by mtime) in RESULTS/.
forensic_cleanup_old_results() {
  local base_dir="${1:?}"
  local max_keep="${2:-3}"
  local tmp item mt path i count_deleted
  [[ -d "$base_dir" ]] || return 0
  tmp="$(mktemp -t forensic_results.XXXXXX 2>/dev/null || mktemp)" || return 0
  count_deleted=0
  {
    shopt -s nullglob 2>/dev/null || true
    for item in "$base_dir"/*; do
      [[ -d "$item" ]] || continue
      mt="$(stat -f %m "$item" 2>/dev/null)" || mt=0
      printf '%s\t%s\n' "$mt" "$item"
    done
    shopt -u nullglob 2>/dev/null || true
  } | sort -t $'\t' -nr -k1,1 > "$tmp"
  i=0
  while IFS=$'\t' read -r mt path; do
    [[ -n "${path:-}" ]] || continue
    [[ -d "$path" ]] || continue
    i=$((i + 1))
    if (( i > max_keep )); then
      rm -rf "$path" 2>/dev/null || true
      printf '%s[+] %sRemoved old folder: %s%s\n' "${RGB_YELLOW}" "${ANSI_WHITE}" "$(basename "$path")" "${RESET_COLOR}"
      count_deleted=$((count_deleted + 1))
    fi
  done < "$tmp"
  rm -f "$tmp"
  if (( count_deleted > 0 )); then
    printf '%s[+] %sKeeping a maximum of %s folders in RESULTS/%s\n' "${RGB_GREEN}" "${ANSI_WHITE}" "${max_keep}" "${RESET_COLOR}"
  fi
}

# Creates RESULTS/<tag_date_time>/ and assigns FORENSIC_SESSION_DIR.
# $1 optional: mode suffix (e.g. Complete_With_RAM) — concatenated to the host before safe_filename.
forensic_create_output_directory() {
  local extra_label="${1:-}"
  local host tag date_str time_str base_dir folder_name
  host="$(forensic_host_label)"
  if [[ -n "$extra_label" ]]; then
    tag="$(forensic_safe_filename "${host}_${extra_label}")"
  else
    tag="$(forensic_safe_filename "${host}")"
  fi
  date_str="$(date +"%d-%m-%Y")"
  time_str="$(date +"%H:%M")"
  base_dir="${SCRIPT_DIR}/RESULTS"
  if ! forensic_ensure_directory "$base_dir" "RESULTS"; then
    FORENSIC_SESSION_DIR=""
    return 1
  fi
  folder_name="${tag}_${date_str}_${time_str}"
  FORENSIC_SESSION_DIR="${base_dir}/${folder_name}"
  if ! forensic_ensure_directory "$FORENSIC_SESSION_DIR" "session folder"; then
    FORENSIC_SESSION_DIR=""
    return 1
  fi
  forensic_report_step "Applying retention policy in RESULTS/ (keep up to 3 recent sessions; rm if exceeded)"
  forensic_cleanup_old_results "$base_dir" 3
  return 0
}

# Writes UTF-8 text in the current session ($1 = relative file name).
# If the session folder doesn't exist (e.g. deleted manually), tries to create it again.
forensic_write_text() {
  local name="$1"
  local content="${2-}"
  local file_dir
  [[ -n "${FORENSIC_SESSION_DIR:-}" ]] || return 1
  [[ -n "$name" ]] || return 1
  file_dir="$(dirname "${FORENSIC_SESSION_DIR}/${name}")"
  if ! forensic_ensure_directory "$file_dir" "output directory"; then
    return 1
  fi
  printf '%s' "${content}" > "${FORENSIC_SESSION_DIR}/${name}" || return 1
}

# Informational console message (stderr): what's being done; no progress percentage.
forensic_report_step() {
  printf '%s[·] %s%s%s\n' "${RGB_BLUE}" "${ANSI_WHITE}" "$*" "${RESET_COLOR}" >&2
}

# Runs a native command and dumps stdout/stderr into a .txt (one file per execution).
# Usage: forensic_cmd_to_file "path/name.txt" command [args...]
forensic_cmd_to_file() {
  local rel="${1:?}"
  shift
  [[ -n "${FORENSIC_SESSION_DIR:-}" ]] || return 1
  local log="${FORENSIC_SESSION_DIR}/${rel}"
  {
    printf '%s[·] %sRunning:' "${RGB_BLUE}" "${ANSI_WHITE}" >&2
    local _a
    # %s with an argument starting with '-' (e.g. uname -a) must not go as "printf ' %s'":
    # on macOS /usr/bin/printf treats it as an option; concatenated with safe format instead.
    for _a in "$@"; do printf '%s' " ${_a}" >&2; done
    printf '%s → %s%s\n' "${ANSI_WHITE}" "${rel}" "${RESET_COLOR}" >&2
  }
  if ! forensic_ensure_directory "$(dirname "$log")" "output"; then
    return 1
  fi
  {
    # Don't use printf '--- …' : on macOS the format can't start with '-' (confused with options).
    printf '%s\n' "--- Forensic-MAC.sh | $(date) ---"
    local _header="--- Command:"
    local a
    for a in "$@"; do _header+=" ${a}"; done
    _header+=" ---"
    printf '%s\n\n' "${_header}"
  } > "$log"
  if "$@" >>"$log" 2>&1; then
    printf '\n--- exit code: 0 ---\n' >>"$log"
  else
    printf '\n--- exit code: %s ---\n' "$?" >>"$log"
  fi
}

# Listing of ~/Applications for each account in /Users/* and /var/root (don't use just «~» with sudo: it would be root).
forensic_software_ls_users_applications() {
  local rel="${1:?}"
  local log="${FORENSIC_SESSION_DIR}/${rel}"
  [[ -n "${FORENSIC_SESSION_DIR:-}" ]] || return 1
  forensic_report_step "Listing /Applications for each user (ls) → ${rel}"
  if ! forensic_ensure_directory "$(dirname "$log")" "output"; then
    return 1
  fi
  {
    printf '%s\n' "--- Forensic-MAC.sh | $(date) ---"
    printf '%s\n\n' "--- Command: ls -la (equivalent to ~/Applications per user; see README) ---"
    local d
    shopt -s nullglob 2>/dev/null || true
    for d in /Users/*; do
      [[ -d "$d" ]] || continue
      if [[ -d "$d/Applications" ]]; then
        forensic_report_step "Running: ls -la ${d}/Applications → ${rel}"
        printf '\n=== %s/Applications ===\n' "$d"
        ls -la "$d/Applications" 2>&1 || true
      else
        printf '\n=== %s/Applications (does not exist) ===\n' "$d"
      fi
    done
    shopt -u nullglob 2>/dev/null || true
    forensic_report_step "Running: ls -la /var/root/Applications → ${rel}"
    printf '\n=== /var/root/Applications ===\n'
    ls -la /var/root/Applications 2>&1 || true
    printf '\n--- exit code: 0 ---\n'
  } >"$log"
  return 0
}

# Listing of ~/Library/LaunchAgents for each /Users/* and /var/root (forensic equivalent to «ls ~/Library/LaunchAgents» with sudo).
forensic_persistence_ls_users_library_launchagents() {
  local rel="${1:?}"
  local log="${FORENSIC_SESSION_DIR}/${rel}"
  [[ -n "${FORENSIC_SESSION_DIR:-}" ]] || return 1
  forensic_report_step "Listing ~/Library/LaunchAgents per user (ls) → ${rel}"
  if ! forensic_ensure_directory "$(dirname "$log")" "output"; then
    return 1
  fi
  {
    printf '%s\n' "--- Forensic-MAC.sh | $(date) ---"
    printf '%s\n\n' "--- Command: ls -la (~/Library/LaunchAgents per user; see README) ---"
    local d
    shopt -s nullglob 2>/dev/null || true
    for d in /Users/*; do
      [[ -d "$d" ]] || continue
      if [[ -d "$d/Library/LaunchAgents" ]]; then
        forensic_report_step "Running: ls -la ${d}/Library/LaunchAgents → ${rel}"
        printf '\n=== %s/Library/LaunchAgents ===\n' "$d"
        ls -la "$d/Library/LaunchAgents" 2>&1 || true
      else
        printf '\n=== %s/Library/LaunchAgents (does not exist) ===\n' "$d"
      fi
    done
    shopt -u nullglob 2>/dev/null || true
    forensic_report_step "Running: ls -la /var/root/Library/LaunchAgents → ${rel}"
    printf '\n=== /var/root/Library/LaunchAgents ===\n'
    ls -la /var/root/Library/LaunchAgents 2>&1 || true
    printf '\n--- exit code: 0 ---\n'
  } >"$log"
  return 0
}

# Login Items via System Events (osascript), attempted once per local user in /Users/* (TCC / graphical session: see README).
forensic_loginitems_osascript_per_user() {
  local rel="${1:?}"
  local log="${FORENSIC_SESSION_DIR}/${rel}"
  [[ -n "${FORENSIC_SESSION_DIR:-}" ]] || return 1
  forensic_report_step "Login items via osascript (System Events; may fail due to TCC) → ${rel}"
  if ! forensic_ensure_directory "$(dirname "$log")" "output"; then
    return 1
  fi
  {
    printf '%s\n' "--- Forensic-MAC.sh | $(date) ---"
    printf '%s\n\n' "--- Command: osascript System Events → login items (per user; may fail due to TCC or no GUI) ---"
    local d u
    shopt -s nullglob 2>/dev/null || true
    for d in /Users/*; do
      [[ -d "$d" ]] || continue
      u="$(basename "$d")"
      [[ "$u" == "Shared" ]] && continue
      forensic_report_step "Running: sudo -u «${u}» osascript (login items) → ${rel}"
      printf '\n=== user «%s» (sudo -u … osascript) ===\n' "$u"
      sudo -u "$u" osascript -e 'tell application "System Events" to get the name of every login item' 2>&1 || true
    done
    shopt -u nullglob 2>/dev/null || true
    forensic_report_step "Running: osascript login items (current root process reference) → ${rel}"
    printf '\n=== current root process (osascript without -u; reference) ===\n'
    osascript -e 'tell application "System Events" to get the name of every login item' 2>&1 || true
    printf '\n--- exit code: 0 ---\n'
  } >"$log"
  return 0
}

# Typical Safari / Chrome / Firefox / Edge / Brave paths: only ls -la if they exist. SQLite history copies go to evidence/browser_history/ (next phase).
forensic_ls_browser_paths_preview() {
  local rel="${1:?}"
  local log="${FORENSIC_SESSION_DIR}/${rel}"
  [[ -n "${FORENSIC_SESSION_DIR:-}" ]] || return 1
  forensic_report_step "Listings of typical browser paths (ls only) → ${rel}"
  if ! forensic_ensure_directory "$(dirname "$log")" "output"; then
    return 1
  fi
  {
    printf '%s\n' "--- Forensic-MAC.sh | $(date) ---"
    printf '%s\n\n' "--- ls -la on typical ~/Library/… paths (Safari, Chrome, Firefox, Edge, Brave); SQLite history copies → evidence/browser_history/ phase ---"
    local d u path
    shopt -s nullglob 2>/dev/null || true
    for d in /Users/*; do
      [[ -d "$d" ]] || continue
      u="$(basename "$d")"
      [[ "$u" == "Shared" ]] && continue
      forensic_report_step "Running: ls browser paths (user ${u}) → ${rel}"
      printf '\n######## user %s ########\n' "$u"
      for path in "${d}/Library/Safari" "${d}/Library/Application Support/Google/Chrome" \
        "${d}/Library/Application Support/Firefox" "${d}/Library/Application Support/Microsoft Edge" \
        "${d}/Library/Application Support/BraveSoftware/Brave-Browser" \
        "${d}/Library/Application Support/com.operasoftware.Opera" "${d}/Library/Application Support/com.operasoftware.OperaGX" \
        "${d}/Library/Application Support/Yandex/YandexBrowser" "${d}/Library/Application Support/Chromium" \
        "${d}/Library/Containers/com.apple.Safari/Data/Library/Safari"; do
        [[ -e "$path" ]] || continue
        forensic_report_step "ls -la ${path}"
        printf '\n--- %s ---\n' "$path"
        ls -la "$path" 2>&1 || printf '(ls failed)\n'
      done
    done
    shopt -u nullglob 2>/dev/null || true
    printf '\n=== /var/root (reference) ===\n'
    for path in /var/root/Library/Safari "/var/root/Library/Application Support/Google/Chrome"; do
      [[ -e "$path" ]] || continue
      forensic_report_step "ls -la ${path} (/var/root)"
      printf '\n--- %s ---\n' "$path"
      ls -la "$path" 2>&1 || true
    done
    printf '\n--- exit code: 0 ---\n'
  } >"$log"
  return 0
}

# Locally copies any SQLite: sqlite3 dumps (.schema, integrity_check, page_count). Doesn't touch the source beyond whoever called it (e.g. previous cp).
forensic_sqlite_dump_metadata() {
  local copy="${1:?}" meta_dir="${2:?}" prefix="${3:?}"
  [[ -f "${copy}" ]] || return 0
  if ! command -v sqlite3 >/dev/null 2>&1; then
    forensic_report_step "Skipping sqlite3 (metadata) «${prefix}»: sqlite3 not in PATH."
    return 0
  fi
  forensic_report_step "Running: sqlite3 (metadata) «${prefix}» (.schema / integrity_check / page_count)."
  set +e
  sqlite3 "${copy}" ".schema" >"${meta_dir}/${prefix}.schema.txt" 2>&1
  sqlite3 "${copy}" "PRAGMA integrity_check;" >"${meta_dir}/${prefix}.integrity_check.txt" 2>&1
  sqlite3 "${copy}" "PRAGMA page_count;" >"${meta_dir}/${prefix}.pragma_page_count.txt" 2>&1
  set -e
  return 0
}

# FORENSIC_BROWSER_HISTORY_EXPORT_TABLES=1: shows a CSV sample (URLs) from THE COPY; limit FORENSIC_BROWSER_HISTORY_SQL_LIMIT (default 8000).
forensic_sqlite_history_export_csv() {
  local db="${1:?}" hist_root="${2:?}" pfx="${3:?}" kind="${4:?}"
  local outdir="${hist_root}/export_sql" lim out err
  [[ "${FORENSIC_BROWSER_HISTORY_EXPORT_TABLES:-}" == "1" ]] || return 0
  [[ -f "${db}" ]] || return 0
  command -v sqlite3 >/dev/null 2>&1 || {
    forensic_report_step "Skipping sqlite3 (CSV) «${pfx}»: sqlite3 not in PATH."
    return 0
  }
  lim="$(printf '%s' "${FORENSIC_BROWSER_HISTORY_SQL_LIMIT:-8000}")"
  [[ "${lim}" =~ ^[0-9]+$ ]] || lim="8000"
  [[ "${lim}" -gt 0 ]] || lim="8000"
  forensic_report_step "Running: sqlite3 (CSV ${kind}) tabular sample «${pfx}» (max. ${lim} rows) → export_sql/"
  forensic_ensure_directory "${outdir}" "export_sql browser history" || return 0
  out="${outdir}/${pfx}"
  case "${kind}" in
    chromium )
      sqlite3 -header -csv "${db}" "SELECT url, title, visit_count FROM urls LIMIT ${lim};" >"${out}_urls.csv" 2>"${out}_urls.stderr.txt"
      ;;
    firefox )
      sqlite3 -header -csv "${db}" "SELECT url, title FROM moz_places LIMIT ${lim};" >"${out}_moz_places.csv" 2>"${out}_moz_places.stderr.txt"
      ;;
    safari )
      if sqlite3 "${db}" "SELECT 1 FROM history_items LIMIT 1;" >/dev/null 2>&1; then
        sqlite3 -header -csv "${db}" "SELECT url FROM history_items ORDER BY rowid DESC LIMIT ${lim};" >"${out}_history_items.csv" 2>"${out}_history_items.stderr.txt"
      else
        printf '%s\n' "Safari tabular export skipped: no valid history_items table in this copy." >"${out}_history_items.ERR.txt"
      fi
      ;;
    * ) return 0 ;;
  esac
  return 0
}

forensic_history_post_copy_sqlite() {
  local copy="${1:?}" meta_dir="${2:?}" prefix="${3:?}" kind_hist="${4:?}" hist_root="${5:?}"
  forensic_sqlite_dump_metadata "${copy}" "${meta_dir}" "${prefix}"
  forensic_sqlite_history_export_csv "${copy}" "${hist_root}" "${prefix}" "${kind_hist}"
}

# TCC (SQLite): evidence/TCC/ with copies, chain-of-custody documentation, sqlite_metadata/ on COPIES. SIP may block /Library/… .
forensic_acquisition_tcc() {
  local base doc meta system_src orig dest readme u su d
  [[ -n "${FORENSIC_SESSION_DIR:-}" ]] || return 0
  set +e
  base="${FORENSIC_SESSION_DIR}/evidence/TCC"
  doc="${base}/documentation"
  meta="${base}/sqlite_metadata"
  system_src="/Library/Application Support/com.apple.TCC/TCC.db"

  forensic_report_step "Acquiring TCC databases (SQLite, read-only / copies) → evidence/TCC/"
  forensic_ensure_directory "${doc}" "TCC" || {
    set -e
    return 0
  }
  forensic_ensure_directory "${meta}" "TCC sqlite_metadata" || {
    set -e
    return 0
  }

  forensic_report_step "Running: sqlite3 --version → evidence/TCC/documentation/sqlite3_version.txt"
  sqlite3 --version >"${doc}/sqlite3_version.txt" 2>/dev/null || printf 'sqlite3 not available\n' >"${doc}/sqlite3_version.txt"

  readme="$(cat <<'EOF'
================================================================================
Forensic-MAC.sh — evidence/TCC/ (Transparency, Consent, and Control)
================================================================================

Contents (v1.29+)
--------------------------------
• documentation/     README, sqlite3 version, linear log of every copy attempt (copy_log.txt).
• source_system/     Copy of /Library/Application Support/com.apple.TCC/TCC.db (if it exists and is copyable).
• source_user_*/     Copies from ~/Library/Application Support/com.apple.TCC/TCC.db per account.
• source_var_root/   Copy from /var/root/Library/… if it exists.
• sqlite_metadata/   Dumps from THE COPIES (.schema, PRAGMA integrity_check, PRAGMA page_count).

Evidentiary value
----------------
Supports reproducibility and integrity when cross-referenced with 00_METADATA.txt and the 01_INTEGRITY_CHECK.txt manifest (+ .sig) generated at CLOSE over the whole session (includes this folder if the phase ran before the manifest).

Limitations / operations
-------------------------
• Internal records and policies remain outside the script.
• SIP, permissions, or locks may prevent the system source — see copy_log.txt.
• The SQL schema may differ between macOS versions.
EOF
)"
  forensic_report_step "Writing text: evidence/TCC/documentation/README_PROCEDURE.txt"
  forensic_write_text "evidence/TCC/documentation/README_PROCEDURE.txt" "${readme}" || true

  forensic_report_step "Initializing linear TCC copy log → evidence/TCC/documentation/copy_log.txt"
  {
    printf '%s\n' "--- TCC.db copy attempts log — Forensic-MAC.sh | $(date) ---"
  } >"${doc}/copy_log.txt"

  dest="${base}/source_system"
  forensic_ensure_directory "${dest}" "TCC system" || true
  if [[ -f "${system_src}" ]]; then
    forensic_report_step "Running: cp -p (system TCC.db) → evidence/TCC/source_system/TCC.db"
    if cp -p "${system_src}" "${dest}/TCC.db" 2>/dev/null; then
      printf '%s\n' "OK system: cp -> ${dest}/TCC.db" >>"${doc}/copy_log.txt"
      forensic_sqlite_dump_metadata "${dest}/TCC.db" "${meta}" "source_system"
    else
      printf '%s\n' "FAILED system (cp exit code $?): ${system_src}" >>"${doc}/copy_log.txt"
    fi
  else
    printf '%s\n' "SKIPPED (does not exist or not visible): ${system_src}" >>"${doc}/copy_log.txt"
  fi

  shopt -s nullglob 2>/dev/null || true
  for d in /Users/*; do
    [[ -d "${d}" ]] || continue
    u="$(basename "${d}")"
    [[ "${u}" == "Shared" ]] && continue
    su="$(forensic_safe_filename "user_${u}")"
    orig="${d}/Library/Application Support/com.apple.TCC/TCC.db"
    dest="${base}/source_${su}"
    forensic_ensure_directory "${dest}" "TCC ${su}" || true
    if [[ -f "${orig}" ]]; then
      forensic_report_step "Running: cp -p (TCC.db user ${u}) → evidence/TCC/source_${su}/TCC.db"
      if cp -p "${orig}" "${dest}/TCC.db" 2>/dev/null; then
        printf '%s\n' "OK ${su}: ${orig}" >>"${doc}/copy_log.txt"
        forensic_sqlite_dump_metadata "${dest}/TCC.db" "${meta}" "source_${su}"
      else
        printf '%s\n' "FAILED ${su}: ${orig}" >>"${doc}/copy_log.txt"
      fi
    else
      printf '%s\n' "SKIPPED missing file: ${orig}" >>"${doc}/copy_log.txt"
    fi
  done
  shopt -u nullglob 2>/dev/null || true

  orig="/var/root/Library/Application Support/com.apple.TCC/TCC.db"
  dest="${base}/source_var_root"
  forensic_ensure_directory "${dest}" "TCC var_root" || true
  if [[ -f "${orig}" ]]; then
    forensic_report_step "Running: cp -p (TCC.db /var/root) → evidence/TCC/source_var_root/TCC.db"
    if cp -p "${orig}" "${dest}/TCC.db" 2>/dev/null; then
      printf '%s\n' "OK source_var_root: ${orig}" >>"${doc}/copy_log.txt"
      forensic_sqlite_dump_metadata "${dest}/TCC.db" "${meta}" "source_var_root"
    else
      printf '%s\n' "FAILED source_var_root: ${orig}" >>"${doc}/copy_log.txt"
    fi
  else
    printf '%s\n' "SKIPPED missing file: ${orig}" >>"${doc}/copy_log.txt"
  fi

  printf '%s\n' "--- end copy log $(date) ---" >>"${doc}/copy_log.txt"
  set -e
  return 0
}

# Chromium-style profiles: …/User Data/{Default|Profile *|Guest Profile}/History → copy + SQLite metadata.
forensic_history_copy_chromium_ud() {
  local app_root="${1:?}" hist_root="${2:?}" su_tag="${3:?}" brand="${4:?}" meta="${5:?}" logf="${6:?}"
  local ud sub safe_pl dest st
  ud="${app_root}/User Data"
  [[ -d "${ud}" ]] || return 0
  shopt -s nullglob 2>/dev/null || true
  for sub in "${ud}/Default" "${ud}/Profile "* "${ud}/Guest Profile"; do
    [[ -d "${sub}" ]] || continue
    [[ -f "${sub}/History" ]] || continue
    safe_pl="$(forensic_safe_filename "$(basename "${sub}")")"
    dest="${hist_root}/copy_${su_tag}/${brand}_${safe_pl}"
    forensic_report_step "Running: cp -p («${brand}», ${su_tag}, profile ${safe_pl}) User Data/*/History → browser_history/${brand}_${safe_pl}"
    forensic_ensure_directory "${dest}" "history chromium" || true
    if cp -p "${sub}/History" "${dest}/History" 2>/dev/null; then
      printf '%s\n' "OK ${brand} ${su_tag}: ${sub}/History -> ${dest}/History" >>"${logf}"
      forensic_history_post_copy_sqlite "${dest}/History" "${meta}" "${su_tag}_${brand}_${safe_pl}" chromium "${hist_root}"
    else
      st=$?
      printf '%s\n' "FAILED ${brand} (cp ${st}): ${sub}/History" >>"${logf}"
    fi
  done
  shopt -u nullglob 2>/dev/null || true
  return 0
}

# SQLite copies of typical browser histories (Safari/Chromium/Firefox) + chain-of-custody documentation. No mass SELECT over tables.
forensic_acquisition_browser_history() {
  local base doc meta readme d u su orig dest lf ff places prof_tag safe_prof
  [[ -n "${FORENSIC_SESSION_DIR:-}" ]] || return 0
  set +e
  base="${FORENSIC_SESSION_DIR}/evidence/browser_history"
  doc="${base}/documentation"
  meta="${base}/sqlite_metadata"

  forensic_report_step "Acquiring SQLite browser history copies → evidence/browser_history/"
  forensic_ensure_directory "${doc}" "browser_history" || {
    set -e
    return 0
  }
  forensic_ensure_directory "${meta}" "browser history sqlite_metadata" || {
    set -e
    return 0
  }

  lf="${doc}/copy_log.txt"

  forensic_report_step "Running: sqlite3 --version → evidence/browser_history/documentation/sqlite3_version.txt"
  sqlite3 --version >"${doc}/sqlite3_version.txt" 2>/dev/null || printf 'sqlite3 not available\n' >"${doc}/sqlite3_version.txt"

  readme="$(cat <<'EOF'
================================================================================
Forensic-MAC.sh — evidence/browser_history/
================================================================================

Contents (v1.31+)
--------------------------------
• documentation/  README, CSV export option (environment variables), sqlite3 version, copy log (copy_log.txt).
• copy_user_* / user_var_root/  Local copies of History.db / History / places.sqlite.
• sqlite_metadata/ Schema and PRAGMA from the copies (.schema, integrity_check, page_count).
• export_sql/  Only if FORENSIC_BROWSER_HISTORY_EXPORT_TABLES=1 before launching sudo: CSV samples (urls / moz_places / history_items) with limit.

Scope
------
Safari (~ and container), Chromium-like (Chrome, Brave, Edge, Vivaldi, Arc, Opera, Opera GX, Yandex, Chromium project), Firefox. Optional and bounded tabular export (see FORENSIC_BROWSER_HISTORY_EXPORT_TABLES.txt in this folder).

Evidentiary value
----------------
Chain with 00_METADATA.txt and 01_INTEGRITY_CHECK.txt if the phase ran before closing.

Limitations
------------
• Open browsers may lock or leave the copy inconsistent (WAL). TCC / Full Disk Access may prevent reading.
• Size and sensitivity: handle according to internal policy.
EOF
)"
  forensic_report_step "Writing text: evidence/browser_history/documentation/README_PROCEDURE.txt"
  forensic_write_text "evidence/browser_history/documentation/README_PROCEDURE.txt" "${readme}" || true

  vol_txt="$(cat <<'EOF'
Optional tabular export (from COPIES in session, not from the live browser beyond the cp).

To enable before launching Forensic-MAC with root privileges:

  export FORENSIC_BROWSER_HISTORY_EXPORT_TABLES=1
  export FORENSIC_BROWSER_HISTORY_SQL_LIMIT=8000   # optional; integer; default 8000 rows/query

  sudo -E ./Forensic-MAC.sh

Relative output in the session folder: evidence/browser_history/export_sql/
EOF
)"
  forensic_report_step "Writing text: evidence/browser_history/documentation/FORENSIC_BROWSER_HISTORY_EXPORT_TABLES.txt"
  forensic_write_text "evidence/browser_history/documentation/FORENSIC_BROWSER_HISTORY_EXPORT_TABLES.txt" "${vol_txt}" || true
  [[ "${FORENSIC_BROWSER_HISTORY_EXPORT_TABLES:-}" == "1" ]] \
    && forensic_report_step "FORENSIC_BROWSER_HISTORY_EXPORT_TABLES=1 → CSV samples in evidence/browser_history/export_sql/"
  forensic_report_step "Initializing SQLite copy log (browser history) → evidence/browser_history/documentation/copy_log.txt"
  {
    printf '%s\n' "--- SQLite browser history copy attempts log — Forensic-MAC.sh | $(date) ---"
  } >"${lf}"

  for d in /Users/*; do
    [[ -d "${d}" ]] || continue
    u="$(basename "${d}")"
    [[ "${u}" == "Shared" ]] && continue
    su="$(forensic_safe_filename "user_${u}")"

    orig="${d}/Library/Safari/History.db"
    dest="${base}/copy_${su}/safari_legacy"
    if [[ -f "${orig}" ]]; then
      forensic_ensure_directory "${dest}" "safari legacy" || true
      forensic_report_step "Running: cp -p (Safari legacy ${su}) History.db → browser_history/safari_legacy"
      if cp -p "${orig}" "${dest}/History.db" 2>/dev/null; then
        printf '%s\n' "OK safari_legacy: ${orig}" >>"${lf}"
        forensic_history_post_copy_sqlite "${dest}/History.db" "${meta}" "${su}_safari_legacy" safari "${base}"
      else
        printf '%s\n' "FAILED safari_legacy (cp $?): ${orig}" >>"${lf}"
      fi
    else
      printf '%s\n' "SKIPPED missing file: ${orig}" >>"${lf}"
    fi

    orig="${d}/Library/Containers/com.apple.Safari/Data/Library/Safari/History.db"
    dest="${base}/copy_${su}/safari_container"
    if [[ -f "${orig}" ]]; then
      forensic_ensure_directory "${dest}" "safari container" || true
      forensic_report_step "Running: cp -p (Safari container ${su}) History.db → browser_history/safari_container"
      if cp -p "${orig}" "${dest}/History.db" 2>/dev/null; then
        printf '%s\n' "OK safari_container: ${orig}" >>"${lf}"
        forensic_history_post_copy_sqlite "${dest}/History.db" "${meta}" "${su}_safari_container" safari "${base}"
      else
        printf '%s\n' "FAILED safari_container (cp $?): ${orig}" >>"${lf}"
      fi
    else
      printf '%s\n' "SKIPPED missing file: ${orig}" >>"${lf}"
    fi

    forensic_history_copy_chromium_ud "${d}/Library/Application Support/Google/Chrome" "${base}" "${su}" "chrome" "${meta}" "${lf}"
    forensic_history_copy_chromium_ud "${d}/Library/Application Support/BraveSoftware/Brave-Browser" "${base}" "${su}" "brave" "${meta}" "${lf}"
    forensic_history_copy_chromium_ud "${d}/Library/Application Support/Microsoft Edge" "${base}" "${su}" "edge" "${meta}" "${lf}"
    forensic_history_copy_chromium_ud "${d}/Library/Application Support/Vivaldi" "${base}" "${su}" "vivaldi" "${meta}" "${lf}"
    forensic_history_copy_chromium_ud "${d}/Library/Application Support/Arc" "${base}" "${su}" "arc" "${meta}" "${lf}"
    forensic_history_copy_chromium_ud "${d}/Library/Application Support/com.operasoftware.Opera" "${base}" "${su}" opera "${meta}" "${lf}"
    forensic_history_copy_chromium_ud "${d}/Library/Application Support/com.operasoftware.OperaGX" "${base}" "${su}" operagx "${meta}" "${lf}"
    forensic_history_copy_chromium_ud "${d}/Library/Application Support/Yandex/YandexBrowser" "${base}" "${su}" yandex "${meta}" "${lf}"
    forensic_history_copy_chromium_ud "${d}/Library/Application Support/Chromium" "${base}" "${su}" chromium "${meta}" "${lf}"

    ff="${d}/Library/Application Support/Firefox/Profiles"
    if [[ -d "${ff}" ]]; then
      forensic_report_step "Running: find (Firefox ${su}) places.sqlite → browser_history"
      while IFS= read -r places || [ -n "${places}" ]; do
        [[ -z "${places}" ]] && continue
        [[ -f "${places}" ]] || continue
        prof_tag="$(basename "$(dirname "${places}")")"
        safe_prof="$(forensic_safe_filename "${prof_tag}")"
        dest="${base}/copy_${su}/firefox_${safe_prof}"
        forensic_ensure_directory "${dest}" "firefox" || true
        forensic_report_step "Running: cp -p (Firefox ${su}, profile ${safe_prof}) places.sqlite → browser_history"
        if cp -p "${places}" "${dest}/places.sqlite" 2>/dev/null; then
          printf '%s\n' "OK firefox ${su}: ${places}" >>"${lf}"
          forensic_history_post_copy_sqlite "${dest}/places.sqlite" "${meta}" "${su}_firefox_${safe_prof}" firefox "${base}"
        else
          printf '%s\n' "FAILED firefox (cp $?): ${places}" >>"${lf}"
        fi
      done < <(find "${ff}" -name places.sqlite -type f 2>/dev/null)
    fi
  done

  su="user_var_root"
  orig="/var/root/Library/Safari/History.db"
  dest="${base}/copy_${su}/safari_legacy"
  if [[ -f "${orig}" ]]; then
    forensic_ensure_directory "${dest}" "var_root safari" || true
    forensic_report_step "Running: cp -p (Safari /var/root) History.db → browser_history/var_root safari_legacy"
    if cp -p "${orig}" "${dest}/History.db" 2>/dev/null; then
      printf '%s\n' "OK var_root safari_legacy: ${orig}" >>"${lf}"
      forensic_history_post_copy_sqlite "${dest}/History.db" "${meta}" "${su}_safari_legacy" safari "${base}"
    else
      printf '%s\n' "FAILED var_root safari_legacy (cp $?): ${orig}" >>"${lf}"
    fi
  else
    printf '%s\n' "SKIPPED var_root: ${orig}" >>"${lf}"
  fi
  forensic_history_copy_chromium_ud "/var/root/Library/Application Support/Google/Chrome" "${base}" "${su}" "chrome" "${meta}" "${lf}"
  forensic_history_copy_chromium_ud "/var/root/Library/Application Support/com.operasoftware.Opera" "${base}" "${su}" opera "${meta}" "${lf}"

  printf '%s\n' "--- end copy log $(date) ---" >>"${lf}"
  set -e
  return 0
}

# rsync with logging (native macOS). Trailing / on source recommended.
forensic_rsync_log() {
  local log_name="$1"
  local source="$2"
  local destination="$3"
  [[ -n "${FORENSIC_SESSION_DIR:-}" ]] || return 1
  local log="${FORENSIC_SESSION_DIR}/${log_name}"
  if [[ ! -e "$source" ]]; then
    forensic_report_step "rsync skipped (source does not exist): ${source}"
  else
    forensic_report_step "rsync ${source} → session folder (log: ${log_name})"
  fi
  forensic_ensure_directory "$(dirname "$log")" "rsync log" || return 1
  forensic_ensure_directory "$destination" "rsync destination" || return 1
  {
    printf '%s\n' "--- rsync | $(date) ---"
    printf '%s\n\n' "--- ${source} -> ${destination} ---"
  } >"$log"
  if [[ ! -e "$source" ]]; then
    printf '(Source does not exist, skipping: %s)\n' "$source" >>"$log"
    return 0
  fi
  rsync -aHAX --numeric-ids "${source}" "${destination}" >>"$log" 2>&1 || printf '\n--- rsync exit code: %s ---\n' "$?" >>"$log"
}

# Value of a key in IOPlatformExpertDevice (UUID, serial, etc.). Empty if no match.
forensic_ioreg_platform_value() {
  local key="${1:?}" out
  out="$(ioreg -rd1 -c IOPlatformExpertDevice 2>/dev/null \
    | sed -n "s/.*\"${key}\" = \"\\([^\"]*\\)\".*/\\1/p" | head -1)" || true
  printf '%s' "${out}"
}

# Session metadata (run start): host fingerprint and timeline. Scope, warnings, and operational table → README and this script's header.
forensic_write_session_metadata() {
  local readable_mode="$1"
  local script_path ts_local ts_utc cn lhn hn hwmodel plat_uuid plat_serial boottime kernv uptime_line
  local logname_u ppid_v pid_v script_sha macos_version
  forensic_report_step "Collecting session fingerprint and timing (date, scutil, sysctl, ioreg, script shasum, hostname…) before ${FORENSIC_SESSION_METADATA_FILE}"
  macos_version="$(sw_vers -productVersion 2>/dev/null)" || macos_version="N/A"
  script_path="${BASH_SOURCE[0]:-$0}"
  ts_local="$(date +"%Y-%m-%d %H:%M:%S %Z (offset %z)")" || true
  ts_utc="$(date -u +"%Y-%m-%d %H:%M:%S UTC")" || true
  cn="$(scutil --get ComputerName 2>/dev/null)" || true
  lhn="$(scutil --get LocalHostName 2>/dev/null)" || true
  hn="$(scutil --get HostName 2>/dev/null)" || true
  hwmodel="$(sysctl -n hw.model 2>/dev/null)" || true
  plat_uuid="$(forensic_ioreg_platform_value IOPlatformUUID)" || true
  plat_serial="$(forensic_ioreg_platform_value IOPlatformSerialNumber)" || true
  boottime="$(sysctl -n kern.boottime 2>/dev/null)" || true
  kernv="$(sysctl -n kern.version 2>/dev/null | head -1)" || true
  uptime_line="$(uptime 2>/dev/null)" || true
  logname_u="$(logname 2>/dev/null)" || true
  ppid_v="${PPID:-N/A}"
  pid_v="$$"
  script_sha="$(shasum -a 256 "${script_path}" 2>/dev/null | awk '{print $1}')" || true
  [[ -n "${cn// /}" ]] || cn="N/A"
  [[ -n "${lhn// /}" ]] || lhn="N/A"
  [[ -n "${hn// /}" ]] || hn="N/A"
  [[ -n "${hwmodel// /}" ]] || hwmodel="N/A"
  [[ -n "${plat_uuid}" ]] || plat_uuid="N/A"
  [[ -n "${plat_serial}" ]] || plat_serial="N/A"
  [[ -n "${boottime}" ]] || boottime="N/A"
  [[ -n "${kernv}" ]] || kernv="N/A"
  [[ -n "${uptime_line}" ]] || uptime_line="N/A"
  [[ -n "${logname_u}" ]] || logname_u="N/A"
  [[ -n "${script_sha}" ]] || script_sha="N/A"

  local info
  info="================================================================================
Forensic-MAC.sh — Forensic Extraction (macOS) | session metadata
================================================================================

--- Execution Data Identification ---
Script version: ${VERSION}
Script path: ${script_path}
SHA256 (script on disk): ${script_sha}
Declared mode: ${readable_mode}
Process PID / PPID: ${pid_v} / ${ppid_v}
«logname» user (console prior to sudo, if applicable): ${logname_u}
Output directory for this session: ${FORENSIC_SESSION_DIR}
Machine architecture: ${FORENSIC_ARCH}

--- Timeline ---
Timestamps and temporal state at the start of the session (before the collection phase).
Local timestamp: ${ts_local}
UTC timestamp:   ${ts_utc}
Time since boot (uptime): ${uptime_line}
kern.boottime: ${boottime}

--- Host fingerprint / identification (summary) ---
Visible name (forensic table / folder): $(forensic_host_label)
ComputerName (scutil): ${cn}
LocalHostName (scutil): ${lhn}
HostName (scutil): ${hn}
hostname (short): $(hostname -s 2>/dev/null || hostname 2>/dev/null || echo N/A)
Model (sysctl hw.model): ${hwmodel}
macOS (ProductVersion): ${macos_version}
Architecture: ${FORENSIC_ARCH}
IOPlatformUUID (ioreg): ${plat_uuid}
IOPlatformSerialNumber (ioreg): ${plat_serial}
Kernel (sysctl kern.version, first line): ${kernv}

================================================================================
"
  forensic_report_step "Writing session metadata → ${FORENSIC_SESSION_METADATA_FILE}"
  forensic_write_text "${FORENSIC_SESSION_METADATA_FILE}" "${info}" || true
}

# --- Complete extraction (without external RAM dump) ---
forensic_extraction_complete_without_ram() {
  printf '\n%s╔═════════════════════════════════════════════════════╗%s\n' "${RGB_BLUE}" "${RESET_COLOR}"
  printf '%s║ %s⚙ COLLECTING ARTIFACTS%*s%s║%s\n' "${RGB_BLUE}" "${ANSI_WHITE}" 30 "" "${RGB_BLUE}" "${RESET_COLOR}"
  printf '%s╚═════════════════════════════════════════════════════╝%s\n\n' "${RGB_BLUE}" "${RESET_COLOR}"
  # Context
  forensic_cmd_to_file "evidence/context_date.txt" date
  forensic_cmd_to_file "evidence/context_whoami.txt" whoami
  forensic_cmd_to_file "evidence/context_hostname.txt" hostname
  forensic_cmd_to_file "evidence/context_uname.txt" uname -a
  forensic_cmd_to_file "evidence/context_sw_vers.txt" sw_vers
  forensic_cmd_to_file "evidence/context_sysctl_machdep.txt" sysctl machdep.cpu.brand_string
  # System
  forensic_cmd_to_file "evidence/system_system_profiler_HW_SW.txt" system_profiler SPHardwareDataType SPSoftwareDataType
  forensic_cmd_to_file "evidence/system_processor_info.txt" sh -c "sysctl -a | grep -E 'kern.ostype|kern.version|hw.model|hw.machine|hw.cpu'"
  # Disks and volumes
  forensic_cmd_to_file "evidence/disk_diskutil_list.txt" diskutil list
  forensic_cmd_to_file "evidence/disk_diskutil_apfs_list.txt" diskutil apfs list
  forensic_cmd_to_file "evidence/disk_mount.txt" mount
  # Connected hardware (profiler)
  forensic_cmd_to_file "evidence/hardware_system_profiler_SPUSBDataType.txt" system_profiler SPUSBDataType
  forensic_cmd_to_file "evidence/hardware_system_profiler_SPBluetoothDataType.txt" system_profiler SPBluetoothDataType
  forensic_cmd_to_file "evidence/hardware_system_profiler_SPAirPort_SPThunderbolt.txt" system_profiler SPAirPortDataType SPThunderboltDataType
  # Users
  forensic_cmd_to_file "evidence/users_dscl_list_Users.txt" dscl . list /Users
  forensic_cmd_to_file "evidence/users_dscacheutil_user.txt" dscacheutil -q user
  forensic_cmd_to_file "evidence/users_last.txt" last
  forensic_cmd_to_file "evidence/users_who.txt" who
  # Processes
  forensic_cmd_to_file "evidence/processes_ps_auxww.txt" ps auxww
  forensic_cmd_to_file "evidence/processes_top_l1.txt" top -l 1
  # Network
  forensic_cmd_to_file "evidence/network_netstat_an.txt" netstat -an
  forensic_cmd_to_file "evidence/network_netstat_rn.txt" netstat -rn
  forensic_cmd_to_file "evidence/network_lsof_i.txt" lsof -i
  forensic_cmd_to_file "evidence/network_ifconfig.txt" ifconfig
  forensic_cmd_to_file "evidence/network_scutil_dns.txt" scutil --dns
  forensic_cmd_to_file "evidence/network_arp_an.txt" arp -an
  forensic_cmd_to_file "evidence/network_route_get_default.txt" route get default
  forensic_cmd_to_file "evidence/network_scutil_proxy.txt" scutil --proxy
  forensic_cmd_to_file "evidence/network_scutil_nc_list.txt" sh -c "scutil --nc list 2>&1 || printf '%s\n' '[scutil --nc]: not available'"
  forensic_cmd_to_file "evidence/network_networksetup_listallnetworkservices.txt" networksetup -listallnetworkservices
  forensic_cmd_to_file "evidence/network_networksetup_listallhardwareports.txt" networksetup -listallhardwareports
  forensic_cmd_to_file "evidence/network_dscacheutil_statistics.txt" dscacheutil -statistics
  forensic_cmd_to_file "evidence/network_etc_hosts.txt" sh -c "cat /etc/hosts 2>&1 || printf '%s\n' 'Cannot read /etc/hosts'"
  # Installed software
  forensic_cmd_to_file "evidence/software_ls_Applications.txt" ls -la /Applications
  forensic_software_ls_users_applications "evidence/software_ls_Users_Applications.txt"
  forensic_cmd_to_file "evidence/software_system_profiler_SPApplicationsDataType.txt" system_profiler SPApplicationsDataType
  forensic_cmd_to_file "evidence/software_system_profiler_SPInstallHistoryDataType.txt" system_profiler SPInstallHistoryDataType
  forensic_cmd_to_file "evidence/software_pkgutil_pkgs.txt" pkgutil --pkgs
  # Login items / persistence (listings + osascript; rsync copies continue below)
  forensic_cmd_to_file "evidence/persistence_ls_Library_LaunchAgents.txt" ls -la /Library/LaunchAgents
  forensic_cmd_to_file "evidence/persistence_ls_Library_LaunchDaemons.txt" ls -la /Library/LaunchDaemons
  forensic_persistence_ls_users_library_launchagents "evidence/persistence_ls_Users_Library_LaunchAgents.txt"
  forensic_cmd_to_file "evidence/persistence_launchctl_list.txt" launchctl list
  forensic_cmd_to_file "evidence/persistence_launchctl_print_system.txt" launchctl print system
  forensic_cmd_to_file "evidence/security_spctl_status.txt" spctl --status
  forensic_cmd_to_file "evidence/security_csrutil_status.txt" csrutil status
  forensic_cmd_to_file "evidence/security_systemextensionsctl_list.txt" systemextensionsctl list
  forensic_cmd_to_file "evidence/security_system_profiler_SPExtensionsDataType.txt" system_profiler SPExtensionsDataType
  forensic_cmd_to_file "evidence/security_kextstat.txt" kextstat
  forensic_cmd_to_file "evidence/security_pluginkit_match_Av.txt" sh -c "pluginkit -m Av 2>&1 || printf '%s\n' '[pluginkit]: not executable or option not supported on this system.'"
  forensic_cmd_to_file "evidence/security_ls_Library_Extensions.txt" sh -c "ls -la /Library/Extensions 2>&1"
  forensic_cmd_to_file "evidence/security_ls_Library_SystemExtensions.txt" sh -c 'if [[ -e /Library/SystemExtensions ]]; then ls -la /Library/SystemExtensions 2>&1; else printf "%s\n" "Does not exist or not visible: /Library/SystemExtensions"; fi'
  forensic_cmd_to_file "evidence/security_ls_System_Library_Extensions.txt" sh -c "ls -la /System/Library/Extensions 2>&1"
  forensic_cmd_to_file "evidence/security_kmutil_showlists.txt" sh -c "command -v kmutil >/dev/null 2>&1 && kmutil showlists || printf '%s\n' 'kmutil not available on this system.'"
  forensic_cmd_to_file "evidence/security_kmutil_showloaded.txt" sh -c "command -v kmutil >/dev/null 2>&1 && kmutil showloaded || printf '%s\n' 'kmutil not available on this system.'"
  forensic_cmd_to_file "evidence/security_gatekeeper_assessment.txt" sh -c "softwareupdate -l 2>&1 | head -20 || printf '%s\n' 'No updates available or GateKeeper info unavailable'"
  forensic_acquisition_tcc || true
  forensic_ls_browser_paths_preview "evidence/navigation_ls_typical_paths.txt"
  forensic_acquisition_browser_history || true
  forensic_loginitems_osascript_per_user "evidence/loginitems_osascript_System_Events.txt"
  # Unified logs (Apple)
  local log_coll="${FORENSIC_SESSION_DIR}/evidence/logs_collect.logarchive"
  forensic_report_step "Preparing directory for log collect (.logarchive)…"
  forensic_ensure_directory "$(dirname "$log_coll")" "logs" || true
  forensic_cmd_to_file "evidence/logs_log_collect_cmd.txt" log collect --output "$log_coll"
  # Persistence (copy)
  forensic_rsync_log "evidence/rsync_LaunchDaemons.log" /Library/LaunchDaemons/ "${FORENSIC_SESSION_DIR}/evidence/persistence/Library_LaunchDaemons/"
  forensic_rsync_log "evidence/rsync_LaunchAgents.log" /Library/LaunchAgents/ "${FORENSIC_SESSION_DIR}/evidence/persistence/Library_LaunchAgents/"
  forensic_rsync_log "evidence/rsync_SystemLaunchDaemons.log" /System/Library/LaunchDaemons/ "${FORENSIC_SESSION_DIR}/evidence/persistence/System_Library_LaunchDaemons/"
  forensic_rsync_log "evidence/rsync_SystemLaunchAgents.log" /System/Library/LaunchAgents/ "${FORENSIC_SESSION_DIR}/evidence/persistence/System_Library_LaunchAgents/"
  # Temporary
  forensic_rsync_log "evidence/rsync_tmp.log" /tmp/ "${FORENSIC_SESSION_DIR}/evidence/temp/tmp/"
  forensic_rsync_log "evidence/rsync_var_tmp.log" /var/tmp/ "${FORENSIC_SESSION_DIR}/evidence/temp/var_tmp/"
}

# Volatile RAM: native only (osxpmem is external).
forensic_extraction_volatile_ram_native() {
  printf '%s[*] %s[RAM Mode] Memory metadata / volatile (without osxpmem)…%s\n' "${RGB_BLUE}" "${ANSI_WHITE}" "${RESET_COLOR}"
  forensic_report_step "Writing informational note (osxpmem not included) → evidence/RAM_NOTE_osxpmem_external.txt"
  forensic_write_text "evidence/RAM_NOTE_osxpmem_external.txt" "osxpmem is NOT native to macOS; this script does not run it.
Install the tool separately if you need a physical RAM dump.
The above are just native commands (vm_stat, sysctl)." || true
  forensic_cmd_to_file "evidence/RAM_vm_stat.txt" vm_stat
  forensic_cmd_to_file "evidence/RAM_sysctl_hw_mem.txt" sysctl hw.memsize hw.physicalcpu hw.logicalcpu
  forensic_cmd_to_file "evidence/RAM_sysctl_vm.txt" sysctl vm.loadavg
}

# OpenSSL signature (SHA-256 digest, RSA/EC PEM) → <manifest>.sig next to the .txt. Without a key in the environment, does nothing.
forensic_sign_integrity_check_openssl() {
  local manifest="${1:?}"
  local key_path="${FORENSIC_OPENSSL_SIGN_KEY:-}"
  [[ -n "${key_path}" ]] || return 0
  [[ -f "${manifest}" ]] || return 0
  if [[ ! -r "${key_path}" ]]; then
    printf '%s[!] %sFORENSIC_OPENSSL_SIGN_KEY not readable: %s%s\n' "${RGB_RED}" "${ANSI_WHITE}" "${key_path}" "${RESET_COLOR}" >&2
    return 0
  fi
  if ! command -v openssl >/dev/null 2>&1; then
    printf '%s[!] %sopenssl not found in PATH%s\n' "${RGB_RED}" "${ANSI_WHITE}" "${RESET_COLOR}" >&2
    return 0
  fi
  local sig="${manifest}.sig"
  forensic_report_step "Running: openssl dgst -sha256 -sign → $(basename "${sig}")"
  set +e
  openssl dgst -sha256 -sign "${key_path}" -out "${sig}" "${manifest}" 2>/dev/null
  local st=$?
  set -e
  if [[ "${st}" -eq 0 && -f "${sig}" ]]; then
    printf '%s[*] %sSigned (OpenSSL): %s%s\n' "${RGB_BLUE}" "${ANSI_WHITE}" "$(basename "${sig}")" "${RESET_COLOR}"
  else
    printf '%s[!] %sCould not sign the manifest with OpenSSL (RSA/EC PEM key, permissions).%s\n' "${RGB_RED}" "${ANSI_WHITE}" "${RESET_COLOR}" >&2
    rm -f -- "${sig}" 2>/dev/null || true
  fi
  return 0
}

# Integrity check: auditable header + one line per file (<sha256> <bytes> <mtime_epoch> <relative_path>),
# stable lexicographic order (LC_ALL=C). Excludes the listing itself. macOS: stat -f%z / -f%m, shasum -a 256.
forensic_generate_integrity_check_shasum() {
  local check_output="${FORENSIC_SESSION_DIR}/${FORENSIC_INTEGRITY_CHECK_FILE}"
  local tmp count
  printf '%s[*] %sGenerating %s (integrity check; walking the session, no %% progress)…%s\n' "${RGB_BLUE}" "${ANSI_WHITE}" "${FORENSIC_INTEGRITY_CHECK_FILE}" "${RESET_COLOR}"

  tmp="$(mktemp "${TMPDIR:-/tmp}/forensic_integrity.XXXXXX")" || return 0

  forensic_report_step "Running: find (list session files) + sort LC_ALL=C → temporary list for integrity"
  (
    cd "${FORENSIC_SESSION_DIR}" 2>/dev/null || exit 0
    find . -type f ! -path "./${FORENSIC_INTEGRITY_CHECK_FILE}" -print 2>/dev/null | LC_ALL=C sort
  ) >"${tmp}" 2>/dev/null || true

  count="$(wc -l <"${tmp}" 2>/dev/null | tr -d '[:space:]')"
  [[ -z "${count}" ]] && count=0

  forensic_report_step "Running: shasum -a 256 + stat on ${count} session file(s) → ${FORENSIC_INTEGRITY_CHECK_FILE}"

  {
    printf '# Forensic-MAC.sh — integrity check\n'
    printf '# VERSION: %s\n' "${VERSION}"
    printf '# SESSION_ROOT: %s\n' "${FORENSIC_SESSION_DIR}"
    printf '# ALGORITHM: SHA-256\n'
    printf '# FILES: %s\n' "${count}"
    printf '# FORMAT: <sha256> <size_bytes> <mtime_unix_epoch> <relative_path>\n'
    printf '# GENERATED: %s\n' "$(date '+%Y-%m-%d %H:%M:%S %Z')"
    printf '# ---\n'
    (
      cd "${FORENSIC_SESSION_DIR}" 2>/dev/null || exit 0
      set +e
      while IFS= read -r rp || [ -n "${rp}" ]; do
        [ -z "${rp}" ] && continue
        rel="${rp#./}"
        [ -n "${rel}" ] || continue
        [ -f "${rp}" ] || continue
        sz="$(stat -f%z "${rp}" 2>/dev/null)"
        mt="$(stat -f%m "${rp}" 2>/dev/null)"
        h="$(shasum -a 256 "${rp}" 2>/dev/null | awk '{print $1}')"
        [ -n "${h}" ] || h="ERROR"
        [ -n "${sz}" ] || sz="?"
        [ -n "${mt}" ] || mt="?"
        printf '%s %s %s %s\n' "${h}" "${sz}" "${mt}" "${rel}"
      done <"${tmp}"
    )
  } >"${check_output}" || true

  rm -f -- "${tmp}"
  forensic_sign_integrity_check_openssl "${check_output}"
  return 0
}

# Orchestrator: creates session, metadata, phases, and integrity check (hashes).
forensic_execute_mode() {
  local label="$1"
  local readable_mode="$2"
  local mode_type="${3:?}"

  if ! forensic_create_output_directory "${label}"; then
    printf '\n%s╔═════════════════════════════════════════════════════╗%s\n' "${RGB_RED}" "${RESET_COLOR}"
    printf '%s║ %s✗ ERROR: Could not create RESULTS/%*s%s║%s\n' "${RGB_RED}" "${ANSI_WHITE}" 18 "" "${RGB_RED}" "${RESET_COLOR}"
    printf '%s╚═════════════════════════════════════════════════════╝%s\n' "${RGB_RED}" "${RESET_COLOR}"
    return 1
  fi
  local session_name session_pad
  session_name="$(basename "${FORENSIC_SESSION_DIR}")"
  # Truncate if the session name (host + mode + timestamp) exceeds the box width, so the border never breaks.
  (( ${#session_name} > 52 )) && session_name="${session_name:0:49}..."
  session_pad=$(( 53 - 1 - ${#session_name} ))
  (( session_pad < 0 )) && session_pad=0
  printf '\n%s╔═════════════════════════════════════════════════════╗%s\n' "${RGB_GREEN}" "${RESET_COLOR}"
  printf '%s║ %s✓ Session initialized%*s%s║%s\n' "${RGB_GREEN}" "${RGB_SUCCESS}" 31 "" "${RGB_GREEN}" "${RESET_COLOR}"
  printf '%s╟─────────────────────────────────────────────────────╢%s\n' "${RGB_GREEN}" "${RESET_COLOR}"
  printf '%s║ %s%s%*s%s║%s\n' "${RGB_GREEN}" "${ANSI_WHITE}" "${session_name}" "${session_pad}" "" "${RGB_GREEN}" "${RESET_COLOR}"
  printf '%s╚═════════════════════════════════════════════════════╝%s\n' "${RGB_GREEN}" "${RESET_COLOR}"

  forensic_write_session_metadata "${readable_mode}"

  printf '\n%s[*] %sStarting forensic artifact collection…%s\n' "${RGB_BLUE}" "${ANSI_WHITE}" "${RESET_COLOR}"

  # Subshell: don't disable the main script's set -e if a command fails.
  (
    set +e
    case "${mode_type}" in
      complete_without_ram)  forensic_extraction_complete_without_ram ;;
      complete_with_ram)     forensic_extraction_complete_without_ram; forensic_extraction_volatile_ram_native ;;
      *)                     printf '%s[!] unknown mode: %s\n' "${RGB_RED}" "${mode_type}" ;;
    esac
  )

  forensic_generate_integrity_check_shasum

  local file_count file_count_pad
  file_count="$(find "${FORENSIC_SESSION_DIR}/evidence" -type f 2>/dev/null | wc -l | tr -d '[:space:]')"
  file_count_pad=$(( 53 - 1 - 9 - ${#file_count} ))
  (( file_count_pad < 0 )) && file_count_pad=0
  local integrity_pad=$(( 53 - 1 - 13 - ${#FORENSIC_INTEGRITY_CHECK_FILE} ))
  (( integrity_pad < 0 )) && integrity_pad=0

  printf '\n%s╔═════════════════════════════════════════════════════╗%s\n' "${RGB_SUCCESS}" "${RESET_COLOR}"
  printf '%s║ %s✓ Extraction completed successfully%*s%s║%s\n' "${RGB_SUCCESS}" "${ANSI_WHITE}" 17 "" "${RGB_SUCCESS}" "${RESET_COLOR}"
  printf '%s╟─────────────────────────────────────────────────────╢%s\n' "${RGB_SUCCESS}" "${RESET_COLOR}"
  printf '%s║ %s→ Files: %s%s%*s%s║%s\n' "${RGB_SUCCESS}" "${RGB_BLUE}" "${ANSI_WHITE}" "${file_count}" "${file_count_pad}" "" "${RGB_SUCCESS}" "${RESET_COLOR}"
  printf '%s║ %s→ Integrity: %s%s%*s%s║%s\n' "${RGB_SUCCESS}" "${RGB_BLUE}" "${ANSI_WHITE}" "${FORENSIC_INTEGRITY_CHECK_FILE}" "${integrity_pad}" "" "${RGB_SUCCESS}" "${RESET_COLOR}"
  printf '%s╚═════════════════════════════════════════════════════╝%s\n' "${RGB_SUCCESS}" "${RESET_COLOR}"
  return 0
}

# --- Terminal width (to center frame and logo) ---
get_terminal_width() {
  local cols
  cols="$(tput cols 2>/dev/null || true)"
  if [[ -n "${cols}" && "${cols}" =~ ^[0-9]+$ ]]; then
    echo "${cols}"
  else
    echo 80
  fi
}

# --- Screen clearing (macOS/Linux friendly) ---
clear_screen() {
  # shellcheck disable=SC2015
  command -v clear >/dev/null 2>&1 && clear || printf '\033c'
}

# --- ASCII Logo: $1 = left margin in spaces (usually margin+8) ---
# Figlet "standard" font banner spelling "ForensicMAC" (generated with: figlet -f standard "ForensicMAC")
_print_logo() {
  local ascii_margin="$1"
  local l1=" _____                        _      __  __    _    ____ "
  local l2="|  ___|__  _ __ ___ _ __  ___(_) ___|  \\/  |  / \\  / ___|"
  local l3="| |_ / _ \\| '__/ _ \\ '_ \\/ __| |/ __| |\\/| | / _ \\| |    "
  local l4="|  _| (_) | | |  __/ | | \\__ \\ | (__| |  | |/ ___ \\ |___ "
  local l5="|_|  \\___/|_|  \\___|_| |_|___/_|\\___|_|  |_/_/   \\_\\____|"
  printf "\n%s%*s%s%s\n" "${RGB_GREEN}" "${ascii_margin}" "" "${l1}" "${RESET_COLOR}"
  printf "%s%*s%s%s\n" "${RGB_GREEN}" "${ascii_margin}" "" "${l2}" "${RESET_COLOR}"
  printf "%s%*s%s%s\n" "${RGB_BLUE}" "${ascii_margin}" "" "${l3}" "${RESET_COLOR}"
  printf "%s%*s%s%s\n" "${RGB_BLUE}" "${ascii_margin}" "" "${l4}" "${RESET_COLOR}"
  printf "%s%*s%s%s\n" "${RGB_ASCII_GREEN}" "${ascii_margin}" "" "${l5}" "${RESET_COLOR}"
  printf "\n%s%*s    %smacOS Tahoe • Forensic Extraction Tool%s\n" "${RGB_YELLOW}" "${ascii_margin}" "" "${ANSI_WHITE}" "${RESET_COLOR}"
}

# Repeats $1 exactly $2 times (UTF-8 safe).
repeat_char() {
  local ch="$1"
  local count="$2"
  local out="" i
  for ((i=0; i<count; i++)); do
    out+="${ch}"
  done
  printf "%s" "${out}"
}

# Centers $2 in a field of $1 characters (truncates if it exceeds). Emojis may misalign.
pad_center() {
  local width="$1"
  local text="$2"
  local len left right
  # Note: this assumes "simple" width (ASCII/UTF-8 without considering real emoji width, etc.)
  len="${#text}"
  if (( len >= width )); then
    printf "%s" "${text:0:width}"
    return 0
  fi
  left=$(( (width - len) / 2 ))
  right=$(( width - len - left ))
  printf "%*s%s%*s" "${left}" "" "${text}" "${right}" ""
}

# Single menu. $1=margin, $2=interior box width (52).
# Option lines use fixed padding to align the right border ║.
_print_menu() {
  local margin="$1"
  local menu_width="$2"

  local top="╔$(repeat_char '═' "${menu_width}")╗"
  local mid="╠$(repeat_char '═' "${menu_width}")╣"
  local bot="╚$(repeat_char '═' "${menu_width}")╝"

  printf "\n%s%*s%s%s\n" "${RGB_GREEN}" "${margin}" "" "${top}" "${RESET_COLOR}"
  printf "%s%*s║%s%s%s║%s\n" "${RGB_GREEN}" "${margin}" "" "${RGB_BLUE}" "$(pad_center 52 "FORENSIC EXTRACTION")" "${RGB_GREEN}" "${RESET_COLOR}"
  printf "%s%*s║%s%s%s║%s\n" "${RGB_GREEN}" "${margin}" "" "${RGB_SUCCESS}" "$(pad_center 52 "macOS Tahoe • v${VERSION}")" "${RGB_GREEN}" "${RESET_COLOR}"
  printf "%s%*s%s%s\n" "${RGB_GREEN}" "${margin}" "" "${mid}" "${RESET_COLOR}"
  printf "%s%*s║ %s[1]%s %sComplete Collection%*s%s║%s\n" "${RGB_GREEN}" "${margin}" "" "${RGB_YELLOW}" "${RGB_BLUE}" "${ANSI_WHITE}" 28 "" "${RGB_GREEN}" "${RESET_COLOR}"
  printf "%s%*s║ %s[2]%s %sComplete Collection With RAM (future)%*s%s║%s\n" "${RGB_GREEN}" "${margin}" "" "${RGB_YELLOW}" "${RGB_BLUE}" "${ANSI_WHITE}" 10 "" "${RGB_GREEN}" "${RESET_COLOR}"
  printf "%s%*s║ %s[Q]%s %sExit program%*s%s║%s\n" "${RGB_GREEN}" "${margin}" "" "${RGB_YELLOW}" "${RGB_BLUE}" "${ANSI_WHITE}" 35 "" "${RGB_GREEN}" "${RESET_COLOR}"
  printf "%s%*s%s%s\n" "${RGB_GREEN}" "${margin}" "" "${bot}" "${RESET_COLOR}"
}

# Entry point: main loop until [Q].
main() {
  forensic_require_root_at_start
  while true; do
    local terminal_width menu_width margin ascii_margin
    terminal_width="$(get_terminal_width)"
    menu_width=52
    # Center the box (52 cols); the logo uses extra margin (+8) relative to the box.
    margin=$(( (terminal_width - menu_width) / 2 ))
    (( margin < 0 )) && margin=0
    ascii_margin=$(( margin + 8 ))

    _print_logo "${ascii_margin}"
    _print_menu "${margin}" "${menu_width}"

    printf "\n%s[?] %sSelect an option %s(1, 2 or Q)%s: " "${RGB_BLUE}" "${ANSI_WHITE}" "${RGB_YELLOW}" "${ANSI_WHITE}"
    IFS= read -r option || true

    case "${option}" in
      1)
        clear_screen
        printf "\n%s╔═════════════════════════════════════════════════════╗%s\n" "${RGB_GREEN}" "${RESET_COLOR}"
        printf "%s║ %s🔍 COMPLETE COLLECTION%*s%s║%s\n" "${RGB_GREEN}" "${RGB_BLUE}" 31 "" "${RGB_GREEN}" "${RESET_COLOR}"
        printf "%s╟─────────────────────────────────────────────────────╢%s\n" "${RGB_GREEN}" "${RESET_COLOR}"
        printf "%s║ %s➤ 50+ forensic artifacts%*s%s║%s\n" "${RGB_GREEN}" "${RGB_SUCCESS}" 28 "" "${RGB_GREEN}" "${RESET_COLOR}"
        printf "%s║ %s➤ Automatic SHA-256 integrity%*s%s║%s\n" "${RGB_GREEN}" "${RGB_SUCCESS}" 23 "" "${RGB_GREEN}" "${RESET_COLOR}"
        printf "%s║ %s➤ Duration: 5-15 minutes%*s%s║%s\n" "${RGB_GREEN}" "${RGB_SUCCESS}" 28 "" "${RGB_GREEN}" "${RESET_COLOR}"
        printf "%s╚═════════════════════════════════════════════════════╝%s\n\n" "${RGB_GREEN}" "${RESET_COLOR}"
        forensic_execute_mode "Complete_Without_RAM" "Complete extraction without RAM dump (osxpmem)" "complete_without_ram"
        printf "\n%s╔═════════════════════════════════════════════════════╗%s\n" "${RGB_GREEN}" "${RESET_COLOR}"
        printf "%s║ %s✓ Extraction completed successfully%*s%s║%s\n" "${RGB_GREEN}" "${RGB_SUCCESS}" 17 "" "${RGB_GREEN}" "${RESET_COLOR}"
        printf "%s╚═════════════════════════════════════════════════════╝%s\n" "${RGB_GREEN}" "${RESET_COLOR}"
        printf "\n%s[*] %sPress ENTER to return to menu...%s" "${RGB_BLUE}" "${ANSI_WHITE}" "${RESET_COLOR}"
        IFS= read -r _ || true
        clear_screen
        ;;
      2)
        clear_screen
        printf "\n%s╔═════════════════════════════════════════════════════╗%s\n" "${RGB_GREEN}" "${RESET_COLOR}"
        printf "%s║ %s🔮 FUTURE MODE%*s%s║%s\n" "${RGB_GREEN}" "${RGB_ORANGE}" 39 "" "${RGB_GREEN}" "${RESET_COLOR}"
        printf "%s╟─────────────────────────────────────────────────────╢%s\n" "${RGB_GREEN}" "${RESET_COLOR}"
        printf "%s║ %sRAM memory dump (osxpmem)%*s%s║%s\n" "${RGB_GREEN}" "${ANSI_WHITE}" 27 "" "${RGB_GREEN}" "${RESET_COLOR}"
        printf "%s║ %sImplementation in development...%*s%s║%s\n" "${RGB_GREEN}" "${ANSI_WHITE}" 20 "" "${RGB_GREEN}" "${RESET_COLOR}"
        printf "%s║%*s%s║%s\n" "${RGB_GREEN}" 53 "" "${RGB_GREEN}" "${RESET_COLOR}"
        printf "%s║ %s→ Available in future versions%*s%s║%s\n" "${RGB_GREEN}" "${RGB_YELLOW}" 22 "" "${RGB_GREEN}" "${RESET_COLOR}"
        printf "%s╚═════════════════════════════════════════════════════╝%s\n" "${RGB_GREEN}" "${RESET_COLOR}"
        printf "\n%s[*] %sPress ENTER to return to menu...%s" "${RGB_BLUE}" "${ANSI_WHITE}" "${RESET_COLOR}"
        IFS= read -r _ || true
        clear_screen
        ;;
      q|Q)
        clear_screen
        printf "\n%s╔═════════════════════════════════════════════════════╗%s\n" "${RGB_GREEN}" "${RESET_COLOR}"
        printf "%s║ %sThank you for using Forensic-MAC%*s%s║%s\n" "${RGB_GREEN}" "${ANSI_WHITE}" 20 "" "${RGB_GREEN}" "${RESET_COLOR}"
        printf "%s║ %sSee you soon%*s%s║%s\n" "${RGB_GREEN}" "${RGB_SUCCESS}" 40 "" "${RGB_GREEN}" "${RESET_COLOR}"
        printf "%s╚═════════════════════════════════════════════════════╝%s\n\n" "${RGB_GREEN}" "${RESET_COLOR}"
        exit 0
        ;;
      *)
        printf "\n%s╔═════════════════════════════════════════════════════╗%s\n" "${RGB_RED}" "${RESET_COLOR}"
        printf "%s║ %s⚠ INVALID OPTION%*s%s║%s\n" "${RGB_RED}" "${ANSI_WHITE}" 36 "" "${RGB_RED}" "${RESET_COLOR}"
        printf "%s╟─────────────────────────────────────────────────────╢%s\n" "${RGB_RED}" "${RESET_COLOR}"
        printf "%s║ %sPlease select: [1], [2] or [Q]%*s%s║%s\n" "${RGB_RED}" "${ANSI_WHITE}" 22 "" "${RGB_RED}" "${RESET_COLOR}"
        printf "%s╚═════════════════════════════════════════════════════╝%s\n" "${RGB_RED}" "${RESET_COLOR}"
        printf "\n%s[*] %sPress ENTER to continue...%s" "${RGB_BLUE}" "${ANSI_WHITE}" "${RESET_COLOR}"
        IFS= read -r _ || true
        clear_screen
        ;;
    esac
  done
}

main "$@"

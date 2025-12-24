#!/usr/bin/env bash
set -euo pipefail

readonly SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
readonly TESTS_ROOT="$(cd "${SCRIPT_DIR}/../../.." && pwd)"
readonly OUT_DIR="${TESTS_ROOT}/_data/disk/vdi"

log()  { printf '[INFO] %s\n' "$*" >&2; }
warn() { printf '[WARN] %s\n' "$*" >&2; }
error()  { printf '[ERROR] %s\n' "$*" >&2; }

have() { command -v "$1" >/dev/null 2>&1; }

require_tools() {
    local -a tools=(qemu-img pigz xxd dd)
    local missing=0

    for t in "${tools[@]}"; do
        if ! have "$t"; then
            error "Missing required tool: $t"
            missing=1
        fi
    done

    if (( missing != 0 )); then
        error "One or more required tools are missing. Aborting."
        exit 1
    fi
}

pattern() {
    local size="$1"

    stream() {
        while true; do
            for i in $(seq 0 255); do
                printf "`printf '%02x' "${i}"`%.0s" {0..4095}
            done
        done
    }

    stream | xxd -r -ps | head -c "${size}" || true
}

generate() {
    local name="$1"
    local size="$2"

    local raw="$(mktemp -t raw.XXXXXX)"

    pattern "${size}" > "${raw}"
    # Create a hole at the start for testing sparse files
    dd if=/dev/zero bs=1M count=1 seek=0 of="${raw}" conv=notrunc

    local outpath="${OUT_DIR}/${name}.vdi"

    log "Converting RAW -> VDI (${name})"
    qemu-img convert -f raw -O vdi "${raw}" "${outpath}"

    log "Compressing ${outpath} -> ${outpath}.gz"
    cat "${outpath}" | pigz -c > "${outpath}.gz"

    log "Generated: ${outpath}.gz"
}

main() {
    require_tools

    mkdir -p "${OUT_DIR}"

    # TODO: Snapshots/differencing disks
    generate "basic" "$((10 * 1024 * 1024))"

    log "All test cases generated under: ${OUT_DIR}"
}

main "$@"

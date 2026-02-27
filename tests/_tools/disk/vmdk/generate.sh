#!/usr/bin/env bash
set -euo pipefail

readonly SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
readonly TESTS_ROOT="$(cd "${SCRIPT_DIR}/../../.." && pwd)"
readonly OUT_DIR="${TESTS_ROOT}/_data/disk/vmdk"

log()  { printf '[INFO] %s\n' "$*" >&2; }
warn() { printf '[WARN] %s\n' "$*" >&2; }
error()  { printf '[ERROR] %s\n' "$*" >&2; }

have() { command -v "$1" >/dev/null 2>&1; }

require_tools() {
    local -a tools=(qemu-img pigz dd)
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
    local options="${3:-}"

    local raw="$(mktemp -t raw.XXXXXX)"

    pattern "${size}" > "${raw}"
    # Create a hole at the start for testing sparse files
    dd if=/dev/zero bs=1M count=1 seek=0 of="${raw}" conv=notrunc

    local outpath="${OUT_DIR}/${name}.vmdk"

    log "Converting RAW -> VMDK (${name})"
    qemu-img convert -f raw -O vmdk -o "${options}" "${raw}" "${outpath}"

    # log "Compressing ${outpath} -> ${outpath}.gz"
    # for file in "${OUT_DIR}/${name}"*; do
    #     cat "${file}" | pigz -c > "${file}.gz"
    # done

    log "Generated: ${outpath}.gz"
}

main() {
    require_tools

    mkdir -p "${OUT_DIR}"

    generate "sparse" "$((10 * 1024 * 1024))" subformat=monolithicSparse
    generate "flat" "$((10 * 1024 * 1024))" subformat=monolithicFlat
    generate "stream" "$((10 * 1024 * 1024))" subformat=streamOptimized
    generate "split-sparse" "$((10 * 1024 * 1024))" subformat=twoGbMaxExtentSparse
    generate "split-flat" "$((10 * 1024 * 1024))" subformat=twoGbMaxExtentFlat

    # TODO: Generate some test data on ESXi

    log "All test cases generated under: ${OUT_DIR}"
}

main "$@"

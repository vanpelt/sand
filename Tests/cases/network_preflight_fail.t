#!/bin/bash
set -euo pipefail

source "$ROOT/Tests/lib/common.sh"

init_defaults
ensure_e2e_deps

# backend: softnet with a softnet in a user-writable directory (like Homebrew's):
# preflight P12 must refuse it before cloning anything, and sand must never run
# that binary or sudo against it.
workdir=$(mktemp_dir)
trap 'cleanup_dir "$workdir"' EXIT
mkdir -p "$workdir/bin"
cat >"$workdir/bin/softnet" <<EOF_SOFTNET
#!/bin/bash
touch "$workdir/softnet-ran"
echo "--allow  in [proto PROTO] [TARGET] [port PORT]; TARGET may be @host"
EOF_SOFTNET
cat >"$workdir/bin/sudo" <<EOF_SUDO
#!/bin/bash
touch "$workdir/sudo-ran"
echo "sudo: a password is required" >&2
exit 1
EOF_SUDO
chmod +x "$workdir/bin/softnet" "$workdir/bin/sudo"

runner=$(unique_runner_name)
config="$workdir/config.yml"
register_e2e_artifacts "$config"
cat >"$config" <<EOF_CONFIG
runners:
  - name: ${runner}
    stopAfter: 1
    vm:
      source:
        type: oci
        image: ${SAND_E2E_IMAGE}
      run:
        network:
          profile: github
          backend: softnet
          softnetPath: ${workdir}/bin/softnet
    provisioner:
      type: script
      config:
        run: echo "must never run"
EOF_CONFIG

set +e
output=$(PATH="$workdir/bin:$PATH" "$SAND_BIN" run --config "$config" 2>&1)
status=$?
set -e
assert_ne "0" "$status"
assert_match "Network preflight failed" "$output"
assert_match "P12 softnet path" "$output"
assert_match "install-managed-softnet.sh" "$output"
assert_eq "no" "$([ -e "$workdir/softnet-ran" ] && echo yes || echo no)"
assert_eq "no" "$([ -e "$workdir/sudo-ran" ] && echo yes || echo no)"
assert_eq "missing" "$(tart_vm_state "$runner")"

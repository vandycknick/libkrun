# Native execution-state diagnostic

`native-execution-probe` is an explicitly invoked, developer-only Linux x86_64
standalone target. Its feature is a diagnostic build exclusion, not a qualification
input. It never grants a live bit, creates a machine pause token, exposes a capture
C API, or bypasses a missing production provider. All native live bits remain false
through commit 5; public operations remain `not-delivered`.

The probe uses the production `Vmm`, `CpuController`, typed owner commands,
execution envelope codec, `ValidatedExecution`, and `build_restore_prepared`.
The fixture constructor has an **actually empty** legacy/virtio attachment inventory.
Its constant input bus callbacks complete real KVM IO/MMIO exits; they are not
successful substitute state providers. A fixture RAM copy is bounded to exactly
3 MiB, is never advertised as the production RAM image API, and does not qualify
private mapping, sharing, incremental capture, dirty coverage, reclaim or activation.
The restore constructor executes no cold-boot payload/FDT/register initialization.
The initial closed xstate witness is x87/SSE/YMM. Additional actual exposed xstate
components are a named unqualified profile, never hidden by CPUID suppression or
reported as exercised by a RAM sentinel. If the ordinary production profile
requires another component, its live workload/proof remains a local acceptance
blocker, not permission to substitute the fixture or declare that Linux gate done.

## Required evidence, not a reduced production gate

The assembly fixture proves only the CPU execution sub-barrier. It does not boot
Linux and deliberately leaves PIT unprogrammed. It cannot prove that the ordinary
production Linux kernel has retired PIT. The observed production kernel 7.2.2,
two online CPUs, `tsc`, per-CPU `lapic-deadline`, empty broadcast selection and
local timer interrupt progress were recorded separately in
`/home/nickvd/sm/silo-smoke-14o1a_79/evidence/phase09-guest-clock-inventory.log`.
Those observations do **not** establish the native PIT predicate, frozen PIT phase,
execution restore, or device-provider completeness.

The ordinary kernel's exact retired-PIT predicate and the complete production
execution/busy-device gates remain required. Do not replace them with this fixture
or a forced guest clocksource. `native_execution_linux.c` supplies a per-online-CPU,
affinity-pinned, live GPR/x87/SSE/YMM userspace workload for the ordinary Linux gate.
Its sentinels are seeded only once; the worker loops make no calls that could
spill/reload the sentinels. The reporting thread records real monotonic/boot-time
samples and sustained per-CPU progress. It does not alter kernel timer selection.
AVX eligibility is read from the actual guest's CPUID XSAVE/OSXSAVE/AVX bits and
XGETBV(0)'s x87/SSE/YMM enablement. Detection has no compiler CPU-model runtime
dependency; the existing live YMM sentinel workload is unchanged.

`native_execution_controller.py --production-driver <executable>` invokes an
actual production integration driver with the exact kernel and workload paths.
The driver must use commit 6's actual devices/providers, host-owned destination
bindings and normal boot path, not the CPU-only constructor. The controller
requires named observed witness records for normal kernel/native PIT admission,
original due/no-IRR and pending timers, pending-plus-future, masked/unmask,
in-service/EOI, offline/HLT, live xstate, IO/MMIO completion, long prepared dwell,
contemporary clocks, three fresh generations, source resume, partial install,
missing-provider refusal, busy block/net/vsock/console, balloon/RNG/legacy and
shared native IRQ behavior. An absent driver records these gates **pending**,
never passing. A supplied driver's failure fails the invocation. The extension is
not an authority to grant capabilities, and a JSON assertion alone does not replace
review of its raw native/guest observations.

Actual KVM arm64 and HVF arm64 runtime gates remain pending owner lanes. Linux
compilation and target-neutral codec tests do not prove those platforms.

## KVM arm64 source counter contract

Cold source construction establishes `KVM_ARM_SET_COUNTER_OFFSET` before creating
any vCPU, so physical and virtual guest counters share one epoch from the first
instruction. Fresh restore establishes the same policy before `VCPU_INIT`.
The saved VM record names this common-counter model explicitly; unknown model
tags are rejected rather than interpreted as the old, distinct native defaults.
KVM ignores subsequent counter writes through `SET_ONE_REG` after this policy is
set, so restoration never relies on those writes to repair an epoch mismatch.

Before fencing either timer, each source owner retains physical/virtual/physical
counter observations and verifies that the virtual sample lies within the
wrap-safe physical sampling interval. Sequential samples need not be equal.
The common cut uses the retained virtual sample of the first saved CPU. Final
preparation displaces both counter views together and replays the original
physical and virtual comparator/control values unchanged, preserving future and
already-due timer relations rather than translating one timer into another epoch.

The ARM owner gate must observe **both** counter views and **both** timer families
before capture, after same-source resume, and after fresh restore, including
prepared dwell longer than a future timer's residual. Counter displacement and
original due/future residuals must survive; virtual progress alone is insufficient.
That native gate remains **pending**. The x86-only standalone commands below
cannot exercise or qualify it.

Primary semantics: [KVM API section 4.138](https://docs.kernel.org/virt/kvm/api.html#kvm-arm-set-counter-offset)
and [Linux timer initialization and common-offset installation](https://github.com/torvalds/linux/blob/v6.18/arch/arm64/kvm/arch_timer.c).

## Main-only commands

Nothing listed here has been executed as part of the source handoff. Run from the
production checkout, after the integration owner has landed all slices. No Cargo
test may create a VM. Stop any individual command after five minutes; retained
runner timeout evidence is a failure, not a successful native reap.

Build the opt-in standalone target through the normal native build environment:

```sh
make native-execution-probe
```

Build the fixture outside Cargo tests, retaining the ELF and exact symbols:

```sh
mkdir -m 700 -p target/native-execution-inputs
cc -c -nostdlib -fno-pie -m64 -o target/native-execution-inputs/fixture.o src/libkrun/examples/native_execution_fixture.S
ld -nostdlib -Ttext=0x1000 -e _start -o target/native-execution-inputs/fixture.elf target/native-execution-inputs/fixture.o
objcopy -O binary --only-section=.text target/native-execution-inputs/fixture.elf target/native-execution-inputs/fixture.bin
nm -n target/native-execution-inputs/fixture.elf > target/native-execution-inputs/fixture.symbols
cc -O2 -pthread -static -o target/native-execution-inputs/native-execution-linux src/libkrun/examples/native_execution_linux.c
```

If the host C toolchain lacks static libc/pthread archives, an installed Zig
toolchain can provide the static musl build without a compiler CPU-model runtime:

```sh
zig cc -target x86_64-linux-musl -O2 -pthread -static -o target/native-execution-inputs/native-execution-linux src/libkrun/examples/native_execution_linux.c
```

Use the actual ordinary staged kernel file for `KERNEL`, not a replacement fixture
kernel. It is fingerprinted as provenance by CPU-only runs, not booted by them.
Each command below is a separate bounded gate invocation. Select both CPU counts
for every positive case except `offline`, which requires two CPUs:

```sh
python3 src/libkrun/examples/native_execution_controller.py \
  --probe "$PWD/target/debug/examples/native-execution-probe" \
  --fixture "$PWD/target/native-execution-inputs/fixture.bin" \
  --symbols "$PWD/target/native-execution-inputs/fixture.symbols" \
  --kernel "$KERNEL" --evidence "$EVIDENCE/cpu1-future" --cpus 1 --case future --dwell-ms 2000
```

Repeat with `--cpus 1` and `--cpus 2` and each `--case`:
`future`, `due`, `due-no-irr`, `masked`, `pending-future`, `in-service`, `io`,
`mmio`; then `--cpus 2 --case offline`. Use a fresh evidence directory for each
invocation. `due` requires an actual materialized original IRR cause with a zero
comparator. `due-no-irr` holds a real input callback while the original comparator
expires and requires the actual due nonzero comparator without IRR/ISR. If native
completion semantics produce another cut, that case fails rather than substituting
a timer or filtering the witness away. No fixture host wake/rearm is used to make
continuation pass. Masked delivery changes guest interrupt acceptance only.

Run `--case active-pit` and `--case count-lapic` separately for both CPU counts.
These genuinely program the unsupported native timers and require named refusal;
they are not skipped positive production-profile tests. Existing Phase 8's
active-PIT control-responsiveness probe remains separate and unchanged.

Every positive invocation runs source resume, an actual incomplete install
completion barrier, and three fresh-process restore/progress/recapture generations.
The incomplete-construction case holds the last owner's **real successful native
Installed ACK** past a 200 ms absolute deadline. The constructor must fail while
retaining the actual attempt, with no accepted Release and unchanged RAM, then
stop/reap through the same journal. This is an actual native-completion timeout,
not a fabricated setter error or proof of a short native MSR transfer. Known
malformed state must still reject before construction; no validation hole is
introduced to make the failure gate possible. The original source is
stopped/reaped before the first destination process is launched. Each prepared
dwell exceeds the original 500 ms future sleep; final common preparation must
preserve its residual guest time. A retired ancestor CPU payload cannot pass the
child recapture comparison. The offline AP is actually started by guest INIT/SIPI
after the first restore, so subsequent generations correctly capture live CPUs.

Only after the original timer/IO cause has passed its exact-once oracle, the guest
starts new sustained work: 10 ms deadline sleeps plus actual IO and MMIO inputs.
Every online CPU must finish at least ten of each during the observation window.
This later workload cannot repair a lost original cause: it begins after that
assertion. Its sentinels remain live and are never reseeded. Recapture first asks
the guest to stop that new workload, then captures a separately programmed
original future/pending/masked/in-service cause for the next generation.

Invoke the production extension once its actual driver is available, adding:

```sh
  --production-driver "$PRODUCTION_DRIVER" \
  --linux-fixture "$PWD/target/native-execution-inputs/native-execution-linux"
```

`PRODUCTION_DRIVER` receives `--evidence <dir> --kernel <path>
--register-fixture <path> --execution-completeness --busy-devices`.
The required result is schema 1, `scope: whole-machine-production`,
`status: passed`, `all_reaped: true`, `qualification_eligible: false`,
`native_pause: false`, with exactly the named `witnesses` keys in the controller's
`production_extension` function. Every witness has exactly `status: passed` and
`observations: [{path, bytes, sha256}, ...]`. Paths are relative regular files
inside the driver's evidence directory; the controller independently checks
lengths and digests. Each witness has 1–64 observations, each at most 16 MiB,
with at most 64 MiB of unique observed bytes overall. These are retained native
and guest facts, not a boolean substitute for them. Commit 6 admission is a
separate reviewed decision, not a driver flag or generated JSON value.

## Pure test filters

These audited filters call only argument/closed-case validation, JSON escaping,
bounded `GuestMemoryMmap` copying and actual private regular-file/FIFO checks.
None calls `run`, opens KVM, constructs a VM, starts a CPU thread or requires a
kernel/init image:

```sh
cargo test --locked -p libkrun --features native-execution-probe --lib native_execution_probe_closed_cases_and_bounds
cargo test --locked -p libkrun --features native-execution-probe --lib native_execution_probe_json_escapes_native_errors
cargo test --locked -p libkrun --features native-execution-probe --lib native_execution_probe_fixture_ram_copy_preserves_boundaries
cargo test --locked -p libkrun --features native-execution-probe --lib native_execution_probe_fixture_files_are_bounded_private_and_regular
```

Main separately runs the common/backend owners' audited pure filters, formatting
and strict native Clippy. Never run wholesale libkrun tests as a hypervisor-free
gate: unrelated existing tests construct VMs.

## Evidence schema and ownership

All generated evidence is private (directories 0700, files 0600), exclusively
created, and retained on failure. The controller records each exact command,
exit status, duration, stdout/stderr, executable/fixture/symbol/kernel SHA-256,
host kernel and relevant actual KVM acceleration parameters. PID observations
must identify distinct source/destination processes.

Each captured generation contains:

- `execution.state`: actual production bounded canonical codec bytes, including
  exact native package/source/build facts, ABI/profile/cut/topology/RAM bindings,
  effective CPUID, complete raw/classified MSR inventory and values, MCG_CAP,
  full dynamic XSAVE extent/component layout, GPR/special/debug/events/MP state,
  original deadlines, LAPIC, PIT, PIC/IOAPIC and common source clock tuple.
- `native-inventory.txt`: a complete typed debug rendering of that same actual
  state, not a second codec or substituted inventory.
- `memory.fixture`: exactly the stopped fixture's bounded RAM, after native
  controller/CPU capture. This is not a production RAM-image format.
- `capture.json`: scope, case, CPU count, strict malformed/profile/producer/
  missing-participant refusals, repeated capture equality and a real exclusive
  output failure followed by equality-preserving recapture.
  MSR batch counts are explicitly labelled **derived from successfully checked
  native transfers, not a raw return ledger**: the production getter checks the
  actual requested/completed equality before returning each bounded vector.
  State/model vectors are chunked at 256; MCG_CAP, TSC and deadline GETs each
  check one entry. Native short-transfer failures retain their real requested/
  completed/first-missing-index error. No short-transfer failure is invented.
- Source `withheld-capture-ack.txt`: the actual typed owner ACK held past the
  common deadline, including native failure details when capture fails. Success
  requires matching CPU/request/key and retained payload; the same journal
  reconciles it before release. No fabricated successful ACK.
- Source `vm-capabilities.json`: actual VM XSAVE2 extent and deadline support.
- Controller generation manifests record every object size and SHA-256; an actual
  failed partial destination install must leave the source manifest unchanged.

Each successful process record additionally carries actual preparation key/plans
and the same source/destination paired clocks used by native time preparation,
final preparation latency, original future residual, real original IRQ/arm counts,
sustained progress, contemporaneous BSP/AP/BSP TSC bracket (normalized by the
saved offset difference, never independently stale RAM fields), and completed
stop/reap. A failed fresh install retains its actual VM/owner handles until stop
and reap; the accepted-Release ledger must remain false before any first entry.
Partial install never falls back to boot. Prepared construction checks both that
ledger and unchanged RAM through dwell. Failure records preserve cleanup outcome;
process timeout explicitly does not claim native cleanup acknowledgement.

The shared target-neutral KVM/HVF schema remains production code, not probe-owned
state. KVM time admission uses the exact unscaled common TSC relation, with no
ordinary `IA32_TSC` replay; the original future/due/masked/pending comparator is
reinstalled after the absolute offset and LAPIC. Reset/qualified retired PIT state
is fully inventoried and natively fenced; active/unclassified PIT and unqualified
count modes refuse by name. The production Linux retired-PIT predicate remains
unproven until the normal-kernel gate actually establishes it.

Linux x86_64 diagnostic execution has passed all 21 prescribed cases: eight
positive cases and two timer-refusal cases at each CPU count, plus the two-CPU
offline case. Evidence is retained under `target/phase09-evidence/`: CPU1
`future-03`, CPU2 `future-02`, and attempt `01` for the other cases.
Earlier failed attempts remain retained. These results do not qualify the
ordinary Linux guest profile, device providers, or any public live operation.

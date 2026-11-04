# Native execution-state diagnostic

`native-execution-probe` is an explicitly invoked, developer-only Linux x86_64
standalone target. Its feature is a diagnostic build exclusion, not a qualification
input. It never grants a live bit, creates a machine pause token, exposes a capture
C API, or bypasses a missing production provider. Diagnostic builds remain excluded
from native availability. Commit 6 enables the implemented native pause primitive
in supported normal builds; public operations remain `not-delivered`, and unrun
lanes remain pending qualification.

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

Fixture RAM is raw only during bounded cold loading. Once constructed, every
runtime fixture read/write uses the production `RuntimeGuestMemory` domain.
The existing execution coordinator closes and drains ordinary writers before
native save, retains native-effects authority through terminal CPU ACKs, then
seals, harvests and rearms the cut. Resume reopens that domain before preparation
and fixture seed writes, which belong to the next epoch. CPU resources and
accepted commands retain the domain and VM backing even when cleanup fails.
The probe reports a cleanup deadline as failure, never as successful reap.
These ownership rules do not turn `memory.fixture` into a baseline or production
RAM image, and grant no additional qualification.

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

### KVM-TSC-DEADLINE-EARLY: non-blocking host limitation

Only the absolute no-early TSC-deadline delivery requirement is non-blocking.
The whole-machine check still samples every future/halted, pending-plus-future
and masked-future continuation on both source and destination. It retains the
unchanged original comparator `D`, actual ISR TSC, wrap-safe signed
`ISR_TSC - D` in ticks, TSC rate in kHz, host release/version, case and
source/child linkage, plus the original and coherent delivery snapshots.
Negative deltas are explicitly `known-host-limitation`; nonnegative deltas are
`not-observed`, not proof that the host can never deliver early.
The closed `absolute_timer_delivery` witness has status `observed-not-gating`,
never `passed`, and uses the same bounded, digest-bound artifact collection as
the other witnesses. Overall `passed` means the remaining blocking assertions
completed, not that the absolute timing requirement passed.

The tracked evidence is `target/phase09-evidence/timer-traced-01`: 16/16 early
source-only deliveries without intervening reconstruction, with full exact
MSR/IRQ trace. The [upstream discussion](https://lkml.rescloud.iu.edu/2312.2/06707.html)
is contextual evidence, **not** a filed matching bug or a fixed-version
announcement. No corruption or application failure was observed; that is not
a claim of no possible application impact. Do not use a custom host kernel,
host timer tuning, a guessed fixed-version cutoff, comparator rewriting or
synthetic IRQs to hide the observation.

Revisit **KVM-TSC-DEADLINE-EARLY on 2026-12-01 and on host kernel updates**:
retain host revisions and repeat the same source-only and restored exact
MSR/IRQ observations, compare signed deltas and check upstream evidence before
changing the exception. Restore strict gating only with an explicit reviewed
policy change supported by that evidence.

All other gates remain blocking: coherent publication, exact original
comparators, exact interrupt/EOI counts, native cause restoration, clock/offset
relationships and positive residual/preparation bounds, isolation, continuation,
and cleanup/reap. The CPU-only diagnostic has no absolute ISR-versus-comparator
oracle; its wrapper reports this requirement `not-measured` and retains the
existing coarse residual/dwell and all other checks. The ordinary provider-cycle
wrapper also reports `not-measured`. Neither result establishes this timing
requirement. Phase 9 remains incomplete until its remaining gates actually run.

Main can run the host-independent policy regression tests with:

```sh
python3 -m unittest discover -s src/libkrun/examples -p 'test_native_device_execution.py'
```

Then run the closed whole-machine invocation below with fresh evidence and the
existing exact production inputs; the implementation agent does not run gates.


## KVM memory tracking and native effects

The Linux backend retains each successful RAM registration, including its full
address-space/slot ID, original flags and backing lifetime. Construction binds
these records to the common memory domain. Source arming allocates every slot
bitmap before enabling ordinary `KVM_MEM_LOG_DIRTY_PAGES` on the exact retained
registrations, preserving other flags. The explicit tracked restore initializer
preallocates all records and buffers, registers every slot with logging enabled
from its first registration, and returns the initial epoch before execution
installation, not merely before the first `KVM_RUN`.

Exported VM descriptor owners retain the registered backing and bound domain,
including while an asynchronous IRQ-route worker outlives a failed VMM owner.
vCPU constructors retain that same owner before their native descriptors can
escape. The final VM descriptor closes before the retained backing is released;
ordinary Stop completion is not the lifetime guarantee.

Native execution commands require the domain's native-effects authority through
their terminal acknowledgment. In particular, `SET_MSRS` can write guest RAM via
the KVM PV wall-clock MSRs. A failed or short native operation is not proof that
RAM was unchanged; coverage is invalidated without discarding known dirty bits.
CPU command journals retain the terminal result, not the completed authority.

Final CPU harvest follows all native save operations and ordinary writer drain.
It uses fixed, exact-size slot buffers, immediately retaining each result in the
common dense page map, including non-word-aligned region starts and masked
padding. An entered failing `GET_DIRTY_LOG` loses coverage even when a later
retry might return no bits. The backend does not retry it, clear retained
dirties, or accept a baseline. Successful ordinary GET already reprotects the
slot; rearm only consumes its exact cut/epoch witness without another ioctl.
Tracked registrations cannot be replaced or exported as an untracked mapping.

These are implementation invariants, not native qualification evidence. Pure
slot/bitmap regressions require no KVM. Main must separately exercise every
actual slot, repeated writes across accepted generations, partial-harvest
retention, and restore-time wall-clock writes before any guest entry.

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
retaining the actual attempt, with no accepted Release and this CPU-only
fixture's unchanged RAM observation, then stop/reap through the same journal.
This is an actual native-completion timeout,
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

Each CPU-only subprocess has an explicit 120 s aggregate watchdog. The complete
production driver has a separate 600 s aggregate watchdog, matching Main's
standalone driver watchdog: the retained direct scenario alone takes 207–235 s
before all pressure cases. These are harness scheduling bounds, not native
operation or timing oracles. Native requests remain bounded at 5 s and pressure
reads at 30 s; their original deadlines are unchanged.

On timeout, the Linux diagnostic controller first sends SIGINT only to its owned
driver, allowing Python `finally` blocks to close native/netd resources. It gives
that unwind at most 120 s of cleanup-only grace, allowing multiple nested existing
per-session waits (10 s native reap, 15 s netd terminate, 5 s netd forced reap),
without changing any of those waits or the 10 s native stop deadline. It then
SIGKILLs remaining members of the owned group and bounds the controller's final
reap at 10 s. This grace is additional cleanup time after the aggregate watchdog,
not extra time to complete an operation successfully.

Ownership comes from `Popen(start_new_session=True)`: the actual driver PID is
the new session and process-group leader, and current native/netd spawn paths
inherit that group without detaching. Only that group is force-signalled, never
the invoking shell's group or PIDs found by scanning. `waitid(WNOWAIT)` observes
the leader's graceful exit without reaping it, reserving its PID/PGID until after
the final group signal, including when descendants outlive the controller.
Descendants that deliberately detach are outside this current driver contract.
Invocation evidence separately records observed graceful leader exit, group-kill
delivery, final leader reap/status and any cleanup errors. None establishes a
native cleanup ACK or descendant reap: timeout remains failure with
`native_cleanup_acknowledged: false`, even if the interrupted controller exits 0.
The real-subprocess regressions exercise both a controller's `finally` cleanup
and a surviving descendant's actual socket lifetime, without native devices:

```sh
python3 -m unittest discover -s src/libkrun/examples -p 'test_native_execution_controller.py'
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
Partial install never falls back to boot. This CPU-only fixture also checks
unchanged fixture RAM through dwell; that observation is not a generalized
production no-entry criterion. Failure records preserve cleanup outcome;
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

## Device-provider witnesses and qualification boundary

The commit 6 provider work reuses the production transport queue escrow,
`VirtioStateProvider`, barrier journal and execution construction barrier.
Provider payloads have one checked framing prefix (version, virtio kind, offered
and acknowledged features); transport records remain the sole queue-state
encoding. Destination resources are actual caller-constructed device objects.
No artifact field selects a host path or reuses a source endpoint descriptor.
Source pause is reversible and is not virtio reset.

The following are source-level regression selections for Main, **not results**.
They exercise real anonymous guest memory, Raw files, eventfds and socket/pipe
endpoints, not a native VM. They do not qualify KVM IRQ delivery or a live lane.

```sh
cargo test --locked -p krun-devices --features blk --lib block_provider_
cargo test --locked -p krun-devices --features blk --lib discard_zero_range_
cargo test --locked -p krun-devices --features blk --lib write_zeroes_zero_range_
cargo test --locked -p krun-devices --features blk --lib disk_image_id_
cargo test --locked -p krun-devices --features net --lib net_provider_
cargo test --locked -p krun-devices --lib console_provider_
cargo test --locked -p krun-devices --lib console_output_
cargo test --locked -p krun-devices --lib provider_rng_
cargo test --locked -p krun-devices --lib provider_balloon_
cargo test --locked -p krun-devices --lib lifecycle_callback_
cargo test --locked -p krun-devices --lib lifecycle_rng_partial_dma_
```

### Raw block

The raw provider retains the actual worker handle and backend until completion.
Its acquisition gate serializes pause admission closure with the real queue
pop, without holding that gate over disk I/O. An acquired request must finish
its backend effect, final status byte, actual writable used length, used-ring
publication and required interrupt notification. A parse, publication or
notification fault remains sticky even when the write has already reached the
disk; it cannot be made coherent by rewinding or replaying the request.
Ordinary backend I/O errors complete with `VIRTIO_BLK_S_IOERR` and the required
used-ring/interrupt publication; they do not stop subsequent queue service.
The backend failure remains sticky on worker handback so capture and terminal
drain cannot certify success after a failed request, even if a later flush succeeds.
For a failed read, imago cannot report partial DMA: used length is conservatively
zero, without zero-filling or claiming valid read data. Other backend failures
publish the status byte. The [split-ring used-length contract](https://github.com/oasis-tcs/virtio-spec/blob/master/split-ring.tex)
explicitly permits underestimates when error-path write progress is unknown.
Adopted write-only/read-only Raw backing regressions exercise actual
`preadv`/`pwritev` rejection with `EBADF`, status, used ring, IRQ, subsequent
successful I/O, and sticky failure on owner handback.
Available-but-unpopped work stays in the original queue and is explicitly
rescanned on source resume without requiring another kick.
Sized but unready queues must not pop, DMA or update notification fields; the
block rescan regression compares the complete guest-memory contents around it.

Pause and serialization do not flush. The separate cut-bound
`flush_for_capture` checks raw `flush` followed by `sync`, including when guest
FLUSH is suppressed by `CacheType::Unsafe`. A durability failure retains the
completed pause and does not certify a disk seal. Read-only bindings have no
writable backing to synchronize. Copying, synchronizing and publishing the
immutable disk cut remain the capture coordinator's responsibility.

The bounded raw record includes exact byte length, capacity/configuration,
read-only mode, serial, offered/acknowledged features, configured disk ID and
cache/direct-I/O/sync profile. A destination validates its trusted already-open
raw binding and adopts the captured serial, rather than deriving a new serial
from the destination inode. Installation starts no worker and performs no queue
scan, DMA or IRQ. DISCARD and WRITE_ZEROES with UNMAP retain zero-read semantics,
including non-aligned edges and reopened file capacity.

The block regressions cover actual write/read/guest FLUSH, final status and used
length, notification, a real saturated eventfd, invalid used-ring publication
after a performed write without replay, malformed/no-status chains, checked
sector overflow, an actual request held immediately after pop while admission
closes, original queue/backend identity across lost-kick resume, exact resource
refusals and dormant serial adoption. The capture-failure regression poisons
the actual backend lock; it proves checked error propagation and retained pause,
not that a real filesystem `fsync` failure has been exercised.

### Other provider boundaries

- Managed Unix-datagram net retains both original source queues and deferred
  source RX. Destination activation fencing is distinct from pause: both
  directions drop traffic, and explicit correlated release must discard queued
  fenced traffic before fresh delivery. Tests select actual datagrams, worker
  escrow/lost-kick resume, deferred RX, publication faults, exact MAC/resource
  validation and inactive endpoint fencing. TAP and Unix-stream attachments are
  not admitted by a generic net-device match.
- Native mux vsock must retain all three queues, including EVQ, and park actual
  mux/reaper/timesync owners. Source sessions/FDs survive reversible pause.
  Fresh destination mux/control resources admit only the explicitly bound
  agent-control service until activation release; old sessions are not copied.
  TRANSPORT_RESET is a real guest event, remains pending under EVQ starvation,
  and cannot be replaced with MMIO reset or destructive control failure fencing.
- Console regressions select real sockets/pipes and partial output ownership,
  every input/output/absent/unopened direction queue, and ordered pending
  control state. Fresh endpoints must neither replay accepted output nor
  regenerate the initial guest handshake during dormant install.
- Balloon preserves all five queue/configuration states, leaves unpopped stats
  work queued and invents neither a held stats owner nor a polling timer.
  Restored host reclaim stays permanently disabled without altering negotiated
  features. RNG has explicit bounded framing, fresh host entropy and
  chunked partial DMA accounting; it cannot rewind a partially written head and
  also publish its completion.

### Required whole-machine production observations

The standalone production driver, not these pure selections, must record all
of the following with exact native/kernel/profile/topology/process identities:

1. Busy multi-vCPU raw reads/writes/guest FLUSH, managed datagram RX/TX,
   multiport console, mux control/credit/session traffic, RNG, balloon and every
   attached legacy/IRQ/maintenance producer. Include an already-owned request,
   an unpopped head with a consumed kick, stimulated paused host ingress and
   per-participant queue/effect ownership. Guest heartbeat silence alone is
   insufficient.
2. Exact-token source continuation without reboot, renegotiation, lost or
   duplicate numbered work; actual incomplete drain/deadline/late result and
   accepted-wake-failure reconciliation; reversible cancellation or actual
   stop/reap when effects are uncertain. Stop while paused must not resume or
   inject guest-visible shutdown input.
3. Checked multi-disk durability before the immutable copies; numbered disk
   records correlated with the captured memory cut; nonzero/wrapping queue
   cursors and pending IRQ state. Restore into fresh processes/resources with
   unchanged capacity/read-only/serial and no duplicate write/output, then
   continue sustained I/O, recapture the child and independently resume the
   source. A failed reopen/install has no first guest instruction or endpoint
   release.
4. Source mux streams survive pause; child streams reset/reconnect through
   actual EVQ transport-reset delivery, including EVQ starvation. Only the bound
   agent service crosses the activation fence. Partial control/FD transfer,
   credit pressure, accepted sessions, reaper expiry and timesync parking need
   actual owner evidence, not merely a fenced control socket.
5. Unique packet IDs in both directions during prepared restore and activation:
   no guest delivery/send through the fence, no delayed fenced backlog after
   release, correct destination MAC/socket/reservation and no source-address
   delivery. Pure socketpair behavior does not qualify managed netd integration.
6. Simultaneous completions on shared native IRQ lines, independent device ACK,
   one actual route registration per shared line, pending-versus-delivered
   causes without blind IRQ replay, legacy sink UART/controller coverage and
   surviving-member progress. Unknown/unsupported devices, raw formats,
   resource mismatches and malformed cut/profile/attachment records refuse by
   exact identity before mutation or first instruction.

The ordinary virtio-console fixture configures no primary legacy console.
Its actual sink UARTs are COM2, COM3 and COM4; COM1 is attached only when a
legacy console is configured. The independent COM1 IRQ event registration
does not create a bus device or a missing UART payload. The original PIO
witness uses the attached COM3 scratch register.

These device gates and the ordinary production passive-PIT profile observation
remain required. Source implementations, unrun selections and the 21 CPU-only
diagnostic cases do not establish them. Full RAM-image/dirty/reclaim sharing
qualification belongs to later phases. Actual KVM arm64 and HVF runtime remain
pending their owner lanes; public live operations remain not delivered.

## Ordinary-kernel, real-provider standalone driver

The `native-device-probe` executable is a separately invoked driver. Both
controller modes require the existing `native-device-witness-probe` build target:
ordinary `blk,net` providers plus the `native-device-probe` diagnostic observation
feature, not fake devices or an unprogrammed-PIT fixture. It uses ordinary
`VmmBuilder` cold construction only
for the source. Fresh generations go through `ValidatedExecution`,
`ValidatedDevices`, actual destination resource bindings and
`build_restore_prepared`; that path does not load a kernel/initramfs or perform
boot writes into restored RAM.

Build and run these commands explicitly from this checkout. They have not been
run by the implementation agents:

```sh
make BLK=1 NET=1 native-device-witness-probe
cc -O2 -pthread -static -o /absolute/private/native-device-linux \
  src/libkrun/examples/native_device_linux.c
cc -O2 -pthread -static -o /absolute/private/native-execution-linux \
  src/libkrun/examples/native_execution_linux.c
python3 src/libkrun/examples/native_device_controller.py \
  --probe target/debug/examples/native-device-probe \
  --netd /absolute/path/to/the/actual/silo-netd \
  --guest-init /absolute/private/native-device-linux \
  --kernel /absolute/path/to/the/ordinary/production/vmlinux \
  --register-fixture /absolute/private/native-execution-linux \
  --evidence /absolute/fresh/private/evidence-directory
```

Supply the actual Silo netd executable and ordinary production ELF kernel.
There is no socketpair substitute for netd, external dependency installation,
SDK build, PIT reset, guest CPUID reduction or reduced network feature mask.
The offered network offloads match Silo's current production compatibility
mask. The exact native producer binding must be available in the build; an
incomplete/dirty producer observation is a refusal, not a diagnostic fallback.
Follow Main's existing clean-source build/binding procedure.

The controller creates two new bounded 128 MiB raw files and runs
`mkfs.ext4` on those new files only. They are mounted by the actual guest, never
by the host. PID 1 runs numbered cached file writes/reads and real guest flushes,
host-entropy reads, free-page reporting pressure, input-only/output-only console
ports and an unopened absent-direction port, UDP echo through the actual netd
reservation and concurrent native-mux vsock echo listeners. The existing live
GPR/SIMD/x87 register workload runs as a separate guest process. Extra **real**
RNG attachments put the busy block/net/vsock/balloon devices on the final shared
virtio IRQ line; all those attachments remain in the captured inventory.

The controlled standalone x86 guest sets
`/sys/module/page_reporting/parameters/page_reporting_order` to `0` before
starting allocation churn. It retains the actual original setting and checked
readback in `page-reporting-order-original` and `page-reporting-order` guest
observations; missing, unreadable, unwritable, or mismatched settings fail setup.
This is guest fixture configuration, not host tuning or a production default.
Linux otherwise defaults to pageblock-order reporting and skips smaller free
blocks; ordinary 32 MiB mmap/touch/munmap churn does not guarantee such blocks.
The `report` counter counts completed allocation/free iterations, not reports.
Actual source reporting and new destination used entries remain mandatory;
no allocation counter substitutes for queue progress, and restored private RAM
host reclaim remains disabled.

`/dev/hwrng` multiplexes the kernel's selected provider; its pathname and growing
read counter do not prove `rng0` queue progress. The controlled guest cycles every
advertised `virtio_rng.N` provider, bounded by the eleven actual RNG attachments
(`rng0` and ten IRQ-line padding devices). It verifies the exact selected name
before and after each complete 4096-byte read, handles short reads and EINTR, and
keeps selection stable across that read. This exceeds the actual kernel's small
shared hwrng and per-virtio caches; changing selection alone does not clear the
shared cache. No attachment is removed and no Linux IDA index is assumed to map
to native `rng0`.

Each retained guest profile includes `rng-initial`, `rng-current`, `rng-available`,
`rng-selected`, `rng-node`, and `rng-virtio-device`. These record the pre-workload
selection, current sysfs selection, available providers, explicit-selection state,
opened character-device major/minor checked against sysfs, actual virtio RNG
device/driver paths, and completed read bytes per provider. The device-path
inventory is not a guessed positional provider-to-MMIO mapping. The native
source/destination `rng0` used-ring progress requirement remains unchanged and
is still mandatory; guest read counters do not substitute for it.

Actual same-boot `/proc/version`, clocksource, both online clockevents,
broadcast-clockevent, interrupts, modules and speaker-consumer observations
come back through the real console. `RetiredLinuxPit` is admitted only from those
observations. The actual native PIT/controller predicate still runs at the cut
and may refuse. No successful ordinary PIT observation is inferred from the
earlier CPU diagnostic.

The native driver owns each inherited PTY/input/output/datagram/mux descriptor.
Destination descriptors, netd processes, sockets and endpoint names are new;
artifact bytes never select host paths or descriptors. Console input and output
directions have separate real endpoints. The controller retains endpoint
ownership through activation release, including an inactive/unready endpoint.
The destination uses the explicit network MAC binding and vsock service 1027;
host reclaim is disabled independently of saved balloon feature bits.

The controller exercises a completed source pause, repeated capture under
continued endpoint/SIGWINCH stimulation, checked raw flush/sync and private
read-only copies, source continuation, a consumed-token refusal, actual console
backpressure with failed-Pausing cancellation, and three independently constructed
fresh-process generations with prepared dwell, real transport reset/reconnect,
activation-fenced network operation, continued numbered work and child recapture.
Each new child cut has a new caller-owned run/capture binding. A final ordinary
generic-datagram configuration proves exact `net0` refusal before any CPU
transition, while its normal cold execution and terminal shutdown remain usable.
The negative configuration first observes and admits its actual clock/PIT profile,
just like a positive source, so an unrelated missing-profile refusal cannot stand
in for the named unsupported network participant.
Both baseline and closed execution then leave the actual console output endpoint
undrained and use the shared `Session.blocked_console_stop()` helper. Its existing
`prepare_blocked_console()` requests a guest burst and observes the real `hvc0`
port 2 owner: retained unfinished worker, open admission, a blocked descriptor
head and positive write remainder. `blocked-console-readiness.json` retains that
owner, the native snapshot path, timestamps and a non-consuming output peek.
Only after this observation does the helper issue the existing native `stop`
once, with its unchanged ten-second deadline. Output pumping stays disabled
through native exit/reap; a second non-consuming peek and unchanged output-log
byte count demonstrate that reader draining did not unblock shutdown.
`blocked-console-stop.json` retains preparation, stop timing, the actual
`native-stop.json` result, native reap status and any failure. Baseline generation
records include this proof; the closed `unsupported_participant_named` witness
also binds preparation, the actual blocked-owner snapshot, stop proof, native
stop result and process identity. Success still requires zero native exit status
and the controller's all-session cleanup gate; a forced process kill cannot pass.

This is destructive terminal shutdown coverage, not a reversible pause shortcut.
Only terminal shutdown/reset may interrupt the blocked TX owner. Reversible
close/quiesce/cancel must preserve and drain accepted output before acknowledging
pause/capture. The earlier failed-pause/cancel and byte-conservation proofs are
unchanged. The terminal witness does not retry stop, extend its deadline, drain
output to manufacture completion, or synthesize an owner acknowledgement.

Raw logs, native participant/queue/IRQ journals, ordinary guest observations,
exact inputs and capture manifests remain in the evidence directory. Failed
evidence is not removed.

RAM transfer here is bounded standalone copying of the actual completed cut,
not delivered RAM capture, sparse images, private-map sharing, dirty tracking
or reclaim qualification. The host ext4 prerequisite from Phase 7 is separate
and is not waived by mounting ext4 inside this guest.

The driver accepts commands on its separate standard-input control channel:
`profile DIRECTORY`, `preflight`, `pause`, `status`, `state`, `capture DIRECTORY`,
`resume`, `cancel ORIGINAL_OPERATION`, `release`, `activate` and `stop`.
Errors retain the real fenced operation so the controller can cancel or stop.
`status` reports the actual CPU release journal, retained time plans and owned
participant/IRQ inventory. Prepared release is an internal request on the
existing whole-machine journal, with final time/controller preparation before
routes/devices and CPUs last. It does not weaken the CPU-only release guard.
Failed fresh installation reports whether an actual Release was accepted and
retains the attempt until real stop/reap or process termination/reap.

Destination `activate` retains one operation, saved pause generation and original
five-second deadline across resource and worker readiness contention. Before a
provider accepts its begin, only actual transport `WouldBlock` or an explicitly
unaccepted `LockBusy` remains pending. Each accepted begin is issued once, even
if another resource stays busy. An accepted begin failure remains terminal and
provider-owned; it is not retried. The driver drops guards before dispatching
events and distinguishes poisoned transport locks from ordinary contention.

After acceptance, net and vsock providers keep that exact request and classify
their own contended readiness reads as `Poll::Pending`, not a failed activation
or a new begin. Poison, worker failures, invalid state, foreign keys and expiry
remain errors; real provider faults stay retained for terminal cleanup. A
completed exact-key acknowledgement is terminal, and the driver stops polling
that provider while others remain pending. It checks the unchanged aggregate
deadline before new effects and before reporting `OK activate`, including when
the final provider becomes ready after expiry. Failures retain the original
effects and existing explicit stop/process-reap cleanup; they do not reverse a
release that may already have run.

Vsock's accepted resume, which precedes destination activation, follows the
same readiness rule at both preflight boundaries and the worker-running read.
Only actual contention stays pending under its original journal key/deadline;
the provider neither reissues begin nor clears accepted queues. Its completed
exact-key Running acknowledgement remains terminal. Poison, expiry and other
real failures stay in the original resume journal for reconciliation/cleanup.

`target/phase09-evidence/whole-machine-timer-exception-06` remains failed:
`execution-mmio-child/driver.log:6` and `provider-report.json:9` record
`ERROR activate activation poll: LockBusy`. The provider path was vsock's
post-acceptance preflight reading its actual contended worker-control mutex.
This readiness correction and its real-lock provider regressions do not
qualify that recorded run or grant capabilities. A subsequent Main-owned
whole-machine run must still satisfy every original oracle and cleanup check.

Main-only provider regression selections, using `krun-devices` with
`blk,net,native-device-probe`, are `provider_vsock_activation_owner_`,
`provider_vsock_resume_owner_` and
`net_provider_activation_retains_request_across_owner_contention_and_terminals`.
They exercise real workers, Unix mux/datagram resources and contended owner
locks, including terminal poison/deadline and exact-key completion. The
implementation agents did not run them.

`provider-report.json` from the ordinary provider-cycle command reports that
command's exercised assertions only. The separate execution-completeness mode
below supplies the older controller's closed production-extension contract.
Neither mode grants native pause or qualification. New runtime observations
remain unverified until Main actually executes and reviews them. KVM arm64 and
HVF runtime remain pending their owner lanes.

### Closed whole-machine execution extension

The old extension invocation is unchanged:
`--evidence DIRECTORY --kernel KERNEL --register-fixture EXECUTABLE
--execution-completeness --busy-devices`. The executable is still
`native_device_controller.py`; `native_device_execution.py` is its orchestration
adapter, not a second native controller. Additional prebuilt prerequisites use
the existing `NETD_BIN` convention and paths beside the supplied register fixture.
The default native executable is this checkout's
`target/debug/examples/native-device-probe`. Explicit `--probe`, `--netd`,
`--guest-init`, `--device-pressure` and `--witness-dir` remain available.

Pressure observations append each received UDP payload (including malformed
payloads), peer and host timestamp to `device-pressure/actual-netd-packets.jsonl`
before validation. `network-phase-acknowledgements.json` retains the guest phase
snapshots before activation. The single guest producer acknowledges a NET
generation only after its `sendto` succeeds; this excludes later old-generation
application sends, but does not prove kernel/neighbour queues have drained.
The diagnostic PID-1 fixture installs a permanent neighbor for the actual netd
host alias `192.168.127.254` at its configured gateway MAC `5a:94:ef:e4:0c:dd`,
both after initial interface setup and after the destination MAC change (which
flushes neighbors). `SIOCGARP` reads back and verifies the complete/permanent
flags and hardware address; the guest record is retained in
`destination-network-neighbor.json`. This removes unresolved ARP as a prerequisite
for the UDP pressure frames without changing native activation policy, discarding
payloads, or treating `sendto` as native frame-completion evidence. It does not
establish the cause of the retained `-11` failure or per-packet native traversal.
The original fence/no-replay and fresh bidirectional packet assertions remain
unchanged. A destination failure is retained in `destination-failure.json` before
cleanup; `destination-cleanup.json` separately records the existing explicit
stop/reap result and close/forced-reap failures. Cleanup failure alone fails the
gate; cleanup cannot replace an earlier pressure failure. Main's real controller
success/failure runs exercise this cleanup path.

Main builds these inputs explicitly. The commands are not executed by an
implementation agent:

```sh
make BLK=1 NET=1 native-device-witness-probe
cc -O2 -pthread -static -o /absolute/private/native-device-linux \
  src/libkrun/examples/native_device_linux.c
cc -O2 -pthread -static -o /absolute/private/native-execution-linux \
  src/libkrun/examples/native_execution_linux.c
cc -O2 -pthread -static -o /absolute/private/native-device-pressure \
  src/libkrun/examples/native_device_pressure.c
mkdir -p /absolute/private/native-device-witness
as --64 -o /absolute/private/native-device-witness/witness.o \
  src/libkrun/examples/native_device_witness.S
ld --build-id=none -nostdlib -Ttext=0x1c001000 \
  -o /absolute/private/native-device-witness/witness.elf \
  /absolute/private/native-device-witness/witness.o
objcopy --only-section=.text -O binary \
  /absolute/private/native-device-witness/witness.elf \
  /absolute/private/native-device-witness/witness.bin
nm -n /absolute/private/native-device-witness/witness.elf \
  > /absolute/private/native-device-witness/witness.nm
NETD_BIN=/absolute/path/to/the/actual/silo-netd \
  python3 src/libkrun/examples/native_device_controller.py \
  --evidence /absolute/fresh/private/whole-machine-evidence \
  --kernel /absolute/path/to/the/ordinary/production/vmlinux \
  --register-fixture /absolute/private/native-execution-linux \
  --execution-completeness --busy-devices
```

The original `make BLK=1 NET=1 native-device-probe` target remains the normal
`blk,net` production-feature compilation target. Its binary lacks the real-owner
observation command now required by the controller's blocked-console negative
gate, so it cannot complete either controller mode. Use the existing witness
target above for both baseline and execution-completeness controller runs;
neither mode skips the negative gate. These diagnostic runs do not establish
production qualification. The witness build explicitly enables
`native-device-probe`, forwards only its diagnostic instrumentation to devices,
and is excluded from native live-profile eligibility. It retains ordinary
production execution, controller, legacy and device-provider implementations.
It does not enable the CPU-only release path for attached production devices.
Use Main's established exact source/build-binding procedure for both binaries.
Both diagnostic drivers share the common metadata owner's existing
`diagnostic-only;` canonical producer format. It records actual package,
compiler, feature and clean/dirty/unknown source facts without claiming a
production binding. Caller binding material includes the actual helper binary
hash. The production `execution_producer`, `binding_complete` and live-profile
eligibility checks remain strict; no dirty build or diagnostic feature is
relabeled production-eligible.
The same actual-build producer selector is used by both drivers, common capture
admission and fresh restore admission; expected producer equality is exact at
each consumer. Diagnostic build provenance is independent of CPU-only fixture
scope. Only the explicit empty-inventory capture mode or actual prepared
diagnostic buses select the CPU-only fixture path, never a producer-string
prefix. A diagnostic build exercising real attached providers still requires
the exact whole-machine pause, full device/legacy capture, attachment identity
matching and all normal provider restore validation.

`network-echo-<monotonic-ns>.json` and its transition log retain actual host datagram receive
counts, accepted echo-send counts, owned netd peers and the last bounded packet
prefix around pause/capture/resume/release/activation and at timeout. Accepted
host sends are not claimed to be guest deliveries. Guest progress separately
counts actual replies, mismatches, receive timeouts, refusals and interruptions,
with the last complete reply sequence null until one is observed. These
observations distinguish endpoint service, late data and actual guest receive
progress without retrying requests or weakening UDP comparison, deadlines or
strict progress requirements.
Each UDP request is sent once and owns one absolute 100 ms monotonic deadline.
Delayed or mismatched replies are consumed and counted without issuing a new
request or resetting that deadline. Only an exact full datagram for the current
request, checked before expiry, advances `net_rx`; oversized matching prefixes
cannot pass. Nonblocking receive plus the remaining-time poll keeps repeated
stale packets and interruptions within the original deadline, including across
ordinary pause/resume. All diagnostic receive counters remain independent of
the strict successful-reply counter.
Every progress check sends one fresh `C<32-hex-nonce>` request through the real
guest control stream. PID1 uses the same bounded counter-record emitter to
return actual atomic counter observations with that nonce. Buffered ancestor
reports cannot establish this baseline. An ancestor value can only detect
regression; all nine required counters must then strictly advance past the
newly observed baseline. The nonce round trip and subsequent progress share
the original total 60-second budget. Continuation, pressure and timeout records
retain the actual request/reply baseline; no workload is restarted and no
request is retried.

Native-mux streams begin with the native `OK <u32-port>\n` acknowledgement,
not guest payload. Normal echo, retained partial-control and exhausted-credit
readers share `Session.parse_mux_ack`: it buffers fragmented ACKs, bounds the
line to 64 bytes excluding the newline, rejects malformed/out-of-range ports
and preserves every coalesced payload byte. The pressure reader performs no
stream reads, including ACK reads, until the real native snapshot observes
`waiting_credit` or `deferred_credits`. Its original 5-second send and 30-second
resume budgets, accepted byte count and strict original-payload equality are
unchanged. `partial-control-resumed.json` and `mux-credit-resumed.json` retain
the ACK and actual received payload before equality is asserted; ordinary echo
mismatches retain the ACK, expected prefix and received bytes in
`vsock-payload-mismatch.json`. Close-only transient streams still exercise
native disconnect/reaping without draining them, and the activation-fence
rejection probe still requires EOF/reset, not a successful ACK.

The separate numbered output-only console is a byte stream, not a record-atomic
endpoint. Once the native source is paused and all owners are quiesced, the
pressure controller drains its actual output socket to EAGAIN before fixing the
cut boundary. It retains every complete source record and the exact trailing
prefix. Continued-source bytes after that boundary and fresh-child output are
each checked with that prefix concatenated only in observer memory. The prefix
is never sent, written or replayed to a guest or endpoint. Exact canonical bytes
and consecutive sequence numbers are required, while a still-incomplete valid
last-record prefix is retained rather than rejected. Source continuation evidence
records the complete cut sequence, raw-byte boundary, drained-byte count and
prefix hex; fresh-child evidence records its actual received-byte count and final
prefix. Original console-output logs remain unmodified by the observer stitch.
This changes neither the producer nor operation deadlines.

Main can run the host-independent pure framing regressions with:

```sh
python3 -m unittest discover -s src/libkrun/examples -p 'test_native_device_controller.py'
python3 -m unittest discover -s src/libkrun/examples -p 'test_native_device_pressure.py'
```

All three guest producers emit complete bounded records with a single write
to the shared hvc0 stream. Clock/device reports and pressure reports are fully
formatted before emission; the original register helper assembles the whole
CPU array before writing it. Profile observations buffer each complete
BEGIN/body/END frame before emission, rather than allowing other reports to
appear inside its body. Variable profile bodies retain the existing object
bound and release their temporary buffers. PID1 opens a blocking output
description shared by its children and a separate nonblocking input
description. Formatting errors or short/failed writes fail the fixture; they
are not retried as independently interleavable record fragments. Independent
clock/register measurements, raw identity bytes and equality assertions are
unchanged.

Source fixture construction has four native CPUs. The unchanged ordinary Linux
image uses CPUs 0/1 (`maxcpus=2`), including the supplied original live-register
executable and all busy providers. Explicit E820 reservations
`memmap=16M$448M memmap=64K$448K` protect the bounded witness RAM and low SIPI
trampoline. Only initial source construction installs CPU 2's guest entry through
a diagnostic-only AP2-targeted command in the existing owner mailbox/journal.
It requires the exact parked source scope and native UNINITIALIZED state,
then writes only initial REGS/SREGS2/MP. It never replays CPUID, MSRs, xstate,
LAPIC, events or clocks into already-run source CPUs; CPUs 0/1/3 receive no
bootstrap command. Fresh restore retains its complete checked installation.
CPU 3 stays genuinely uninitialized until CPU 2 issues actual guest INIT/SIPI. No captured destination
CPU, deadline, GPR or SIMD state is reseeded, and Linux's kernel, PIT and clockevent
profile are not replaced. Each child must continue the same kernel identity,
original register-process PID and useful device work.
The source bootstrap can occur only once, cannot follow a fresh restore install,
and a partial setter failure makes its owner stop-only. The host retained AP2
entry changes only after the real successful owner acknowledgement; later
captures observe the original live guest-created sentinels rather than
reconstructing the entry.

The dedicated guest CPU supplies original future, due/non-IRR, pending,
pending-plus-future, masked/unmask, in-service/EOI and halted causes. Its live
GPR/x87/SSE/YMM values are checked in the actual native captured records in
addition to exercising the original Linux SIMD executable. IO and MMIO use an
existing sink UART scratch register and a real RNG transport selector. A
diagnostic observer runs only after each original device callback; a bounded
completion hold lets the existing Park journal finish native emulation without
another guest instruction. Exact fixture ELF completion symbols, native RIP,
native original comparator/IRR/ISR/MP state, guest expiry/EOI/completion counters
and callback counts distinguish original causes from replacement work.
Native KVM PIO and MMIO dispatch pass the actual owning logical CPU ID to
the Bus, rather than attributing every access to CPU 0. The observer therefore
holds only the real CPU-2 callback at the exact fixture address; its CPU/address
filter is not widened to manufacture an observation.
The due/non-IRR comparator expires while the actual completed RNG write still
owns its vCPU, not after an opportunistic native re-entry. Mask coverage includes
both an overdue masked compare and a retained future masked compare. For the
overdue cut, a retained nonzero original comparator must deliver exactly once
on unmask; a zero comparator with the validated empty IRR/ISR must deliver none.
Merely observing guest TSC past the deadline does not prove consumption.
KVM keeps a pending timer behind the LVT mask and clears its comparator when
processing that event. The future masked compare must deliver its original
expiry exactly once. The guest reads its actual native LVT mask before either
unmask. No comparator is moved to manufacture a successful window.

The source-only `masked-source-no-pause-01` diagnostic observed one IRQ and one
EOI after unmask without any pause, capture or reconstruction between arm and
delivery. Its original arm count and comparator remained unchanged, and the
terminal native comparator was zero. This distinguishes an original pending
expiry from an invented interrupt; it is not an additional timing waiver.
See the [pinned KVM LAPIC implementation](https://github.com/archlinux/linux/blob/v7.1.8-arch1/arch/x86/kvm/lapic.c)
for masked pending-timer admission and comparator consumption.

`witness-cut masked` reads the original guest comparator through the VMM guard
already retaining its native cut, rather than recursively acquiring that same
non-reentrant mutex. In `whole-machine-timer-exception-03`, the source's final
`execution-265-original-cause.json` recorded masked command 4, followed by
`OK pause` and `ERROR witness-cut witness VMM lock` in `driver.log`; the validator
itself owned the conflicting guard. The unchanged full masked scenario is the
regression, not evidence that the corrected run has passed.

VMM acquisitions remain nonblocking: snapshot and accepted-Park observation
also acquire the witness gate, so replacing every VMM try-lock with a blocking
lock would introduce a lock-order hazard. Validation remains read-only, and a
diagnostic error does not certify an untouched command or permit replay of
guest writes or partially accepted bootstrap work. No command is retried, no
deadline is renewed, and the original owner journal and stop/reap requirements
remain unchanged.

The ISR reads its actual entry TSC immediately after saving its three scratch
registers, before publishing observation metadata. Reserved slot 23 brackets
publication of the IRQ count and current/previous timestamps with an odd/even
guest-written epoch. Each host sample uses atomic slot loads and retains both
epoch reads as `irq_publication`; only equal, even epochs qualify its IRQ record.
An interrupted publication remains explicit evidence, not a fabricated complete
record. The existing bounded wait and exact comparator assertion remain
blocking; absolute early delivery is recorded under KVM-TSC-DEADLINE-EARLY as
described above. Publication completes before any deliberate in-service/EOI hold.

Contemporary clock evidence uses a primary CPU's TSC and monotonic brackets
around a freshly acknowledged secondary sample, paired with the actual native
offset difference. Linux converts TSC to monotonic time using its own calibrated
fixed-point multiplier; this slope need not equal the integer `GET_TSC_KHZ`
rate. The observer initializes one exact rational feasible affine relation from
the original source's brackets before its first pause. Every selected source,
child and recapture bracket must remain compatible with that same slope and
intercept. Later observations may only narrow the original measured uncertainty,
never reset or widen it. `original-clock-calibration.json` and each continuation's
`clock_relation` retain the original and surviving bounds. Native per-CPU rates
and offset-plan arithmetic remain separately checked exactly.

The long prepared dwell exceeds the original 500 ms compare interval.
Three fresh native processes each progress and
recapture real child state. Partial-install evidence withholds an actual
successful Installed acknowledgement and retains each expected CPU owner's
actual `KVM_RUN` attempt observer before and after successful stop/join.
Only exact owner coverage and zero attempts across both observations prove
zero first instruction; a nonzero attempt is conservatively refused, not
misreported as a definite guest entry. The observers are diagnostic-only,
monotonic, never reset, and survive owner/handle destruction.
Both passing and failing observations retain actual ACK identity/kind/result,
CPU-batch reconciliation, release disposition and bounded private-RAM comparison
diagnostics. No captured range is excluded or rewritten. Destination equality
is not a no-entry proxy: native KVM registration of the ordinary kernel's
`MSR_KVM_WALL_CLOCK_NEW` writes its private shared page before any guest entry,
as permitted by the construction contract. Those mandatory setters are unchanged.
The CPU-only fixture's unchanged-RAM result remains a separate fixture-specific
observation.
The passing whole-machine witness requires the real successful held ACK,
unreconciled batch, no accepted Release, zero observed attempts for every
expected CPU through successful reap, and exact immutable source/checkpoint
bytes. The caller validates all proof fields and per-CPU numeric observations,
not just a zero-entry boolean, and binds source object sizes/SHA-256 plus the
unchanged source manifest. Private RAM differences and comparison failures
remain explicit diagnostics; an observation/comparison error cannot pass.
The final native preparation duration and clock advance must both fit the
original positive residual interval; elapsed prepared dwell is not charged to
it. Fresh guest observations retain the original boot ID and kernel identity,
and every completed case is recaptured with the live original SIMD sentinels.
A failed capture into an existing immutable output directory is followed by
source continuation, a real signal hold, and a successful byte-identical retry.

The first host vsock CONNECT waits for a guest-reported listener mask set only
after both real bind/listen calls succeed. Native driver READY is not Linux
service readiness. The mask is retained guest state and remains observable in
fresh child progress reports. Startup failures retain actual stream EOF/send
observations and an attempted native pressure snapshot before teardown; they
are not retried or counted as successful traffic.
The native `OK <port>` acknowledgement is parsed separately and never counted
as guest echo. Actual accepted payload bytes, including partial sends, must
return byte-for-byte, and the original guest vsock counter must progress.

For a restored destination, the inherited listener mask does not prove that
the guest has finished resetting its old connections. Native admission leaves
the first CONNECT and its passed descriptor unread until the reset event's
four guest-memory bytes appear in a newly posted EVQ buffer. Preposted buffers
cannot satisfy this condition. Buffer addresses, not descriptor-head numbers,
identify the event because negotiated IN_ORDER can renumber descriptors.
Notification arming and bounded rechecks prevent a lost repost wake; malformed
queue evidence remains a provider fault. Same-object pause/resume retains the
pending observation rather than publishing another reset.

This is a dependency on the admitted Silo Linux guest profile, not a generic
virtio reset acknowledgement. The pinned Linux
[7.2.2](https://raw.githubusercontent.com/gregkh/linux/v7.2.2/net/vmw_vsock/virtio_transport.c)
and [6.18.48](https://raw.githubusercontent.com/gregkh/linux/v6.18.48/net/vmw_vsock/virtio_transport.c)
drivers reset connected sockets before reposting the event buffer and kicking
EVQ. A native CONNECT ACK alone still cannot replace the byte-exact guest echo
gate. Missing completion evidence leaves admission fenced.

An absent `/proc/modules` is retained as an explicit guest `ENOENT`
observation, not an empty successful read. Admission requires the supplied
kernel's actual emitted sibling `.config` to contain the unambiguous disabled
`CONFIG_MODULES` setting. That configuration is retained and hashed in the
input identity; each profile records its absence admission. Missing/malformed
configuration cannot authorize absence, contradictory presence fails, and
other open/read errors still fail. Ordinary kernel/PIT admission is unchanged.

Broadcast observation retains both the raw `current_device` bytes and a
guest-generated completed-read record with the exact path, byte count and
device/no-device classification. The pinned kernel's `current_device_show`
returns zero bytes when the selected tick device has no event device; it is
not an unreadable or unknown name. Native admission accepts that explicit
zero-byte no-device observation, rejects empty/unknown observations without
it, and still refuses a selected `pit`. TSC, both online LAPIC-deadline
clockevents, speaker absence and the actual native retired-PIT predicate
remain mandatory. Parser unit coverage includes missing, contradictory and
incorrect-length evidence and a genuinely selected PIT.

`native_device_pressure.run` returns exactly seven bounded lists of actual
retained paths for block, net, vsock, console, balloon/RNG/legacy, shared IRQ and
no-post-release-controller-rewrite evidence. Its helper is included before
source capture. Real worker acquisition/consumed-kick holds, the original
subscribed eventfd's accepted-write `EAGAIN`, original guest ACK holds, actual
EVQ starvation/reset, mux FD/credit/reaper traffic and real endpoint backpressure
are observed through the existing controller and concrete owners.
Successful PIC, IOAPIC, PIT and clock setter counts are recorded at the actual
native setter returns, including a setter preceding a later partial failure.
Their retained preparation key and subsequent stability are not inferred from
guest silence or an outer successful method.

Both controller modes use `Session.blocked_console_cancel` on their existing
source, without another workload or Session. The helper withholds real output
draining for the original three seconds, sends one pause and retains its bounded
`ERROR pause` response. Only that subsequent status command's bounded raw replies
can identify the failed Pausing operation/generation. The actual `hvc0` console
must retain accepted, unfinished quiescence for that same key while the other
participants are quiesced; an absent fault or that key's retained Deadline is
allowed, but another console fault, Running or Quiesced console is not proof.
The helper also retains non-consuming bytes from the actual undrained socket,
proves the host output-log boundary did not advance during the hold, and requires
actual drained-byte growth after restoring draining. Draining is restored even
on failure. The original 0.2-second drain precedes exactly one cancellation of
the original operation, followed by nonce-correlated resumed device progress.
The production pressure path binds `device-pressure/blocked-console-cancel.json`
into `busy_console`; the ordinary device path retains the same returned record.
The helper neither captures nor stops, and the existing execution/source and
destination owners retain cleanup responsibility. This is gate machinery, not
runtime proof or a capability grant.

Pressure snapshots are read-only observations, not reissuable pressure commands.
One native snapshot owns one original five-second deadline. Only typed
`WouldBlock`/`LockBusy` from its actual VMM, transport, resource or nested owner
read remains pending. Each incomplete collection drops all guards before the
driver dispatches events; poison, provider faults, invalid state and native read
errors remain terminal. A collection completed after expiry cannot publish an
`OK`. File creation/write/sync happens once, only after a complete timely
collection. The Python controller sends that command once; it does not replay
string-matched `DeviceLock` failures. Wake/restore, request holds/releases, IRQ
ACK holds/releases and EVQ effects are never replayed by observation admission.
Block ownership reads use short nonblocking acquisition/returned-worker locks.
The original worker releases its acquisition gate while deliberately holding a
popped request, so observation can report that actual head without waiting for
the later release command. No queue position, counter or witness is synthesized,
and incomplete collections do not produce partial evidence.

The native `status` command likewise retains one received command and the
original five-second observation deadline. Only typed VMM `WouldBlock` or
participant-manager `LockBusy` is pending; all guards are released before event
dispatch. Poison, IRQ/native read errors and other manager/provider faults remain
terminal. The complete control, release, time, IRQ and participant observation
must be collected before the deadline and before any `CONTROL`,
`RELEASE_MAY_HAVE_RUN`, `TIME`, `IRQS` or `PARTICIPANT` record is printed. Pending
collections therefore emit neither partial successful frames nor duplicate
records. The controller still sends `status` once, and terminal-stop behavior is
unchanged.

Pressure IRQ hold/release retains one native command and its original five-second
deadline while awaiting initial admission. The attachment address is resolved
once and retained across contended polls, without repeatedly copying the
attachment inventory. Only typed `WouldBlock` at the VMM
or the manager's transport lock is pending: the latter is acquired before
`diagnostic_hold_irq_acks` changes ACK hold state or applies retained ACKs.
Every pending attempt drops all guards before driver event dispatch. Once
admitted, the hold/release effect executes once; all provider errors (including
release errors after ACK application), poison and event-dispatch errors are
terminal. Completion after the original deadline cannot return `OK` or replay
the effect. This is not Python command retry and does not alter ACK eligibility,
accounting, shared-IRQ invariants or the whole-machine evidence oracle.
The real-transport `pressure_observation_` regression also checks that contended
IRQ hold/release leaves hold state and ACK accounting untouched, admission after
unlock changes the actual hold state, and poisoned transport locks are terminal.

`target/phase09-evidence/whole-machine-timer-exception-05` remains a failed run:
`execution-source/driver.log:439` reports a busy `hvc0` transport (`Virtio(3)`,
address `3489660928`, IRQ `5`) during `request_ownership("owned")`. Its last
`device-pressure/request-owned-60.native.json` records PID `3480182`, `Running`,
controller setter counts `[26,26,26,39,13]`, both block workers retained and
unfinished, but `owned_head: null`, `available_unpopped: 0`, `consumed_kicks: 0`.
The Vsock observation is expected/started `3/3`, parked `0`, with two unfinished
workers. These are actual observations, not proof of the requested owned-head
boundary or completed pressure/cleanup. The original seven witness sets and
all numerical/state/count/cleanup assertions remain mandatory.

Main-only pure regression selections are `pressure_observation_` in libkrun
with `blk,net,native-device-probe` and krun-devices with
`blk,net,native-device-probe`, plus
`provider_vsock_shared_proxy_owner_prevents_queue_escrow` with that device
feature set. These changes have not been checked by implementation agents.

Fresh network ingress uses a caller-managed resource setup packet through the
actual new netd before transferring its connected datagram FD. An ARP exchange
and a distinct UDP priming payload establish that new netd's actual host peer
for the helper's reserved UDP port. The setup record explicitly labels these
packets as caller-generated, not guest progress. Subsequent tagged host packets
must cross the real endpoint and native activation fence; source sessions,
sockets and NAT peers are not inherited. The source's genuine UDP traffic and
the child's traffic are attributed to their actual owned netd socket inodes,
not whichever controller happened to read the shared echo socket.

The extension requires the exact old witness names and emits a pass only after
all their real assertions and native stop/reap acknowledgements. Each witness
binds 1..64 retained regular files by relative path, byte length and SHA256,
with a 16 MiB per-object and 64 MiB unique-object bound. Input binaries, original
kernel/profile observations, native records, guest records and immutable cut
manifests remain present on failure. There are no inferred passing records,
threshold changes, provider substitutes, capability grants or public delivery
claims.

Additional Main-only pure selections are `bus_probe_real_serial_completion_`,
`device_witness_symbols_`, and the existing diagnostic-feature capability
refusal test. Format/lint/build, fixture assembly, production observations and
runtime gates are all Main-owned.

All admitted providers now use the existing descriptor utility's preallocated
queue-max snapshot. It validates the complete raw NEXT graph, TTL/bounds,
duplicate indices/cycles, flags, direction order and mapped ranges before
effects, and consumers use the same immutable descriptor metadata. Adjacent
RAM regions use bounded directional guards from the VM's memory domain.
Reader owns only read guards; Writer owns premarked write guards, including
file-read destinations and console input. Split data/status retain independent,
disjoint write obligations. Borrowed syscall views remain guard-bound through
completion and errors; the final view is clipped to the requested byte count.
Descriptor consumption and native iovecs use bounded 64-entry stack scratch,
without per-call lease clones or temporary vectors. This does not remove pinned
imago 0.2.4's existing internal vector and pointer-guard allocations.
Block IN/OUT requests consume successive bounded batches until the validated
request length is complete, advancing the file offset with checked arithmetic.
A zero-progress or failed batch is not successful completion; already-completed
prefix transfers retain their effects and existing error/status accounting.
Additional hypervisor-free selections for Main (not executed results) are
`descriptor_snapshot_`, `descriptor_file_io_`, `descriptor_error_after_`,
`descriptor_consumer_`, `descriptor_read_sources_`, `descriptor_tracked_`,
`file_views_`, `console_port_views_`, `memory_slice_at_most_`, `block_provider_full_chain_`,
`block_provider_read_data_and_status_`, `block_provider_scattered_`,
`execution_device_envelope_`,
`execution_prefence_vm_refusal_`, `inactive_rng_provider_`,
`legacy_resume_preflight_` and `lifecycle_queue_unready_`.

### Diagnostic shared-IRQ observations

Only the explicitly enabled `native-device-probe` feature adds transport IRQ
observations. The counters record actual native signal attempts/successes,
actual active guest ACK writes and completed application of those writes
(`ack_applied`), alongside the real current interrupt status. A completed held
ACK need not clear a bit if a newer signal superseded its ownership.
Signal success means that
the native call/write accepted the signal, **not** that a guest IRQ was
delivered. KVM route observations expose actual retained GSI membership,
registration and raw IOAPIC IRR/redirection state. The guest's actual shared-GSI
handler counts remain the delivery-side observation; neither aggregate guest
progress nor an IOAPIC bit alone proves peer independence.

The optional bounded ACK hold retains at most 4096 original ACK values without
clearing their cause. Releasing it completes every original ACK exactly once,
clearing only bits still owned by an actual guest ACK. Diagnostic-only
per-member synchronization orders held-ACK eligibility with cause publication:
a newer same-bit signal invalidates an older ACK's eligibility, and a subsequent
real guest ACK can own that newer cause. Release never signals an IRQ or kicks
a queue. Releasing twice has no additional effect. Pending held ACKs refuse quiescence
and capture. Overflow completes all originals and marks the observation
permanently invalid rather than dropping callbacks or manufacturing a pass.
Poisoned eligibility is permanently invalid and discarded before cleanup;
original ACK accounting completes with no cause bits cleared, and release
returns a failure. Neither repeated release nor quiescence can certify it.
Stop/reset also complete retained originals, but do not certify a cut. A shared
line witness must always release the hold before pause/capture, including its
error cleanup, and may repeat the real hold after fresh release. No diagnostic
accepted ACK state enters an artifact. Normal builds contain none of this
storage, instrumentation or hold behavior.

Main-only hypervisor-free regression selection: `irq_probe_`. Its tests use
actual activated RNG transports, a shared real eventfd and actual MMIO ACK
writes. The release regression covers a newer same-bit cause, an independently
acknowledged config bit, later guest acknowledgement, peer isolation and no
eventfd replay; they have not been run by the implementation agent.

### Nonblocking production admission under active device traffic

Transient mutex contention is not an unsupported device profile. The common
pause owner retains the original operation, generation and deadline in its
pre-effects `Admission` phase, and makes bounded nonblocking admission progress
on subsequent monitor turns. Only an explicit `WouldBlock` classification
(`LockBusy`) is pending. Poison, unsupported resources, invalid state and sticky
effect faults remain real refusal. The inventory scan continues past busy
participants so contention cannot hide a different known unsupported provider.
Legacy and nested provider preflight locks use the same distinction.

No ingress fence or CPU park command is accepted before admission succeeds.
Deadline/failure or explicit cancellation in that phase retires the untouched
operation back to Running without parking/restarting CPUs or devices; its
operation number cannot be reused. The actual first fence result determines the
ownership boundary: an expired attempt with no EventManager fence remains
untouched, while any retained fence changes phase before CPU dispatch. Thus
partial fence/dispatch effects remain owned by the existing cancellation path.

After CPU parking, begin-quiesce/resume admission makes at most one nonblocking
attempt per untouched attachment in each poll. Already accepted begin commands are
never resent. A transient lock before acceptance is pending, not an accepted
provider fault. Polling likewise leaves contended locks pending. Cancellation
reconciles accepted transitions only and leaves untouched attachments running;
expired operations do not acquire new owners. No controller retry, workload
shutdown, blocking/spinning monitor or relaxed evidence assertion is involved.

Main-only regression selections: `device_admission_`,
`pause_admission_`, `legacy_resume_preflight_`,
`callback_fence_actual_epoll_failure_`,
`block_provider_preflight_contention_`,
`console_provider_port_preflight_distinguishes_`,
`console_provider_control_preflight_distinguishes_`,
`console_provider_busy_`, `provider_vsock_preflight_` and
`cpu_capture_rollback_`. These implementation agents did not run checks.

Completed exact-key device resume acknowledgements are terminal while other
providers remain pending; the transport never re-runs that provider or its
queues. Existing late/fault outcomes and current IRQ failure remain visible,
and the manager still enforces the aggregate deadline. Real two-RNG regressions
exercise staggered inner/outer contention, partial begin/resume, expiry followed
by accepted-only cancellation, untouched unready queue geometry and a later
cycle with stale previous-key acceptance. These are unit regressions, not
whole-machine runtime qualification.
The unready-queue fixture completes real feature negotiation through
`FEATURES_OK` but never sets `DRIVER_OK` or queue-ready. It records the complete
actual `QueueState` at a baseline cut, then checks equality after partial
expiry/cancellation and later fresh operations. Queue size and address MMIO
registers are write-only, so reading them as zero is not a preservation oracle.
The peer's actual transport mutex remains held throughout the partial/cancel
interval, with its lifecycle snapshot unchanged.

Cancellation during an accepted CPU capture does not submit a replacement
Park or discard the original capture journal. It drains that exact batch under
the new cancellation deadline and retains the cut/payloads before subsequent
common-time preparation can retire the batch. Only the old command's expiry
while acknowledgements remain unresolved is pending; participant/rejection or
payload faults remain real errors. The CPU-journal regressions are unit checks;
actual delayed/queued native captured-ACK cancellation still needs Main's
runtime evidence.

Fresh prepared construction must attach actual dormant MMIO resources before
creating CPU owners: the Bus clone copies its mapping. Saved provider state
application stays after native VM/CPU execution installation and before any
first guest instruction. Moving resource attachment earlier is not moving
payload application, releasing workers or introducing mutable shared routing.

### Retained terminal capture is not running admission

At an exact accepted Quiesced cut, serialization must not re-enter running
worker-inventory admission. The shared transport still checks the actual cut,
retained faults, sticky IRQ failure, unresolved diagnostic ACK/overflow,
queue ownership and static SHM exclusion. Actual provider capture and full
payload/resource/prefix validation remain required.

Vsock terminal validation observes the single canonical sticky worker failure,
actual mutex poison, finished real owner handles and provider effect/journal
faults without locking the running gate. Immutable restore exclusions belong
to muxer configuration. Paused owners no longer repeatedly broadcast and wake
one another while holding that gate. Block's actual backend owner is joined
and returned before the cut; Console joins direction owners and freezes its
control producer. These are terminal ownership requirements, not permission
to ignore a busy live producer. Console's defensive snapshot remains
nonblocking and preserves exact contention, poison and effects errors.

No second capture lifecycle, record cache, outer driver retry, repeated flush
or fake successful observation was added. Existing fresh diagnostic captures
continue reading actual state. Main-only regression selections include
`provider_vsock_terminal_`,
`provider_vsock_sticky_worker_failure_does_not_wait_for_owner_gate` and
`console_provider_capture_preserves_lock_busy_poison_and_control_fault`.
The real held-gate regression uses the same Vsock instance in an actual
MmioTransport and compares complete capture bytes while the real gate is held;
old shared running-preflight re-entry fails that regression. These changes
have not been checked by the implementation agents and grant no native lane.

### Blocked console preparation observes the actual writer

The reversible blocked-output negative case does not infer backpressure from a
fixed sleep, a flat guest counter, or unread endpoint bytes. Before its single
pause it disables endpoint draining, requests one bounded burst of 65,536
ordinary numbered `CONSOLE N\n` records from the existing guest writer, and
observes `pressure snapshot` under the existing 30-second observation budget.
The burst only omits the writer's usual 1 ms delay; it adds no writer, synthetic
acknowledgement, hold, stream marker, or discarded output. Normal paced work
continues after the burst.

Readiness requires the actual `hvc0` output port 2 to retain an unfinished
worker with admission open and a popped descriptor head blocked by a real
`WouldBlock`, with positive `write_remaining`. Head zero is valid.
`bytes_written` counts the chain's completed bytes; `write_remaining` describes
the current blocked memory segment. Native observation neither drains output
nor changes owner state. A missing readiness witness fails preparation, without
attempting pause. All observations share one deadline, rather than renewing it
for each snapshot.

`blocked-console-readiness.json` retains PID, timing, before/after guest samples,
output offset, observation count, the selected actual owner, and unread-byte
digest before the pause assertion can fail. Each observation is published once
at `blocked-console-readiness-NNNN.native.json`; the readiness record references
the last successfully published snapshot. Preparation errors also retain the
readiness record. The existing
failed-Pausing exact-key console ownership, accepted-only cancellation, restored
draining, continued counters and numbered-byte conservation checks remain
mandatory.

The retained `whole-machine-timer-exception-15` source samples advance from
153,653 console records at guest monotonic 319.897947680 s to 154,945 at
321.301938019 s (about 920 records/s), then remain at 154,960 through
323.406616183 s. The output log contains 2,213,295 bytes and ends with record
154,960. Those facts and `OK pause` alone do not establish a native pending
writer or quiesce data loss; the old three-second preparation had no such proof.

Destination pressure validation likewise waits for actual reset readiness:
after EVQ release the first retained CONNECT must produce byte-exact guest
echo before the delivered-reset snapshot and old-stream RESET assertion.
Exactly one reset and subsequent control-only service denial remain required.

Main can run the host-independent controller and pressure regressions with
`python3 -m unittest discover -s src/libkrun/examples -p 'test_native_device_*.py'`,
then rebuild the native driver/guest fixture through the existing Makefile
lane and run the full native lane with these retained readiness artifacts.
Implementation agents have not run checks or granted runtime qualification.


### Native memory-domain dirty coverage

The focused `--memory-dirty` mode uses the ordinary-kernel provider workload
and final whole-machine paused cuts. It is standalone verification, not a
Cargo hypervisor test or a public RAM capture API. Build the existing register
fixture as described above, then run from the native checkout:

```sh
make BLK=1 NET=1 native-device-witness-probe
cc -O2 -pthread -static \
  -o target/native-device-inputs/native-device-linux \
  src/libkrun/examples/native_device_linux.c
python3 -m unittest discover \
  -s src/libkrun/examples -p 'native_memory_controller.py'
python3 src/libkrun/examples/native_device_controller.py \
  --memory-dirty \
  --probe target/debug/examples/native-device-probe \
  --netd "$NETD_BIN" \
  --guest-init target/native-device-inputs/native-device-linux \
  --register-fixture target/native-device-inputs/native-execution-linux \
  --kernel "$KERNEL_PATH" \
  --evidence "$EVIDENCE_DIR"
```

`NETD_BIN` and `KERNEL_PATH` name actual executable/kernel inputs. Keep the
kernel's actual emitted `.config` beside `KERNEL_PATH`; a kernel without
`/proc/modules` requires that configuration to establish `CONFIG_MODULES=n`.
The kernel's embedded IKCONFIG is also an authoritative source of those exact
configuration bytes. Do not substitute an assumed configuration fragment.
The evidence parent must already exist. `EVIDENCE_DIR` must be a new directory
with at least 8 GiB available on its filesystem. The guest needs `vmsplice`
and PID1 pagemap PFN visibility. Two
guest-owned anonymous pages are mlocked and retained by an undrained real
pipe; their observed physical addresses must remain stable. One page is
changed only by the explicit host write, the other by the nonce-correlated
guest CPU command.

Each capture retains `memory-dirty.bitmap` in dense little-endian u64 form
and `memory-dirty.json` with its actual granule, packed region geometry,
page population and pause generation. The controller scans complete RAM
cuts as an independent oracle and rejects changed pages missing from the
harvested union. It also compares repeated frozen cuts, retains actual
provider progress, and requires acknowledged stop plus process reaping.

Host-writer attribution requires the existing active host bitmap to be
clean before the production `RuntimeGuestMemory::write_slice` and dirty
afterward, with byte-exact readback. The dedicated CPU page must remain
clean in that host bitmap around the guest store. A bit already present in
the cumulative union is not evidence of a new host mark.

This mode does not accept or clear a baseline. CPU re-dirty after accepted
generation clearing, incremental-versus-full image equivalence, file-private
sharing and restored reclaim qualification require the later RAM-image
gates. Source and binary hashes are retained separately, not presented as a
reproducible-build attestation. No capability is granted by this mode.
Preserve text reports, manifests and required inputs before removing
successful generated RAM/disk payloads; retain failed samples for diagnosis.

Capture-tracked source VMs disable destructive balloon reclaim from
construction, not only after accepting a baseline or restoring RAM. Reporting
queues still complete normally. The pressure gate checks the disabled reclaim
policy separately from actual reporting used-ring progress; reporting
acknowledgements do not establish discarded bytes or reclaim qualification.

Pause admission performs read-only device preflight before checking the
construction-time memory tracking mode. An unsupported attached provider
therefore retains its named refusal instead of being masked by the resulting
untracked-memory policy; neither check starts pause effects.

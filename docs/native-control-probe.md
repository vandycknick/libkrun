# Native CPU control diagnostic

`native-control-probe` is an opt-in, standalone Linux x86_64 KVM diagnostic.
It is disabled in ordinary builds and is not a Cargo test. The feature is a
diagnostic build fact, never a production qualification input. It exports only
`api::native_control_probe::run()` and its JSON result type. It does not expose
backend handles, bypass whole-machine device admission, or create a machine
`PauseToken`.

The fixture uses the production `Vm`, `Vcpu`, `VcpuHandle`, `CpuController`,
mailboxes, owner threads, KVM memory registration and KVM_RUN loop. There is no
second CPU controller or emulation loop. A small real-mode guest replaces a
Linux kernel/init fixture; this is a CPU sub-barrier proof, not Linux boot,
whole-machine pause, device-provider, time-freeze, or non-Linux qualification.
Native live bits remain false and the public live vector remains not-delivered.

## Running

Only the integration owner runs this diagnostic, after the ordinary build and
hypervisor-free checks. It requires accessible `/dev/kvm`, the KVM immediate-exit
kick mechanism, and x86 in-kernel irqchip/PIT support. TEE builds are excluded.
No kernel/init image is needed by this fixture; normal repository build/link
prerequisites still apply.

From the production checkout, explicitly select the opt-in standalone target:

```sh
cargo run --locked -p libkrun --features native-control-probe --example native-control-probe
```

Do not use `cargo test` as a machine gate. The example target has `test = false`
and `bench = false`. The module unit-test filters below inspect payload bytes,
bounded branch encoding, the real guest-memory MMIO hole, exact completion-cut
instruction offsets and JSON escaping. None opens KVM or calls the
machine-executing `run()` function:

```sh
cargo test --locked -p libkrun --features native-control-probe --lib native_control_probe_payload_has_bounded_real_mode_branches
cargo test --locked -p libkrun --features native-control-probe --lib native_control_probe_json_escapes_errors
cargo test --locked -p libkrun --features native-control-probe --lib native_control_probe_mmio_load_targets_unmapped_real_mode_hole
cargo test --locked -p libkrun --features native-control-probe --lib native_control_probe_completion_cuts_precede_guest_result_stores
```

The owner must separately run the common controller/backend pure filters. Do not
run the complete libkrun test suite as a purported hypervisor-free check: existing
unrelated tests create VMs.

## Actual scenarios and evidence

The entrypoint runs one vCPU and then two vCPUs in separate retained VMs. Each
vCPU has private guest counters and a fixed identity word. Guest code increments
an initialization counter once, then runs a tight progress loop. Every successful
continuation checks that progress changes, initialization remains exactly one,
and the identity is unchanged.

For each CPU count the diagnostic requires:

1. An exact CPU park, stable guest progress while parked, preparation, and actual
   correlated release acknowledgements before continuation.
2. An IO input and an MMIO read through real production bus callbacks. The last
   CPU's callback is held while the production controller accepts and kicks a
   park. The MMIO address is a deliberately unmapped RAM hole at `0x8000`,
   within the real-mode CS segment limit; an address-size override does not
   extend that architectural limit. Park must remain pending until the callback
   is released and the real completion KVM_RUN has returned. Before sending its
   real Park ACK, the owner thread captures actual KVM registers. The probe
   requires that snapshot's exact CPU/request/barrier identity, RIP immediately
   after the pending input instruction, and AL equal to the returned IO (`0xa5`)
   or MMIO (`0x5a`) byte. These checks precede release, so deferred completion on
   a later resume cannot pass the gate. After release, the guest must also store
   the actual input byte in RAM and continue.
3. A guest-programmed PIC and PIT interrupt, an actual STI/HLT timer wait, a park
   during that workload, and continuation. The timer handler increments guest
   RAM and sends PIC EOI. This proves timer-wait control responsiveness, not
   timer-state freezing or exact clock continuity.
4. A withheld actual park ACK: the diagnostic-only handle gate retains the real
   ACK from the owner channel, not a fabricated successful response. The common
   controller must expire with accepted ownership unreconciled. The retained
   CPU/request/operation/generation/kind/result are checked and emitted; clearing
   the gate and same-key reconciliation must precede release.
5. Explicit partial-pause cancellation: hold the last CPU in a real IO callback,
   accept park for every CPU, observe the common deadline expire, then submit a
   same-generation reconciliation with a new request and absolute deadline.
   Releasing the callback allows the original and reconciliation ACKs to settle.
   Only then prepare/release. Actual guest progress and unchanged initialization
   are mandatory. The one-CPU case covers an accepted outstanding command; the
   two-CPU case also permits the other CPU to park independently.
6. A stale CPU release key from the consumed earlier generation, submitted while
   the next generation is parked. The actual backend must refuse it and guest
   progress must stay frozen. The current exact key must still release normally.
   This is stale **CPU authority** refusal, not a claim that unsupported machine
   admission minted a public/machine pause token. Common pure token tests cover
   the opaque machine token's run, owner and consumption rules separately.
7. Ambiguous release: withhold the last CPU's actual release ACK after the native
   mailbox commits running. The controller must expire unreconciled while real
   guest progress continues. No paused/running success is inferred from that
   ambiguous controller result; the only next transition is production Stop and
   actual thread reap.

Success exits zero and prints one JSON document with per-scenario assertions,
exact request/barrier identities, submission and poll outcomes, retained real
ACK identities, parked architectural RIP/RAX cuts, guest progress and
initialization/timer observations, and
`all_reaped = true`. Failures exit nonzero and print JSON-escaped error evidence,
including the journal when construction reached a scenario. There is no fallback
success when KVM is absent or a syscall/guest transition fails. Record the exact
source/build, host/kernel, command, output and exit status with owner evidence;
this document does not claim any execution result.

## Cleanup and deadline ownership

A callback hold is always opened before teardown. Stop clears the diagnostic ACK
hold and uses the same production CPU controller, retaining earlier accepted
commands. No thread is detached and no guest RAM/VM ownership is released while
an owner can still execute. Normal controller polling and reap are nonblocking;
the standalone coordinator sleeps between polls, not inside the VMM owner loop.

The short fault deadline is 40 ms and the ordinary observation/operation budget
is two seconds. Preparation and release share one absolute deadline; explicit
cancellation shares its new deadline across reconciliation, preparation and
release. Expiry never discards accepted work. If terminal cleanup exceeds its
deadline, the coordinator keeps ownership
and polling until reap, then reports failure rather than a backdated success.
For a genuinely stuck native syscall the outer runner may terminate and reap the
entire standalone process; never reinterpret runner timeout as successful native
cleanup or qualification.

## HVF execution-state source contract

The execution schema is `arch::hvf_state`, shared with HVF without a Linux
framework dependency. Its CPU register groups are distinct: general registers
have no FP/LR aliases, SIMD values are fixed 128-bit little-endian values,
architectural/model/debug inventories are exact, and ICC excludes observational
RPR and nested aliases. Debug banks come from the saved debug identity.
Unknown inventories, SVE/SME, exposed PMU state without framework access, and
expanded debug models are refused rather than omitted.

The existing owned optional framework API captures a bounded GIC object and
releases that object on every path before releasing its framework owner. The
opaque blob is separate from owner-thread CPU registers and the software
pending IRQ, wake, offline and accepted CPU_ON state. Framework vCPU IDs and
channels are recreated; only logical identity and MPIDR cross the cut.

HVF capture retains the CPU cut before disabling native timer controls. Capture
retry does not consume the pause or resample a retained cut. Destination CPU
construction skips cold initial registers and remains fenced. Installation
keeps timers disabled during prepared dwell. Final preparation applies one
absolute counter offset before compare/control state and restores the framework
notification mask and matching software cache. Controller installation must
finish before any route/device producer reopens; CPUs release last.
A fresh same-generation capture request refences the retained timer cut before
an unreleased time plan is replaced; an exact duplicate returns its retained
payload without replaying native setters. Refencing invalidates release
preparation before native mutation.
For a retained execution cut, the subsequent generic `PrepareResume(0)` only
validates the exact completed typed time-plan key and acknowledges readiness.
It never recomputes or reinstalls an offset from the ordinary-pause baseline.
An absent/wrong-key plan or a nonzero generic time advance is refused. Ordinary
pause/resume without an execution cut retains its separate elapsed-time path.

The source implementation samples the architectural host counter and Mach
timebase separately. It does not infer physical-counter/timer epoch equivalence
from the virtual offset API. Actual Apple-silicon capture/install, physical and
virtual timer continuation, native GIC/ICC compatibility, multi-CPU clock
brackets, offline/waiting wake, prepared dwell, repeated fresh-process restore
and failed-attempt cleanup remain **pending-lane:hvf**. The Linux standalone
command above does not run those cases and grants no HVF qualification.
XNU's [userspace timebase implementation](https://github.com/apple-oss-distributions/xnu/blob/main/libsyscall/wrappers/mach_absolute_time.s)
adds a separately maintained offset to the architectural counter. Consequently
neither a Mach timestamp nor the virtual-offset setter proves a physical epoch.
An enabled physical timer receives a named unqualified-epoch refusal; its
register inventory is not silently discarded or treated as a virtual timer.

Audited hypervisor-free data tests, runnable on Linux without HVF symbols:

```sh
cargo test --locked -p krun-arch --lib hvf_state::tests::hvf_execution_
```

The following macOS filter exercises real software-state ownership only: no VM
or vCPU is created and no native wake method is called.

```sh
cargo test --locked -p krun-devices --lib legacy::vcpu::tests::hvf_execution_
```


# macOS host memory reclaim

## Goals and ownership

Make private guest RAM eligible for host reclamation when the guest reports it
free, and remove stale host-mapping accounting after device I/O. Preserve live
memory, guest/device throughput, and normal in-kernel refault handling without
replacing anonymous backing or serializing device access through a global lock.
Discard eligibility, task footprint and actual physical discard are separate
outcomes; none should be inferred solely from a successful advice syscall.

Free-page reporting transfers ownership of reported pages to the balloon device
until their virtqueue chain is acknowledged. The host may discard their contents
during that interval. It must not replay old reports after acknowledgement:
those pages may already contain live guest allocations or device buffers.

## Release path

For each validated, coalesced range of private anonymous workload RAM:

1. Claim the corresponding transition states.
2. Remove its guest-physical mapping with `hv_vm_unmap`.
3. Call `madvise(MADV_FREE)` separately for each native host page.
4. Immediately restore the original host/guest mapping and permissions.
5. Publish completion before returning the extent states to mapped.
6. Acknowledge the report after all its ranges are mapped or safely skipped.

Coalescing adjacent descriptors within one report reduces stage-2 mapping
changes and their cross-vCPU TLB invalidations without extending report ownership.
HV operations stay coalesced. Advice calls deliberately do not: XNU's multi-page
fast path walks host PTEs, which may be absent for guest-written backing.
Single-page advice uses the physical-page ref/mod path. Coalescing advice can
therefore turn a successful syscall into ineffective reclamation.

No host backing is replaced, no virtual-address holes are introduced, and there
is no global device-access lock. Unrelated guest/device accesses keep running.
A vCPU faulting in a transition waits and retries without advancing its PC.
Disabling new reclaim operations does not disable recovery of in-flight faults
or detection of lost mappings. If advice fails, remapping is still attempted;
a remap failure takes precedence and is fatal to the VM.

### Transition and failure invariants

One atomic state per 2 MiB RAM extent and a transition generation distinguish a
reclaim race from an invalid guest access. The state granularity is bookkeeping,
not the native-page advice granularity or a new backing allocation size.

```text
Mapped -> Transitioning -> Mapped  (original stage-2 mapping restored)
                       -> Lost    (restoring stage-2 mapping failed)
```

A vCPU samples the generation before entering the guest. Completion must increment
the generation before publishing the final extent state; reversing that order can
expose "mapped, unchanged generation" to a vCPU that entered mid-cycle and falsely
classify its fault as invalid. Waiting on a transitioning extent is itself proof
of a race, even without observing a generation change. Retry leaves the faulting
instruction's PC and registers untouched.

A failed remap publishes `Lost`, never `Mapped`: waiters must fail rather than
resume onto absent stage-2 RAM. Disabling new reclaim does not erase this state
or turn off fault recovery for earlier transitions. An advice failure still
attempts to restore the mapping; if restoration succeeds, further reclaim is
disabled but the VM can continue. Otherwise the VM must stop.

External/shared mappings remain incompatible. Nested EL2 guests are not
qualified for this path.

## Host mapping maintenance

Every 30 seconds, the native VMM event loop normalizes registered private RAM
using same-address `mach_vm_remap(copy=false, VM_FLAGS_FIXED | VM_FLAGS_OVERWRITE)`.
This shares the existing backing object; it is not anonymous backing replacement,
zeroing, or a replay of old free-page reports. The owner of guest RAM remains alive
throughout the operation. No detached maintenance thread or status reader owns
this responsibility. Reclaim-off, unqualified and disabled VMs do not schedule it;
a normalization failure is fatal rather than continuing with uncertain mappings.

Host accesses, including virtio block reads into guest RAM, populate host PTEs
whose footprint charge can survive successful page-wise advice. Normalization
removes those translations and their accounting; later host accesses fault them
back in. Guest mappings and live data are preserved. This is distinct from
physical discard: clean backing may remain resident until pressure.

Use only the 30-second maintenance cadence, independent of report arrival or
status polling. This amortizes normalization work without adding another timer
to each report. The free-page report cycle and backing allocation sizes remain
unchanged. The event-loop wait accounts for the next maintenance deadline even
when no device events arrive, rounding up sub-millisecond waits to avoid busy
polling.

## Qualification and accounting

`MADV_FREE` is lazy. Clean pages can remain resident until macOS needs them.
A footprint decrease from unmapping is not proof that backing was freed.

The startup scratch probe:

- Dirties every native page through an actual vCPU.
- Does **not** read the host payload before advice, since that would create host
  PTEs and hide the guest-only failure mode.
- Samples native `mincore` state before and after the immediate-remap cycle.
- Requires initially resident, modified pages and no referenced, modified or
  paged-out pages afterward.
- Verifies subsequent guest writes and host-visible data coherence.

A passed probe means the discard-state transition and mapping reuse worked, not
that a pressure workload has been run at startup. Resident pages alone are not a
failure; nonresident compressed pages are not evidence of discard.

The public `released_bytes` and `released_extents` counters retain their API names
but count cumulative successfully advised bytes and coalesced ranges, including
repeats. They are not current memory savings or counts of unique physical pages.

## Approaches tested and rejected

- **Guarding every device access with leases:** the early implementation took a
  global mutex and scanned released extents for descriptor reads and payload
  copies. An observed network workload fell from about 300 Mbps to about 1 Mbps
  after free-page reports, with similar vsock degradation. The reporting ownership
  contract and continuously valid host mapping allow passthrough access instead.
  This observation explains the design choice, not a general throughput claim.
- **Delayed stage-2 restoration:** immediate restoration avoids userspace exits
  for later accesses after the cycle. Only a fault racing the brief unmap window
  requires explicit retry. Lazy discard can preserve old contents until pressure;
  zero-fill is expected after actual discard, not merely after advice succeeds.
- **Bulk advice or unmap/remap alone:** both can leave guest-only backing
  referenced and modified despite a successful call or a lower task footprint.
  Native-page advice and metadata-only qualification detect that distinction.
- **Footprint-only qualification:** host translations and reusable accounting can
  change independently of physical discard. The probe therefore checks page
  state and reuse; separate pressure tests establish whether backing was actually
  discarded or compressed backing was removed.

Anonymous backing replacement is outside this design. Periodic normalization
shares existing VM objects and must never be implemented by replaying old reports
or replacing their ranges with fresh zero-filled mappings.

## Tests

The repository's Cargo runner signs macOS test executables with the Hypervisor
entitlement. HVF scenarios run in isolated processes; run probe tests serially.

```sh
cargo test --locked -p krun-hvf
cargo test --locked -p krun-hvf -- --ignored --skip pressure_ --nocapture --test-threads=1
cargo test --locked -p libkrun real_hvf_setup_qualifies_with_mapped_workload_ram -- --ignored --nocapture --test-threads=1
cargo clippy --locked -p krun-hvf --all-targets -- -D warnings
cargo clippy --locked -p libkrun --features net,blk --all-targets -- -D warnings
```

Real-HVF coverage includes unmap-only and bulk-advice controls, native-page and
multi-extent interior ranges, live neighbors, repeated reuse, Mach normalization,
concurrent vCPU transitions, and qualification/watchdog cleanup. Large-backing
tests cover guest-only writes, host population before HV mapping, and host writes
after guest access. Concurrent normalization tests exercise live host and guest
writes without discarding their data.

### Opt-in pressure validation

These tests allocate and keep active the explicitly requested host-memory budget,
plus small guest/control allocations. Do not run them on a busy or memory-starved
host without accounting for that budget. They never increase it automatically.

```sh
KRUN_RECLAIM_PRESSURE_MIB=1024 cargo test --locked -p krun-hvf pressure_reported_pages_discard_instead_of_compressing -- --ignored --nocapture --test-threads=1
KRUN_RECLAIM_PRESSURE_MIB=1024 cargo test --locked -p krun-hvf pressure_already_compressed_pages_are_forgotten -- --ignored --nocapture --test-threads=1
```

The first requires actual discard of both a host-advised control and the reported
guest pages, then verifies zero-fill and safe reuse. The second requires observed
compressed guest pages **before** reporting, then verifies that advice removes
the compressed backing. Neither uses unsupported `MADV_PAGEOUT` as a substitute
for that prerequisite. Unreported guest control data must survive both scenarios.

A budget insufficient to evict the control or produce compressed guest pages
produces an explicitly `INCONCLUSIVE` failing test, not a false pass. If the
control was discarded but reported guest backing remains, that is a failure,
not an inconclusive result. Each scan wait is bounded to 20 seconds and each
isolated child to 60 seconds.

## Initial validation, macOS 26.6.2 / Apple Silicon

The real-HVF control observed 128/128 pages still referenced and modified after
both unmap/remap alone and bulk `MADV_FREE`. Native-page advice cleared both bits
on all 128 pages. Partial-range and reuse tests passed with and without Mach
normalization.

The already-compressed scenario passed with a 1 GiB pressure budget: 1879 of
2048 guest pages were verified paged out before the report, and page-wise advice
removed all paged-out state. Unreported data and subsequent guest reuse remained
intact. This exercised real compressed backing, not an unsupported pageout hint.

The report-before-pressure scenario was inconclusive in two runs at the same
1 GiB budget: neither the guest pages nor the host-advised control was evicted
within the deadline. Both remained resident, clean and uncompressed. Physical
discard in that scenario and a long-running Linux workload/network soak remain
necessary before claiming the original retention problem is fully resolved.

### Host-populated backing and Linux idle comparison

On 128 MiB backing, host population produced about 258 MiB of task footprint
after guest access. Reclaiming the 124 MiB interior cleared all reported page
ref/mod bits but left approximately 134 MiB charged. Content-preserving Mach
normalization reduced that to approximately 6 MiB while the clean pages remained
resident. Without host population, the extra charge did not appear. Host writes
after guest access reproduce the normalization benefit as well.

Two isolated 512 MiB Linux VMs then ran the same 128 MiB buffered virtio-block
read, cache drop, compaction and 65-second idle workload. Baseline libkrun stayed
at approximately 210 MiB footprint; the maintenance build dropped from 212 MiB
to 62 MiB at the first 30-second interval. Both guests had about 20 MiB in use.
The VM-object accounting category stayed near 179 MiB in both runs. These are
mapping-accounting results, not proof of an equivalent physical-RAM reduction.
The native test drivers used identical source and registry dependency versions.

Kernel reference: XNU `xnu-12377.1.9`,
[`vm_object_deactivate_pages`](https://github.com/apple-oss-distributions/xnu/blob/xnu-12377.1.9/osfmk/vm/vm_object.c#L2627)
and the
[ARM64 SPTM bulk pmap walk](https://github.com/apple-oss-distributions/xnu/blob/xnu-12377.1.9/osfmk/arm64/sptm/pmap/pmap.c#L7010).
The inspected public release is older than the running host kernel; real-HVF
regressions remain important across hardware and OS updates.

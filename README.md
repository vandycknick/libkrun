<picture>
   <source media="(prefers-color-scheme: dark)" srcset="docs/images/libkrun_logo_horizontal_darkmode.png">
   <source media="(prefers-color-scheme: light)" srcset="docs/images/libkrun_logo_horizontal.png">
   <img alt="libkrun logo" src="docs/images/libkrun_logo_horizontal_200.png">
</picture>

# libkrun

```libkrun``` is a dynamic library that allows programs to easily acquire the ability to run processes in a partially isolated environment using [KVM](https://www.kernel.org/doc/Documentation/virtual/kvm/api.txt) Virtualization on Linux and [HVF](https://developer.apple.com/documentation/hypervisor) on macOS/ARM64.

It integrates a VMM (Virtual Machine Monitor, the userspace side of an Hypervisor) with the minimum amount of emulated devices required to its purpose, abstracting most of the complexity that comes from Virtual Machine management, offering users a simple C API.

> [!NOTE]
> The `main` branch is now **libkrun 2.0**, which will not be backwards
> compatible with the 1.x API/ABI. The 2.0 API is also still under active
> development and may change further before the first stable release. If
> you are building from source for production use, please use the newest
> [`stable-*` release branch](https://github.com/libkrun/libkrun/branches)
> instead.

## Use cases

* [crun](https://github.com/containers/crun/blob/main/krun.1.md): Adding Virtualization-based isolation to container and confidential workloads.
* [krunkit](https://github.com/containers/krunkit): Running GPU-enabled (via [venus](https://docs.mesa3d.org/drivers/venus.html)) lightweight VMs on macOS.
* [muvm](https://github.com/AsahiLinux/muvm): Launching a microVM with GPU acceleration (via [native context](https://www.youtube.com/watch?v=9sFP_yddLLQ)) for running games that require 4k pages.

## Goals and non-goals

### Goals

* Enable other projects to easily gain KVM-based process isolation capabilities.
* Be self-sufficient (no need for calling to an external VMM) and very simple to use.
* Be as small as possible, implementing only the features required to achieve its goals.
* Have the smallest possible footprint in every aspect (RAM consumption, CPU usage and boot time).
* Be compatible with a reasonable amount of workloads.

### Non-goals

* Become a generic VMM.
* Be compatible with all kinds of workloads.

## Variants

This project provides the following variants of the library:

- **libkrun**: Generic variant compatible with all Virtualization-capable systems.
- **libkrun-sev**: Variant including support for AMD SEV (SEV, SEV-ES and SEV-SNP) memory encryption and remote attestation. Requires an SEV-capable CPU.
- **libkrun-tdx**: Variant including support for Intel TDX memory encryption. Requires a TDX-capable CPU.

Each variant generates a dynamic library with a different name (and ```soname```), so both can be installed at the same time in the same system.

## Virtio device support

### All variants

* virtio-console
* virtio-block
* virtio-fs
* virtio-gpu (venus and native-context)
* virtio-net
* virtio-vsock (for TSI and socket redirection)
* virtio-balloon (only free-page reporting)
* virtio-rng

On Linux, free-page reporting reclaims boot RAM (including capture-tracked RAM)
with `MADV_DONTNEED`. Restored file-private RAM is replaced with anonymous
private zero pages at the same addresses, leaving the checkpoint and sibling
VMs unchanged. Both paths mark the host dirty bitmap before discarding, so an
incremental image writes explicit zeros over any nonzero baseline.
Adjacent restored report ranges are coalesced. Replaced islands are bounded by
half the remaining `vm.max_map_count` budget after existing mappings and a
fixed 1024-mapping VMM reserve. Mapping-budget skips and `mmap` `ENOMEM` are
acknowledged without discarding; status exposes `mapping_limit_skips` and
`replaced_islands` alongside released bytes and operations. These counters are
process-local and do not change persisted balloon state. macOS tracked and
restored reclaim is unchanged and remains inhibited.

The Silo fork completes successful virtio-block DISCARD and WRITE_ZEROES requests
with the entire requested range reading as zero, including partial host blocks
and the device tail, without changing logical length or capacity. DISCARD uses
Imago's zero-preserving operation, including its explicit-zero fallback when
hole punching is unavailable. Hypervisor-free real Raw-device regressions run
with `cargo test --locked -p krun-devices --features blk zero_range`.

## Native completed control (Rust)

`krun::api::VmmHandle` provides exact-token control outside generated FFI.
Types and the dependency-owned barrier identities are available from
`krun::api::control`:

```rust,ignore
pause(owner: PauseOwner, operation: OperationId, deadline: Instant) -> Result<PauseToken, ControlFailure>
resume(token: PauseToken, operation: OperationId, deadline: Instant) -> Result<(), ControlFailure>
cancel_pause(pausing: OperationId, operation: OperationId, deadline: Instant) -> Result<(), ControlFailure>
control_state(deadline: Instant) -> Result<ControlState, ControlFailure>
stop(operation: OperationId, deadline: Instant) -> Result<(), ControlFailure>
```

Call from another thread while `Vmm::run` services the owner loop. Mutation
operation IDs must strictly increase; request IDs and pause generations are
separate. Each operation uses one absolute deadline. A caller timeout, dropped
reply receiver, or accepted command followed by a failed kick never cancels
VM-owned work. Observe the actual state, explicitly cancel the named incomplete
pause, or stop. A completed pause requires its opaque run-bound token; stale,
foreign, wrong-owner and consumed tokens cannot authorize release. There is no
implicit resume on drop.

Pause preflights the existing device/legacy inventory before mutation. CPUs
complete exit emulation before acknowledging park; device queues, callbacks,
host maintenance and actual interrupt routes must also finish before any
whole-machine token can issue. Resume prepares routes, devices and common
timer control before the correlated CPU release acknowledgements. Ambiguous
release becomes stop-only `FailedFenced`, not a claim that CPUs stayed parked.
Stop polls and reaps real CPU owner threads and route workers, then uses the
existing whole-machine process exit/observer boundary. It does not grant a
reusable in-process stopped VM while concrete device termination providers
remain unavailable. Terminal cleanup outside event callbacks may wait for
native termination rather than free RAM or detach a still-running owner thread
when a caller's deadline expires.

Phase 8 does **not** supply production device providers. Ordinary attached
devices and uncovered legacy topology therefore refuse whole-machine pause;
all native live-operation bits remain false and public operations remain
not delivered. The former enqueue-only FFI pause/resume methods and their
idempotent-success test are removed, with no compatibility aliases.

The developer-only [`native-control-probe`](docs/native-control-probe.md)
uses the same CPU controller and native mailbox/completion loop, without
granting whole-machine support:

```sh
cargo run --locked -p libkrun --features native-control-probe --example native-control-probe
```

The diagnostic feature does not grant public live operations. CPU-only evidence
is not device-barrier or macOS/arm64 qualification.

## Native live-state observations (Rust)

The Silo fork exposes a Rust-only, machine-less query in
`krun::api::capabilities`, outside generated FFI:

```rust
pub const LIVE_STATE_SCHEMA: &str = "silo.live-state/1";
pub fn live_state_schema() -> &'static str;
pub fn guest_architecture() -> &'static str;
pub fn query_live_host() -> NativeHostReport;
```

Query ABI `LIVE_QUERY_ABI = 1` is distinct from the package/C ABI and state
encoding schemas. The Rust native API used by Silo exposes the schema accessor
without generated FFI or build-time source inspection.
The adapter-facing types are:

```rust
NativeHostReport {
    live_state_schema: &'static str,
    architecture: &'static str,
    lane: NativeLane,
    kvm: KvmHostFacts,
    kvm_prerequisites: KvmPrerequisites,
    hvf: HvfHostFacts,
    operations: NativeLiveOperations,
}
```

All fields above are public. `NativeLane` distinguishes `KvmX86_64`,
`KvmArm64GicV3`, `HvfArm64GicV3`, and `Unsupported`. A lane is a candidate,
not admission of a VM or GIC. TEE, AWS Nitro and control-probe profiles receive
`Unsupported` without KVM/HVF host probing. Nested virtualization remains a
per-VM runtime setting, not a host-query compatibility decision.

Live-state compatibility depends only on `LIVE_STATE_SCHEMA` and guest
architecture. Bump the summary schema whenever an execution, CPU, RAM-layout,
device or legacy encoding changes. Every native binary state codec owns an
eight-byte magic and `u16` schema checked before reading its body; RAM layout
retains canonical JSON, with `magic: "KRUNRAML"` and its existing numeric schema.
Magic/schema errors retain typed expected and found values. Capture/run,
profile, topology and RAM-layout digests still prevent mixing objects from
different cuts; they are not source-build compatibility gates.

No Git command, source hashing, compiler inventory or checkout cleanliness
observation participates in compilation or restore compatibility.

Host values use `Observation<T>`:
`Observed(T)`, `Unavailable(NativeQueryError)`, `NotEvaluated`, or
`NotApplicable`. Errors retain `QueryOperation`, optional raw OS errno and
`std::io::ErrorKind`. Linux opens one close-on-exec `/dev/kvm` system fd,
reads API version and integer `KVM_CHECK_EXTENSION` values for `Irqchip`,
`Ioeventfd`, `Irqfd`, `UserMemory`, target-specific `SetTssAddr`/`ArmPsci02`,
and `ImmediateExit`. Positive payloads are not reduced to booleans; errors
are not reduced to absent capabilities. `KvmHostFacts` contains `access`,
`api_version`, a fixed seven-entry `capabilities` array of
`KvmCapabilityFact { capability, value }`, and `gic_model`. The latter stays
not evaluated on arm64. `reduce_kvm_prerequisites(NativeLane, &KvmHostFacts)`
returns `SystemQueriesAvailable`, `NotApplicable`, `Incomplete`,
`Unavailable(error)`, `ApiMismatch { observed, required }`, or
`MissingCapability(capability)`. Successful system queries do not establish
that VM construction will succeed.

`HvfHostFacts` retains `framework`, `vm_admission` and `gic_model`, each
`Observation<()>`. On an eligible arm64 macOS lane the query fallibly loads
Hypervisor.framework and resolves addresses only. Framework load failure is
`Unavailable` with `QueryOperation::LoadHvfFramework`, unknown errno and
`ErrorKind::Other`; detailed loader diagnostics are logged. Excluded profiles
and non-HVF targets report `NotApplicable` without framework access.
VM admission and the selected model remain `NotEvaluated` in this machine-less query.

The additional `gic_symbols: Observation<HvfGicSymbols>` records all six
addresses, individually accessible through `contains(HvfGicSymbol)`.
`gic_blob_symbols` and `gic_icc_symbols` separately report
`Observation<HvfSymbolGroup>` (`Available` or the first `Missing(symbol)`).
The blob group is exactly `hv_gic_state_create`, `hv_gic_state_get_size`,
`hv_gic_state_get_data`, `hv_gic_set_state`. CPU registers are excluded from
the blob and require both `hv_gic_get_icc_reg` and `hv_gic_set_icc_reg`.
All six are optional runtime lookups; none is invoked during discovery.
The owned framework context retains copied function pointers, and touched
VM/GIC configuration constructors release their OS objects on every path.

On macOS arm64, the Rust-only `VmmHandle::hvf_vm_facts()` reports the actual
builder-selected `Observation<HvfGicModel>` (`NativeGicV3` or
`UserspaceGicV3`) and the VM's nested setting. Missing optional state APIs
do not prevent cold boot or change its existing userspace-GIC fallback.
`reduce_hvf_gic_admission(lane, host, vm, providers_complete)` is a pure
prerequisite reducer: it refuses unknown facts, missing symbols, userspace
GICs, nested profiles and incomplete providers. Even
`HvfGicAdmission::PrerequisitesAvailable` grants no live operation or host
qualification. Provider completeness remains a per-VM admission predicate,
independent of whether the native pause primitive is implemented.
Actual macOS compile/link/optional-import checks and older-host cold boot
remain unverified, owner Phase 25 (`pending-lane:hvf`).
No query creates a VM/vCPU/GIC, installs signals, allocates guest RAM,
executes guest code, or performs capture/restore/reclaim probes.

`NativeLiveOperations` has `pause`, `capture`, `restore`, `fork` and
`incremental`, each `NativeOperationSupport`. For the recognized
`KvmX86_64`, `KvmArm64GicV3` and `HvfArm64GicV3` lanes, `pause` is
`Supported`: the native whole-machine pause primitive is implemented.
The other four operations remain `Unsupported(NotImplemented)`.
The `Unsupported` lane returns `Unsupported(BuildExcluded)` for all five
operations, including diagnostic probe builds excluded by lane selection.
Native support describes implementation, not host/VM admission, runtime
qualification or delivery of public Silo live operations. Pause still requires
the actual host APIs, admitted execution/controller profile and complete
providers for every attached device. KVM arm64 and HVF runtime qualification
remain pending; public qualification remains false and all public Silo live
operations remain not delivered. API presence and accessible host APIs alone
grant neither VM admission nor public operations.

Run the standalone query explicitly (not as a Cargo test):

```sh
make live-capabilities BLK=1 NET=1
# For an already built example, audit only its query syscalls:
strace -f -e trace=openat,ioctl,close target/debug/examples/live_capabilities
```

The audited hypervisor-free unit selection is:

```sh
cargo test --locked -p libkrun --features blk,net --lib api::capabilities::tests::native_live_
```

Those tests exercise real schema accessors and pure capability reducers,
never the runtime host query.
Do not replace this filter with wholesale fork tests: existing unrelated
tests construct real VMs.

### Internal device/callback quiescence contracts

The transport/provider contracts are internal Rust APIs supporting the native
pause primitive, not delivered public live operations. Real devices still
refuse quiescence unless they explicitly supply `VirtioStateProvider`; an
inactive device or an empty queue is not a provider. These contracts alone
grant neither per-VM admission nor native lane qualification, and enable no
public live-operation bit.

All participants use `polly::event_manager::BarrierRequest { key, deadline }`,
where `BarrierKey { operation: OperationId, generation: BarrierGeneration }`
distinguishes the operation from its pause generation. One absolute `Instant`
deadline covers each transition. Cancellation/resume names the original cut
and supplies a different operation in the same generation with its own deadline.
Caller timeout/drop does not cancel accepted work or reopen admission.

`EventManager` checks `DispatchRole` before **each** callback, including a
previously fetched ready batch. Existing registrations default to `Ingress`.
The owner classifies `Control`, `Exit` and provider-gated `Completion` fds
before starting a barrier. `begin_ingress_fence` admits drain completions;
`park_callbacks` subsequently admits only control/exit. Mixed ingress/completion
callbacks require provider-side ingress closure before using `Completion`.
Suppressed interests are removed from polling to avoid a paused busy loop,
without reading their endpoints. Cached readiness is retained and replayed
after `reopen_ingress`; registration identities prevent stale ready events
from being delivered to a replacement registration of the same fd.

Both native MMIO managers retain typed transports in attachment order, including
configured IDs, addresses and IRQs, in `DeviceQuiescence`. Its begin/poll journal
keeps accepted transitions and errors. `quiescence_settled` observes whether
accepted old work has actually returned ownership, including late returns after
a deadline. It is for explicit cancellation reconciliation, not permission to
issue a token despite a failed operation. `fully_quiesced` additionally requires
every attachment and refuses uncovered legacy participants. Source resume
touches only accepted participants and never resets untouched devices.
These device-only observations are not a CPU/callback/maintenance/IRQ barrier.

KVM registration and live route work share the existing manager-owned route
inventory. Dedicated virtio lines have one notifier each; x86 virtio IRQ15
members share one notifier/registration while retaining independent transport
status and ACK state. The five existing legacy event/GSI registrations remain
five distinct routes, including COM1/3 on GSI4 and COM2/4 on GSI3. Sink UARTs,
CMOS, i8042 and attached arm64 legacy devices retain typed ownership and refuse
live admission until real legacy providers exist.

After producers settle, `begin_irq_fence(Arc<VmFd>, request)` runs actual KVM
IRQFD deassignment on an owned worker. `poll_irq_routes` never joins before
the worker is finished; late polling recovers every route's actual registration
state even after timeout. The route vector and VM stay owned during native
calls and errors. `irq_completion_event` supplies the existing owner loop's
completion wakeup. Deassignment is not exercised by pure tests. Before source
release, `begin_irq_rearm` restores each detached registration once, then the
owner resumes devices/queue scans, reopens callback ingress, and releases CPUs
last. Ambiguous worker/controller faults cannot be treated as successful rearm.
HVF retains synchronous interrupt-source/controller ownership instead of
inventing a KVM IRQFD boundary; its real native/controller lane remains
unqualified until platform execution evidence exists.

Hypervisor-free selections for these new seams (not native IRQ/VM proof):

```sh
cargo test --locked -p krun-polly --lib event_manager::tests::callback_
cargo test --locked -p libkrun --features blk,net --lib vmm::device_manager::quiescence::tests::
cargo test --locked -p libkrun --features blk,net --lib vmm::device_manager::kvm::mmio::tests::quiescence_route_
cargo test --locked -p libkrun --features blk,net --lib vmm::device_manager::legacy::tests::legacy_inventory_
# On the macOS lane, not a Linux qualification:
cargo test --locked -p libkrun --features blk,net --lib vmm::device_manager::hvf::mmio::tests::hvf_route_inventory_
```

These selections use real eventfds, cached ready events, route ownership and
default-provider refusals. None constructs a VM or calls a hypervisor. Native
route drain/rearm, CPU parking, actual device providers and complete host-writer
coverage require their separate execution gates; passing a pure reducer or
empty participant set does not establish a whole-machine cut.


## Networking

In ```libkrun```, networking is provided by two different, mutually exclusive techniques: **virtio-vsock + TSI** and **virtio-net + passt/gvproxy**.

### virtio-vsock + TSI

This is a novel technique called **Transparent Socket Impersonation** which allows the VM to have network connectivity without a virtual interface. This technique supports both outgoing and incoming connections. It's possible for userspace applications running in the VM to transparently connect to endpoints outside the VM and receive connections from the outside to ports listening inside the VM.

#### Enabling TSI

TSI for AF_INET and AF_INET6 is automatically enabled when no network interface is added to the VM. TSI for AF_UNIX is enabled when, in addition to the previous condition, the root filesystem has been configured with `/` as the shared directory.

#### Known limitations

- Requires a custom kernel (like the one bundled in **libkrunfw**).
- It's limited to SOCK_DGRAM and SOCK_STREAM sockets and AF_INET, AF_INET6 and AF_UNIX address families (for instance, raw sockets aren't supported).
- Listening on SOCK_DGRAM sockets from the guest is not supported.
- When TSI is enabled for AF_UNIX sockets, only absolute path are supported as addresses.

#### Native mux state provider

The native Silo Unix control mux has an internal state provider, separate from
TSI. Its reversible source barrier parks the actual mux, deferred reaper and
macOS timesync owners and retains their thread handles, sessions, credits,
partial SCM_RIGHTS frames and original operation deadlines. RX, TX and the
event queue transfer to transport escrow exactly once. Protocol-failure
`ControlHandle::fence` is destructive and is not this barrier.

Frontend and worker pollers independently own their descriptors to the same
polling instance. `Epoll::try_clone` performs fallible descriptor duplication
before worker startup; dropping either owner cannot close the other's descriptor
or an unrelated descriptor subsequently reused by the process.

Restore requires a fresh constructor-supplied control endpoint and listener
bindings, plus `Vsock::bind_restore_control_service` with the trusted guest
agent service port. The device payload contains no host path or descriptor.
Prepared installation starts no worker, scans no queue and writes no guest
memory. At release it discards old queued TX, retains a real pending
`VIRTIO_VSOCK_EVENT_TRANSPORT_RESET` until an event buffer can receive it, and
admits only the bound agent control service after reset delivery. Other
sessions remain fenced until the generation-correlated activation release.
Source cancellation instead resumes the same owners and resources without a
virtio reset. TSI and other non-native-mux profiles remain explicitly refused.

Hypervisor-free `provider_vsock_` regressions exercise actual queues and Unix
SCM_RIGHTS streams. They do not qualify a runtime lane. Busy guest traffic,
credit exhaustion, deferred expiry, reset/reconnect, fresh-process restore and
shared native IRQ delivery still require the production device gates; macOS
timesync execution remains pending its actual host lane.


### **virtio-net + passt/gvproxy**

A conventional virtual interface that allows the guest to communicate with the outside through the VMM using a supporting application like [passt](https://passt.top/passt/about/) or [gvproxy](https://github.com/containers/gvisor-tap-vsock).

#### Enabling virtio-net

Use `krun_add_net_unixstream` and/or `krun_add_net_unixdgram` to add a virtio-net interface connected to the userspace network proxy.

## Security model

The libkrun security model is primarily defined by the consideration that both the guest and the VMM pertain to the same security context. For many operations, the VMM acts as a proxy for the guest within the host. Host resources that are accessible to the VMM can potentially be accessed by the guest through it.

While defining the security implementation of your environment, you should think about the guest and the VMM as a single entity. To prevent the guest from accessing host's resources, you need to use the host's OS security features to run the VMM inside an isolated context. On Linux, the primary mechanism to be used for this purpose is namespaces. Single-user systems may have a more relaxed security policy and just ensure the VMM runs with a particular UID/GID.

While most virtio devices allow the guest to access resources from the host, two of them require special consideration when used: virtio-fs and virtio-vsock+TSI.

### virtio-fs

When exposing a directory in a filesystem from the host to the guest through virtio-fs devices configured with `krun_add_virtiofs*`, libkrun **does not** provide any protection against the guest attempting to access other directories in the same filesystem, or even other filesystems in the host.

A mount point isolation mechanism from the host should be used in combination with virtio-fs.

In addition, when using virtio-fs, a guest may exhaust filesystem resources such as inode limits and disk capacity. Controls should be implemented on the host to mitigate this.

### virtio-vsock + TSI

When TSI is enabled, the VMM acts as a proxy for AF_INET, AF_INET6 and AF_UNIX sockets, for both incoming and outgoing connections. For all that matters, the VMM and the guest should be considered to be running in the network context. As such, you should apply on the VMM whatever restrictions you want to apply on the guest.

## Building and installing

The direct `vmm-sys-util` dependencies used by the KVM path share the version
requirement of `kvm-bindings` and `kvm-ioctls`. Keep these requirements aligned:
FAM errors, eventfds and errno values cross crate boundaries and must use the
same resolved utility version. A consuming application's lockfile can select
0.14 or 0.15; the optional vhost-user dependency separately requires 0.15.

### Linux

For non-TEE x86_64 direct boot, an external initramfs is placed at a page-aligned
address below the MMIO gap, even when guest RAM extends above that gap. Its boot
header retains the exact payload byte length; callers do not need to pad the
initramfs to a page boundary.

On x86_64 KVM, MMIO transports use the existing routed IRQ range. The last IRQ
is a shared line: its manager-owned eventfd is registered with KVM once, and
additional transports retain references to that same notifier. Each transport
keeps independent interrupt status and acknowledgement state. Dropping or
resetting one device does not close or drain another device's shared notifier.
Other architectures and host backends retain their existing allocation policy.

Future device-state capture must retain this notifier-sharing topology and
restore one KVM irqfd registration per shared line, not one per device.
Per-transport pending status remains separate; quiescing or draining a shared
notification source requires coordinating every device attached to that line.

#### Requirements

* [libkrunfw](https://github.com/containers/libkrunfw)
* A working [Rust](https://www.rust-lang.org/) toolchain
* C Library static libraries, as the [init](init/init.c) binary is statically linked (package ```glibc-static``` in Fedora)
* patchelf

#### Optional features

* **GPU=1**: Enables virtio-gpu. Requires virglrenderer-devel.
* **VIRGL_RESOURCE_MAP2=1**: Uses virgl_resource_map2 function. Requires a virglrenderer-devel patched with [1374](https://gitlab.freedesktop.org/virgl/virglrenderer/-/merge_requests/1374)
* **BLK=1**: Enables virtio-block.
* **NET=1**: Enables virtio-net.


#### Compiling

```
make [FEATURE_OPTIONS]
```

#### Installing

```
sudo make [FEATURE_OPTIONS] install
```

### Linux (SEV variant)

#### Requirements

* The SEV variant of [libkrunfw](https://github.com/containers/libkrunfw), which provides a ```libkrunfw-sev.so``` library.
* A working [Rust](https://www.rust-lang.org/) toolchain
* C Library static libraries, as the [init](init/init.c) binary is statically linked (package ```glibc-static``` in Fedora)
* patchelf
* OpenSSL headers and libraries (package ```openssl-devel``` in Fedora).

#### Compiling

```
make SEV=1
```

#### Installing

```
sudo make SEV=1 install
```

### Linux (TDX variant)

#### Requirements

* The TDX variant of [libkrunfw](https://github.com/containers/libkrunfw), which provides a ```libkrunfw-tdx.so``` library.
* A working [Rust](https://www.rust-lang.org/) toolchain
* C Library static libraries, as the [init](init/init.c) binary is statically linked (package ```glibc-static``` in Fedora)
* patchelf
* OpenSSL headers and libraries (package ```openssl-devel``` in Fedora).

#### Compiling

```
make TDX=1
```

#### Installing

```
sudo make TDX=1 install
```

#### Limitations

The TDX flavor of libkrun only supports guests with 1 vCPU and memory less than or equal to 3072mib.

### macOS

#### Requirements

* A working [Rust](https://www.rust-lang.org/) toolchain
* A host running macOS 14 or newer
* Homebrew packages `lld` and `xz`

#### Compiling

```
make [FEATURE_OPTIONS]
```

The [init](init/init.c) binary is cross-compiled using clang and lld.
A suitable sysroot is automatically generated by the Makefile from Debian repository.

#### Installing

```
sudo make [FEATURE_OPTIONS] install
```

## Using the library

Despite being written in Rust, this library provides a simple C API defined in [include/libkrun.h](include/libkrun.h)

## Examples

### chroot_vm

This is a simple example providing ```chroot```-like functionality using ```libkrun```.

#### Building chroot_vm

To be able to ```chroot_vm```, you need need to build libkrun with the `virtio-block` and `virtio-net` optional features:

```
make BLK=1 NET=1
sudo make BLK=1 NET=1 install
cd examples
make
```

#### Running chroot_vm

To be able to ```chroot_vm```, you need first a directory to act as the root filesystem for your isolated program.

Use the ```rootfs``` target to get a rootfs prepared from the Fedora container image (note: you must have [podman](https://podman.io/) installed):

```
make rootfs
```

Now you can use ```chroot_vm``` to run a process within this new root filesystem:

```
./chroot_vm ./rootfs_fedora /bin/sh
```

If the ```libkrun``` and/or ```libkrunfw``` libraries were installed on a path that's not included in your ```/etc/ld.so.conf``` configuration, you may get an error like this one:

```
./chroot_vm: error while loading shared libraries: libkrun.so: cannot open shared object file: No such file or directory
```

To avoid this problem, use the ```LD_LIBRARY_PATH``` environment variable to point to the location where the libraries were installed. For example, if the libraries were installed in ```/usr/local/lib64```, use something like this:

```
LD_LIBRARY_PATH=/usr/local/lib64 ./chroot_vm rootfs_fedora/ /bin/sh
```

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines on submitting changes.

## Status

```libkrun``` has achieved maturity and starting version ```1.0.0``` the public API is guaranteed to be stable, following [SemVer](https://semver.org/).

## Getting in contact

If you think you've identified a security issue in the project, please DO NOT report the issue publicly via the GitHub issue tracker or Matrix. Instead, send an email with as many details as possible to `libkrun-security@redhat.com`. This is a private mailing list for the core maintainers.

The main communication channel is the [libkrun Matrix channel](https://matrix.to/#/#libkrun:matrix.org).

## Acknowledgments

```libkrun``` incorporates code from [Firecracker](https://github.com/firecracker-microvm/firecracker), [rust-vmm](https://github.com/rust-vmm/) and [Cloud-Hypervisor](https://github.com/cloud-hypervisor/).

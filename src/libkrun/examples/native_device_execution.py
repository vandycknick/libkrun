"""Closed whole-machine witnesses over the one real production Session driver."""
from fractions import Fraction
import json
import os
from pathlib import Path
import shutil
import signal
import subprocess
import time

from native_device_pressure import run as device_pressure

CASES = (("future", 1, "long_prepared_dwell"),
         ("due-no-irr", 3, "original_due_no_irr"),
         ("pending", 2, "original_pending"),
         ("pending-future", 5, "pending_plus_future"),
         ("masked", 4, "masked_unmask"),
         ("masked-future", 13, "masked_unmask"),
         ("in-service", 6, "in_service_eoi"),
         ("halted", 1, "halted_wake"),
         ("io", 7, "io_mmio_exact_once"),
         ("mmio", 8, "io_mmio_exact_once"),
         ("offline", None, "offline_start"))

# KVM-TSC-DEADLINE-EARLY: contextual upstream discussion, not a fixed-version claim.
# https://lkml.rescloud.iu.edu/2312.2/06707.html
# Revisit on host kernel updates and 2026-12-01; see docs/native-execution-probe.md.
TIMER_LIMITATION = "KVM-TSC-DEADLINE-EARLY"
TIMER_UPSTREAM = "https://lkml.rescloud.iu.edu/2312.2/06707.html"


def timer_delivery_observation(original, sample, case, label, original_path, sample_path, host):
    deadline = original["words"][7]
    isr_tsc = sample["words"][18]
    delta = ((isr_tsc - deadline + (1 << 63)) % (1 << 64)) - (1 << 63)
    return {"schema": "native-timer-delivery-v1", "tracking_id": TIMER_LIMITATION,
            "upstream_context": TIMER_UPSTREAM, "revisit_on": "2026-12-01",
            "status": "known-host-limitation" if delta < 0 else "not-observed",
            "blocking": False, "absolute_no_early_requirement": "not-gating",
            "original_deadline": deadline, "actual_isr_tsc": isr_tsc,
            "signed_delta_ticks": delta, "rate_khz": original["rates"][2],
            "host": host, "case": case, "continuation": label,
            "original_observation": str(original_path), "delivery_observation": str(sample_path)}


class ClockCorrelation:
    """Retain one measured guest affine relation, independent of KVM's kHz rate."""

    def __init__(self, samples):
        self.samples = []
        self.lower = Fraction(0)
        self.upper = None
        self.observe(samples)
        if len(self.samples) < 2 or self.lower <= 0 or self.upper is None:
            raise RuntimeError("original guest clock calibration lacks separated brackets")
        self.original = tuple(self.samples)
        self.original_bounds = (self.lower, self.upper)

    def observe(self, samples):
        for sample in samples:
            point = (sample["tsc_before"], sample["mono_before"], sample["mono_after"])
            if point[1] > point[2]:
                raise RuntimeError("guest monotonic bracket runs backwards")
            if point in self.samples:
                continue
            for previous in self.samples:
                before, after = sorted((previous, point))
                ticks = after[0] - before[0]
                low_ns, high_ns = after[1] - before[2], after[2] - before[1]
                # Each TSC read occurred inside its measured monotonic interval.
                # A common slope and intercept exist iff every pair admits them.
                if high_ns < 0 or high_ns == 0 and ticks:
                    raise RuntimeError("original TSC/monotonic affine relation changed")
                if high_ns > 0:
                    self.lower = max(self.lower, Fraction(ticks, high_ns))
                if low_ns > 0:
                    upper = Fraction(ticks, low_ns)
                    self.upper = upper if self.upper is None else min(self.upper, upper)
                if self.upper is not None and (self.upper <= 0 or self.lower > self.upper):
                    raise RuntimeError("original TSC/monotonic affine relation changed")
            self.samples.append(point)

    def record(self):
        def ratio(value):
            return [value.numerator, value.denominator]

        return {"bracket_fields": ["tsc_before", "mono_before", "mono_after"],
                "original_brackets": self.original,
                "original_ticks_per_ns": [ratio(value) for value in self.original_bounds],
                "compatible_ticks_per_ns": [ratio(self.lower), ratio(self.upper)],
                "observed_brackets": len(self.samples)}


class Execution:
    def __init__(self, args, session_type, seal, save, digest, echo):
        self.args, self.session_type, self.seal = args, session_type, seal
        self.save, self.digest, self.echo = save, digest, echo
        self.sequence = 0
        self.witnesses = {}
        self.identity = None
        self.boot_identity = None
        self.register_pid = None
        self.offsets = None
        self.rates = None
        self.clock_relation = None

    def retain(self, name, *paths):
        result = self.witnesses.setdefault(name, [])
        for path in paths:
            path = Path(path)
            if path not in result:
                result.append(path)
        if len(result) > 64:
            raise RuntimeError(f"unbounded {name} witness")

    def snapshot(self, session, label, case=None):
        self.sequence += 1
        path = session.directory / f"execution-{self.sequence}-{label}.json"
        command = f"witness-cut {case} {path}" if case else f"witness-snapshot {path}"
        session.command(command)
        sample = json.loads(path.read_text())
        self.irq_complete(sample)
        if self.rates is not None and sample["rates"] and sample["rates"] != self.rates:
            raise RuntimeError("original native per-CPU TSC rates changed")
        return sample, path

    @staticmethod
    def irq_complete(sample):
        publication = sample.get("irq_publication")
        if not isinstance(publication, list) or len(publication) != 2 or any(
                type(value) is not int or not 0 <= value < (1 << 64) for value in publication):
            raise RuntimeError("missing actual guest IRQ publication epochs")
        return publication[0] == publication[1] and not publication[0] & 1

    def wait(self, session, label, predicate):
        deadline = time.monotonic() + 10
        while True:
            sample, path = self.snapshot(session, label)
            if self.irq_complete(sample) and predicate(sample):
                return sample, path
            if time.monotonic() >= deadline:
                raise RuntimeError(f"actual guest witness timeout: {label}")
            session.pump(.005)

    def kernel_continues(self, session, previous):
        old_registers = session.registers[-1] if session.registers else None
        old_clock = session.clock_brackets[-1]["sequence"] if session.clock_brackets else 0
        session.progress(previous)
        session.until(lambda: session.registers and len(session.clock_brackets) >= 2
            and session.clock_brackets[-1]["sequence"] > old_clock
            and (old_registers is None or (session.registers[-1]["sequence"] > old_registers["sequence"]
                and all(new["progress"] > old["progress"] for new, old in zip(session.registers[-1]["cpus"], old_registers["cpus"])))),
            "original live sentinels and fresh clock brackets")
        session.profile()
        if session.observations["kernel-identity"] != self.identity or session.observations["boot-identity"] != self.boot_identity:
            raise RuntimeError("original ordinary kernel boot identity changed")
        registers = session.registers[-1]
        if self.register_pid is None:
            self.register_pid = registers["pid"]
        if registers["pid"] != self.register_pid:
            raise RuntimeError("restored guest replaced original live-register process")
        if any(cpu["failed"] or cpu["progress"] == 0 for cpu in registers["cpus"]):
            raise RuntimeError("original live register process failed")
        # A primary bracket encloses a freshly acknowledged AP sample, not a
        # comparison between two old per-CPU RAM fields.
        offsets, _ = self.snapshot(session, "clock-offsets")
        if self.offsets is None or self.rates is None or self.clock_relation is None:
            raise RuntimeError("clock witness lacks original native affine relation")
        correction = (self.offsets[1] - self.offsets[0]) & ((1 << 64) - 1)
        for sample in session.clock_brackets[-4:]:
            adjusted = (sample["tsc_ap"] - correction) & ((1 << 64) - 1)
            if not sample["tsc_before"] <= adjusted <= sample["tsc_after"]:
                raise RuntimeError("contemporary primary/AP TSC bracket failed")
            if not sample["mono_before"] <= sample["mono_ap"] <= sample["mono_after"]:
                raise RuntimeError("contemporary primary/AP monotonic bracket failed")
        brackets = session.clock_brackets[-4:]
        self.clock_relation.observe(brackets)
        record = session.directory / f"continuation-{self.sequence}.json"
        self.save(record, {"registers": registers, "clock_brackets": session.clock_brackets[-4:],
                           "devices": session.samples[-1], "device_baseline": session.last_device_counter_observation,
                           "offset_observation": offsets, "clock_relation": self.clock_relation.record()})
        self.retain("live_xstate", record)
        self.retain("contemporary_clock_bracket", record)
        return record

    def reset(self, session):
        session.command("witness-arm 12")
        self.wait(session, "reset", lambda s: s["words"][4] == 12)
        # Observe any already accepted previous cause before establishing the
        # next case's baseline, never delete it with a native state setter.
        session.pump(.02)
        baseline, _ = self.snapshot(session, "baseline")
        if not self.irq_complete(baseline):
            raise RuntimeError("baseline captured an incomplete actual guest IRQ publication")
        return baseline

    def arm(self, session, case, number):
        baseline = self.reset(session)
        if number is not None:
            session.command(f"witness-arm {number}")
            if case in ("due-no-irr", "io", "mmio"):
                self.wait(session, "owned-emulation", lambda s: s["bus_held"])
                if case == "due-no-irr":
                    # The original compare expires while its real MMIO completion
                    # owns this vCPU, before another KVM_RUN can materialize IRR.
                    session.pump(0.6)
            elif case in ("pending", "pending-future", "masked", "in-service"):
                self.wait(session, "original-cause", lambda s: s["words"][8] == 1)
            else:
                self.wait(session, "original-armed", lambda s: s["words"][4] == number)
        session.command("pause")
        native, path = self.snapshot(session, f"original-{case}", case)
        if not self.irq_complete(native):
            raise RuntimeError("original native cut interrupted guest IRQ publication")
        self.retain("native_pit_predicate", path.with_suffix(".native.txt"))
        return baseline, native, path

    def time_plan(self, session, case, original, observed):
        clock, offsets = observed["clock"], observed["time_offsets"]
        if clock is None or offsets is None or observed["preparation_key"] is None or session.last_release is None:
            raise RuntimeError("native clock preparation lacks actual paired observations/acknowledged plan")
        if clock["source"] != original["cut_clock"] or len(offsets) != len(original["offsets"]):
            raise RuntimeError("native preparation does not bind the original whole-machine cut")
        source_ns, _, source_tsc, _ = clock["source"]
        destination_ns, _, destination_tsc, _ = clock["destination"]
        if destination_ns < source_ns:
            raise RuntimeError("native paired clock moved behind retained source")
        rate = original["rates"][2]
        advance = (destination_ns - source_ns) * rate // 1000000
        mask = (1 << 64) - 1
        expected = [(offset + source_tsc - destination_tsc + advance) & mask for offset in original["offsets"]]
        if offsets != expected:
            raise RuntimeError("actual acknowledged native affine clock plan differs")
        remaining = None
        if case in ("future", "halted", "pending-future", "masked-future"):
            remaining = (original["deadlines"][2] - source_tsc - original["offsets"][2]) & mask
            preparation_ticks = session.last_release["duration_ns"] * rate // 1000000
            if not 0 < remaining < (1 << 63) or advance >= remaining or preparation_ticks >= remaining:
                raise RuntimeError("original future residual was consumed by native final preparation")
        path = session.directory / f"clock-plan-{self.sequence}.json"
        self.save(path, {"original_clock": original["cut_clock"], "original_offsets": original["offsets"],
            "original_deadline": original["deadlines"][2], "clock": clock, "acknowledged_offsets": offsets,
            "preparation_key": observed["preparation_key"], "rate_khz": rate, "advance_ticks": advance,
            "original_remaining_ticks": remaining, "release": session.last_release})
        self.retain("contemporary_clock_bracket", path)
        if case == "future":
            if session.prepared and session.last_release["command"] == "release":
                if session.last_release["prepared_dwell_ns"] < 2000000000:
                    raise RuntimeError("long prepared dwell was not actually held")
            self.retain("long_prepared_dwell", path)
        return path

    def continue_case(self, session, case, baseline, original, label, original_path):
        before = baseline["words"]
        if case in ("masked", "masked-future"):
            start, _ = self.snapshot(session, "masked-entry")
            unchanged, _ = self.wait(session, "still-masked",
                lambda s: s["words"][2] > start["words"][2])
            if unchanged["words"][5] != before[5] or not unchanged["words"][22] & (1 << 16):
                raise RuntimeError("original native LVT mask or masked expiry was not preserved")
            session.command("witness-arm 10")
        elif case in ("pending", "due-no-irr", "pending-future", "in-service"):
            session.command("witness-arm 11")
        elif case == "offline":
            session.command("witness-arm 9")
        expected = 2 if case == "pending-future" else 1
        if case == "in-service":
            expected = 1
        if case == "masked":
            # KVM retains a masked pending expiry behind a nonzero comparator.
            # A zero comparator with the validated empty IRR/ISR has no expiry.
            expected = int(original["deadlines"][2] != 0)
        if case in ("io", "mmio"):
            index = 12 if case == "io" else 13
            sample, path = self.wait(session, label, lambda s: s["words"][index] == before[index] + 1)
        elif case == "offline":
            sample, path = self.wait(session, label, lambda s: s["ap_started"] == 1)
        else:
            sample, path = self.wait(session, label, lambda s: s["words"][5] == before[5] + expected and s["words"][20] == before[20] + expected)
            if original["deadlines"][2] and sample["words"][7] != original["words"][7]:
                raise RuntimeError("guest original comparator was rewritten")
            if case in ("future", "halted", "pending-future", "masked-future"):
                timing_path = path.with_suffix(".timer-delivery.json")
                self.save(timing_path, timer_delivery_observation(original, sample, case, label,
                    original_path, path, dict(zip(("system", "node", "release", "version", "machine"), os.uname()))))
                self.retain("absolute_timer_delivery", timing_path, original_path, path)
        session.pump(.65)
        final, final_path = self.snapshot(session, f"{label}-exact-once")
        if not self.irq_complete(final):
            raise RuntimeError("exact-once sample interrupted guest IRQ publication")
        if final["words"][0] != 0x53494c4f or final["words"][1] != 1 or original["words"][1] != 1:
            raise RuntimeError("restored guest CPU was reseeded instead of continued")
        if case in ("io", "mmio"):
            index = 12 if case == "io" else 13
            if final["words"][index] != before[index] + 1:
                raise RuntimeError("original IO/MMIO completion repeated")
            expected_callbacks = original["bus_writes"] if label == "source" else 0
            if final["bus_writes"] != expected_callbacks:
                raise RuntimeError("actual original native IO/MMIO callback replayed")
        elif case != "offline" and (final["words"][5] != before[5] + expected or final["words"][20] != before[20] + expected):
            raise RuntimeError("original expiry/EOI lost or duplicated")
        return [path, final_path, self.time_plan(session, case, original, final)]

    def validate_partial_install(self, result, pid, expected_ids, cut):
        if not expected_ids:
            raise RuntimeError("partial-install expected owner topology is empty")
        fields = {"schema", "pid", "status", "partial_observation_succeeded",
            "release_may_have_run", "all_reaped", "expected_cpu_ids",
            "native_run_observers_complete", "native_run_observations_succeeded",
            "zero_first_instruction", "installed_ack_cpu_correct", "installed_ack_kind_correct",
            "installed_ack_succeeded", "cpu_batch_unreconciled", "ram_comparison_succeeded",
            "ram_unchanged", "ram_first_difference", "actual_installed_ack_retained",
            "run_attempts_before_reap", "run_attempts_after_reap"}
        if set(result) != fields or result["schema"] != "native-device-partial-install-v1":
            raise RuntimeError("partial-install evidence schema mismatch")
        if type(result["pid"]) is not int or result["pid"] != pid or result["status"] != "passed":
            raise RuntimeError("partial-install native owner/status mismatch")
        required = ("partial_observation_succeeded", "all_reaped", "native_run_observers_complete",
            "native_run_observations_succeeded", "zero_first_instruction", "installed_ack_cpu_correct",
            "installed_ack_kind_correct", "installed_ack_succeeded", "cpu_batch_unreconciled",
            "ram_comparison_succeeded", "actual_installed_ack_retained")
        if any(result[name] is not True for name in required) or result["release_may_have_run"] is not False:
            raise RuntimeError("missing actual held-install/no-release/reap evidence")
        if result["expected_cpu_ids"] != expected_ids or any(type(cpu) is not int for cpu in result["expected_cpu_ids"]):
            raise RuntimeError("partial-install expected owner topology mismatch")
        for name in ("run_attempts_before_reap", "run_attempts_after_reap"):
            rows = result[name]
            if not isinstance(rows, list) or len(rows) != len(expected_ids):
                raise RuntimeError("partial-install incomplete native run observations")
            for cpu, row in zip(expected_ids, rows):
                if (not isinstance(row, dict) or set(row) != {"cpu_id", "attempts", "observed"}
                        or type(row["cpu_id"]) is not int or row["cpu_id"] != cpu
                        or row["observed"] is not True or type(row["attempts"]) is not int
                        or row["attempts"] != 0):
                    raise RuntimeError("partial-install native run attempted or unobserved through reap")
        if type(result["ram_unchanged"]) is not bool:
            raise RuntimeError("partial-install RAM diagnostic missing")
        difference = result["ram_first_difference"]
        if result["ram_unchanged"]:
            if difference is not None:
                raise RuntimeError("partial-install contradictory RAM diagnostics")
        else:
            expected_fields = {"region_index", "region_offset", "gpa", "file_offset", "expected", "actual"}
            if not isinstance(difference, dict) or set(difference) != expected_fields:
                raise RuntimeError("partial-install missing private RAM difference")
            if any(type(difference[key]) is not int or difference[key] < 0
                   for key in ("region_index", "region_offset", "gpa", "file_offset")):
                raise RuntimeError("partial-install invalid RAM difference coordinates")
            before, after = difference["expected"], difference["actual"]
            if (not isinstance(before, list) or not isinstance(after, list)
                    or not 1 <= len(before) <= 16 or len(before) != len(after)
                    or any(type(byte) is not int or not 0 <= byte <= 255 for byte in before + after)
                    or before[0] == after[0]):
                raise RuntimeError("partial-install invalid bounded RAM difference")
            with (cut / "memory.ram").open("rb") as source:
                source.seek(difference["file_offset"])
                if source.read(len(before)) != bytes(before):
                    raise RuntimeError("partial-install expected bytes differ from immutable source RAM")

    def child(self, cut, name, partial=False):
        directory = self.args.evidence / name
        disks = []
        for index in range(2):
            path = self.args.evidence / f"{name}-disk{index}.raw"
            shutil.copyfile(cut / f"disk{index}.raw", path)
            disks.append(path)
        return self.session_type.create(self.args, directory, disks, self.echo, restore=cut, partial=partial)

    def run(self):
        disks = []
        for index in range(2):
            path = self.args.evidence / f"execution-source-disk{index}.raw"
            with path.open("xb") as output:
                output.truncate(128 * 1024 * 1024)
            with path.with_suffix(".mkfs.log").open("xb") as log:
                subprocess.run(["mkfs.ext4", "-F", "-q", str(path)], check=True, timeout=60, stdout=log, stderr=subprocess.STDOUT)
            disks.append(path)
        source = self.session_type.create(self.args, self.args.evidence / "execution-source", disks, self.echo)
        try:
            source.start_mux(); previous = source.progress(); source.profile()
            self.identity = source.observations["kernel-identity"]
            self.boot_identity = source.observations["boot-identity"]
            source.until(lambda: len(source.clock_brackets) >= 2, "original guest clock calibration")
            self.clock_relation = ClockCorrelation(source.clock_brackets)
            source.command("pause")
            clock_cut, clock_path = self.snapshot(source, "original-clock-relation")
            self.offsets, self.rates = clock_cut["offsets"], clock_cut["rates"]
            calibration = source.directory / "original-clock-calibration.json"
            self.save(calibration, self.clock_relation.record())
            self.retain("contemporary_clock_bracket", calibration, clock_path, clock_path.with_suffix(".native.txt"))
            source.command(f"witness-init {self.args.witness_dir}")
            source.command("resume")
            self.wait(source, "one-source-initialization", lambda s: s["words"][0] == 0x53494c4f and s["words"][1] == 1)
            self.kernel_continues(source, previous)
            profile_paths = [source.directory / "profile" / name for name in ("kernel-identity", "boot-identity", "clocksource", "clockevents", "broadcast-clockevent")]
            self.retain("normal_kernel_profile", *profile_paths, source.directory / "command.json",
                        source.directory / "process.json", self.args.evidence / "inputs.json")
            for case, number, witness in CASES:
                previous = source.samples[-1].copy()
                baseline, original, original_path = self.arm(source, case, number)
                cut = self.args.evidence / f"execution-{case}-cut"
                source.command(f"capture {cut}")
                manifest = self.seal(cut)
                manifest_digest = self.digest(cut / "manifest.json")
                self.retain(witness, original_path, original_path.with_suffix(".native.txt"))
                self.retain("live_xstate", original_path.with_suffix(".native.txt"))
                if case == "future":
                    failed_output = source.command(f"capture {cut}", error=True)
                    source.pump(2)
                    os.kill(source.process.pid, signal.SIGWINCH)
                    source.pump(.1)
                    repeated = self.args.evidence / "execution-source-repeated-cut"
                    source.command(f"capture {repeated}")
                    repeated_manifest = self.seal(repeated)
                    if repeated_manifest != manifest:
                        raise RuntimeError("retained whole-machine cut changed after failed output/host stimulation")
                    repeated_path = source.directory / "repeat-after-output-error.json"
                    self.save(repeated_path, {"actual_output_error": failed_output, "original": manifest, "repeated": repeated_manifest})
                    self.retain("source_resume", repeated_path, cut / "manifest.json", repeated / "manifest.json")
                source.command("resume")
                self.retain(witness, *self.continue_case(source, case, baseline, original, "source", original_path))
                self.retain("source_resume", self.kernel_continues(source, previous))
                child = self.child(cut, f"execution-{case}-child")
                try:
                    child.pump(2 if case == "future" else .02)
                    if child.samples or child.registers:
                        raise RuntimeError("ordinary kernel instruction before prepared release")
                    # Native retained original cause is read before first entry.
                    restored, restored_path = self.snapshot(child, "prepared-original")
                    if (restored["words"] != original["words"] or restored["ap_started"] != original["ap_started"]
                            or restored["irq_publication"] != original["irq_publication"]):
                        raise RuntimeError("dormant destination mutated original guest witness")
                    if restored["deadlines"] != original["deadlines"] or restored["offsets"] != original["offsets"]:
                        raise RuntimeError("destination changed retained original native causes/clock relation")
                    if restored["release_may_have_run"] is not False:
                        raise RuntimeError("fresh native CPU release accepted before prepared observation")
                    child.command("release")
                    os.write(child.console, b"M\n")
                    self.retain(witness, restored_path, *self.continue_case(child, case, baseline, original, "child", original_path))
                    child.start_mux(); child.command("activate")
                    child.profile()
                    if child.observations["kernel-identity"] != self.identity:
                        raise RuntimeError("child replaced the ordinary production kernel")
                    self.kernel_continues(child, previous)
                    if case == "future":
                        self.retain("long_prepared_dwell", restored_path)
                        self.generations(child)
                        partial = self.child(cut, "execution-partial-install", partial=True)
                        try:
                            if partial.process.wait(timeout=10) != 0:
                                raise RuntimeError("partial native owner process failed terminal reap")
                            observation = partial.directory / "partial-install.json"
                            result = json.loads(observation.read_text())
                            self.validate_partial_install(result, partial.process.pid,
                                list(range(len(original["offsets"]))), cut)
                            partial.native_reaped = True
                            self.retain("partial_install_reaped", observation, observation.with_suffix(".native.txt"))
                            self.retain("partial_install_reaped", partial.directory / "process.json")
                        finally:
                            partial.close()
                    else:
                        self.reset(child)
                        previous_child = child.samples[-1].copy()
                        child.command("pause")
                        _, post_restore = self.snapshot(child, "post-restore-live-native", "steady")
                        self.retain("live_xstate", post_restore.with_suffix(".native.txt"))
                        child.command("resume")
                        self.kernel_continues(child, previous_child)
                    child.stop()
                finally:
                    child.close()
                observed_manifest = {
                    name: {"bytes": (cut / name).stat().st_size, "sha256": self.digest(cut / name)}
                    for name in manifest}
                if observed_manifest != manifest or self.digest(cut / "manifest.json") != manifest_digest:
                    raise RuntimeError("source continuation changed immutable child input")
                immutable = source.directory / f"immutable-input-{case}.json"
                self.save(immutable, {"cut": str(cut), "manifest_sha256": manifest_digest,
                    "expected": manifest, "observed": observed_manifest})
                self.retain("source_resume", immutable)
                if case == "future":
                    self.retain("partial_install_reaped", immutable, cut / "manifest.json")
            # The pressure implementation uses the same actual Session, providers,
            # ordinary-kernel state and bounded return contract, not canned passes.
            source.command("pause")
            pressure_cut = self.args.evidence / "execution-pressure-cut"
            source.command(f"capture {pressure_cut}"); self.seal(pressure_cut)
            source.command("resume")
            pressure = device_pressure(self.args, source, self.echo, pressure_cut)
            expected = {"busy_block", "busy_net", "busy_vsock", "busy_console", "balloon_rng_legacy", "shared_irq", "no_post_release_controller_rewrite"}
            if set(pressure) != expected:
                raise RuntimeError("pressure adapter returned an incomplete/foreign witness set")
            for name, paths in pressure.items():
                if not isinstance(paths, list) or not 1 <= len(paths) <= 64:
                    raise RuntimeError("pressure evidence contract bound")
                self.retain(name, *paths)
            self.unsupported(pressure_cut)
            source.stop()
            self.retain("source_resume", source.directory / "native-stop.json", source.directory / "process.json")
            return self.witnesses
        finally:
            source.close()

    def unsupported(self, cut):
        disks = []
        for index in range(2):
            path = self.args.evidence / f"execution-unsupported-disk{index}.raw"
            shutil.copyfile(cut / f"disk{index}.raw", path); disks.append(path)
        negative = self.session_type.create(self.args, self.args.evidence / "execution-unsupported", disks, self.echo, generic=True)
        try:
            negative.start_mux(); previous = negative.progress()
            negative.profile()
            negative.command("status")
            before = [line for line in negative.replies if line.startswith("CONTROL ")][-1]
            refusal = negative.command("pause", error=True)
            if "net0" not in refusal or "Unsupported" not in refusal:
                raise RuntimeError("unsupported actual participant was not named")
            negative.command("status")
            after = [line for line in negative.replies if line.startswith("CONTROL ")][-1]
            if before != after:
                raise RuntimeError("unsupported participant mutated the native controller")
            negative.progress(previous)
            path = negative.directory / "named-refusal.json"
            self.save(path, {"before": before, "refusal": refusal, "after": after, "progress": negative.samples[-1]})
            self.retain("unsupported_participant_named", path)
            terminal_stop = negative.blocked_console_stop()
            self.retain("unsupported_participant_named",
                        negative.directory / "blocked-console-stop.json",
                        negative.directory / "blocked-console-readiness.json",
                        Path(terminal_stop["preparation"]["native_snapshot"]),
                        negative.directory / "native-stop.json",
                        negative.directory / "process.json")
        finally:
            negative.close()

    def generations(self, first):
        current = first
        current_owned = False
        previous_native = self.snapshot(first, "generation-entry-clock")[0]
        previous_clock = previous_native["clock"]["source"][0]
        previous_progress = previous_native["words"][2]
        try:
            for generation in range(1, 4):
                self.reset(current)
                previous = current.samples[-1].copy()
                current.command("pause")
                recaptured, native_path = self.snapshot(current, "new-child-native-cut", "steady")
                if recaptured["cut_clock"][0] <= previous_clock or recaptured["words"][2] <= previous_progress or recaptured["deadlines"][2] != 0:
                    raise RuntimeError("child recapture reused ancestor native state instead of child progress")
                previous_clock, previous_progress = recaptured["cut_clock"][0], recaptured["words"][2]
                self.retain("three_fresh_generations", native_path, native_path.with_suffix(".native.txt"))
                cut = self.args.evidence / f"execution-generation-{generation}-cut"
                current.command(f"capture {cut}"); self.seal(cut)
                current.command("resume")
                continuation = self.kernel_continues(current, previous)
                self.retain("three_fresh_generations", continuation, cut / "manifest.json")
                self.retain("three_fresh_generations", current.directory / "process.json")
                if generation == 3:
                    break
                child = self.child(cut, f"execution-generation-{generation + 1}")
                if current_owned:
                    current.stop(); current.close()
                current, current_owned = child, True
                child.command("release"); os.write(child.console, b"M\n")
                child.start_mux(); child.command("activate")
                child.profile()
                if child.observations["kernel-identity"] != self.identity:
                    raise RuntimeError("generation kernel identity changed")
                self.kernel_continues(child, previous)
        finally:
            if current_owned:
                current.stop(); current.close()


def run(args, session_type, seal, save, digest, echo):
    return Execution(args, session_type, seal, save, digest, echo).run()

//! Restore admission of libvm's generated read-only flat VMDK lowers.
//!
//! Cold attach lets imago open the extents a descriptor names. Restore must not
//! open any path: the descriptor is matched record by record against the held
//! extent handles the caller validated, and imago receives duplicates of those
//! handles through `HeldExtentGate`. Every record must be the exact grammar
//! libvm emits (ADR 0014 "Lower attachment"):
//!
//! ```text
//! # Disk DescriptorFile          \
//! version=1                       |
//! CID=fffffffe                    | fixed header, byte for byte
//! parentCID=ffffffff              |
//! createType="twoGbMaxExtentFlat" |
//!                                /
//! RW <sectors> FLAT "<absolute path>" <file-sector offset>   (1..=1536 records)
//! ```

use std::cell::{Cell, RefCell};
use std::fs::{File, Metadata, OpenOptions};
use std::io;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{FileExt, MetadataExt};
use std::sync::Arc;

use imago::format::gate::ImplicitOpenGate;
use imago::vmdk::Vmdk;
use imago::{
    DynStorage, FormatAccess, FormatDriverBuilder, Storage, StorageOpenOptions,
    file::File as ImagoFile,
};

use crate::virtio::block::{MAX_VMDK_FLAT_RECORDS, ReadonlyVmdk, SECTOR_SIZE, VmdkExtent};

/// imago's descriptor text limit, which libvm's generator also enforces.
pub const MAX_DESCRIPTOR_BYTES: u64 = 2_097_152;
/// One record covers at most 2 GiB of one extent file.
const MAX_RECORD_SECTORS: u64 = 4_194_304;
const HEADER: &str = "# Disk DescriptorFile\nversion=1\nCID=fffffffe\nparentCID=ffffffff\ncreateType=\"twoGbMaxExtentFlat\"\n\n";

/// Why a held read-only VMDK closure is not the admitted generated closure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum VmdkClosureFault {
    /// The descriptor is empty or exceeds [`MAX_DESCRIPTOR_BYTES`].
    DescriptorLength,
    /// The descriptor is not the exact generated `FLAT` grammar.
    DescriptorGrammar,
    /// More than [`MAX_VMDK_FLAT_RECORDS`] records.
    RecordLimit,
    /// A record names a path with no held extent.
    UndeclaredExtent,
    /// A held extent is never referenced by the descriptor.
    UnreferencedExtent,
    /// Two held extents claim the same path.
    DuplicateExtent,
    /// A record reaches past the end of its held extent.
    ExtentRange,
    /// A held extent is writable or bypasses the page cache, unlike the
    /// read-only buffered opens of cold attach.
    ExtentAccess,
    /// imago's view of the descriptor disagrees with the admitted records.
    Reader,
}

/// One admitted `RW <sectors> FLAT "<path>" <offset>` record.
#[derive(Debug, Eq, PartialEq)]
pub(crate) struct FlatRecord<'a> {
    pub(crate) sectors: u64,
    pub(crate) path: &'a str,
    pub(crate) offset: u64,
}

pub(crate) fn parse_generated(text: &[u8]) -> Result<Vec<FlatRecord<'_>>, VmdkClosureFault> {
    let text = std::str::from_utf8(text).map_err(|_| VmdkClosureFault::DescriptorGrammar)?;
    let body = text
        .strip_prefix(HEADER)
        .and_then(|body| body.strip_suffix('\n'))
        .ok_or(VmdkClosureFault::DescriptorGrammar)?;
    let mut records = Vec::new();
    for line in body.split('\n') {
        if records.len() == MAX_VMDK_FLAT_RECORDS {
            return Err(VmdkClosureFault::RecordLimit);
        }
        records.push(parse_record(line).ok_or(VmdkClosureFault::DescriptorGrammar)?);
    }
    Ok(records)
}

fn parse_record(line: &str) -> Option<FlatRecord<'_>> {
    let (sectors, rest) = line.strip_prefix("RW ")?.split_once(' ')?;
    let sectors = decimal(sectors).filter(|sectors| (1..=MAX_RECORD_SECTORS).contains(sectors))?;
    let (path, offset) = rest.strip_prefix("FLAT \"")?.split_once('"')?;
    let offset = decimal(offset.strip_prefix(' ')?)?;
    representable(path).then_some(FlatRecord {
        sectors,
        path,
        offset,
    })
}

/// Canonical unsigned decimal, as `{}` formats a `u64`.
fn decimal(text: &str) -> Option<u64> {
    if text.is_empty()
        || !text.bytes().all(|byte| byte.is_ascii_digit())
        || (text.len() > 1 && text.starts_with('0'))
    {
        return None;
    }
    text.parse().ok()
}

/// The same path spelling rules libvm applies before generating a descriptor.
fn representable(path: &str) -> bool {
    path.starts_with('/')
        && path.trim() == path
        && !path
            .chars()
            .any(|character| character.is_control() || matches!(character, '"' | '\\'))
        && !path
            .split('/')
            .any(|component| component == "." || component == "..")
}

/// An admitted record and the held extent handle that serves it.
struct BoundRecord<'a> {
    record: FlatRecord<'a>,
    file: &'a File,
}

/// Every host file a VMDK device reads, as `(device, inode)`, without repeats:
/// the descriptor first, then each extent in first-reference order.
pub(crate) type FileIdentities = Vec<(u64, u64)>;

fn identity(metadata: &Metadata) -> (u64, u64) {
    (metadata.dev(), metadata.ino())
}

fn record_identity(identities: &mut FileIdentities, metadata: &Metadata) {
    let identity = identity(metadata);
    if !identities.contains(&identity) {
        identities.push(identity);
    }
}

/// Admit the held descriptor text, then bind each record to exactly one held
/// extent whose range covers it. Held extent identities are appended to
/// `identities`.
fn admit<'a>(
    text: &'a [u8],
    extents: &'a [VmdkExtent],
    identities: &mut FileIdentities,
) -> Result<Vec<BoundRecord<'a>>, VmdkClosureFault> {
    let records = parse_generated(text)?;
    // (extent, length, referenced)
    let mut held: Vec<(&VmdkExtent, u64, bool)> = Vec::with_capacity(extents.len());
    for extent in extents {
        if held
            .iter()
            .any(|(previous, ..)| previous.path.as_os_str() == extent.path.as_os_str())
        {
            return Err(VmdkClosureFault::DuplicateExtent);
        }
        if !read_only_buffered(&extent.file) {
            return Err(VmdkClosureFault::ExtentAccess);
        }
        let metadata = extent
            .file
            .metadata()
            .map_err(|_| VmdkClosureFault::ExtentAccess)?;
        record_identity(identities, &metadata);
        held.push((extent, metadata.len(), false));
    }
    let mut bound = Vec::with_capacity(records.len());
    for record in records {
        let (extent, length, referenced) = held
            .iter_mut()
            .find(|(extent, ..)| extent.path.as_os_str().as_bytes() == record.path.as_bytes())
            .ok_or(VmdkClosureFault::UndeclaredExtent)?;
        let end = record
            .offset
            .checked_add(record.sectors)
            .and_then(|sectors| sectors.checked_mul(SECTOR_SIZE))
            .ok_or(VmdkClosureFault::ExtentRange)?;
        if end > *length {
            return Err(VmdkClosureFault::ExtentRange);
        }
        *referenced = true;
        let extent: &'a VmdkExtent = extent;
        bound.push(BoundRecord {
            record,
            file: &extent.file,
        });
    }
    if held.iter().any(|(.., referenced)| !referenced) {
        return Err(VmdkClosureFault::UnreferencedExtent);
    }
    Ok(bound)
}

fn read_only_buffered(file: &File) -> bool {
    let Ok(flags) = nix::fcntl::fcntl(file, nix::fcntl::FcntlArg::F_GETFL) else {
        return false;
    };
    let flags = nix::fcntl::OFlag::from_bits_truncate(flags);
    #[cfg(target_os = "linux")]
    if flags.contains(nix::fcntl::OFlag::O_DIRECT) {
        return false;
    }
    flags & nix::fcntl::OFlag::O_ACCMODE == nix::fcntl::OFlag::O_RDONLY
}

/// Serves imago's implicit extent opens from the held handles, in record
/// order. Any request that is not the next admitted record is refused, so
/// imago can never reach a file the caller did not hand over.
struct HeldExtentGate<'a> {
    records: &'a [BoundRecord<'a>],
    next: &'a Cell<usize>,
    fault: &'a Cell<Option<VmdkClosureFault>>,
}

impl HeldExtentGate<'_> {
    fn refuse<T>(&self, fault: VmdkClosureFault) -> io::Result<T> {
        self.fault.set(Some(fault));
        Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "VMDK open outside the held restore closure",
        ))
    }
}

impl ImplicitOpenGate<Box<dyn DynStorage>> for HeldExtentGate<'_> {
    fn open_format<F: FormatDriverBuilder<Box<dyn DynStorage>>>(
        &mut self,
        _builder: F,
    ) -> io::Result<FormatAccess<Box<dyn DynStorage>>> {
        self.refuse(VmdkClosureFault::Reader)
    }

    fn open_storage(&mut self, options: StorageOpenOptions) -> io::Result<Box<dyn DynStorage>> {
        let index = self.next.get();
        let Some(bound) = self.records.get(index) else {
            return self.refuse(VmdkClosureFault::Reader);
        };
        if options.get_writable() || options.get_direct() {
            return self.refuse(VmdkClosureFault::ExtentAccess);
        }
        if options
            .get_filename()
            .is_none_or(|path| path.as_os_str().as_bytes() != bound.record.path.as_bytes())
        {
            return self.refuse(VmdkClosureFault::Reader);
        }
        // Same open file description as the validated handle; never a reopen.
        let file = ImagoFile::try_from(bound.file.try_clone()?)?;
        self.next.set(index + 1);
        Ok(Box::new(file))
    }
}

/// Cold attach: opens each extent the descriptor names exactly once, as the
/// permissive gate would, but through a std handle whose inode is recorded so
/// live capture can refuse outputs that alias the backing.
struct ColdExtentGate<'a> {
    identities: &'a RefCell<FileIdentities>,
}

impl ImplicitOpenGate<Box<dyn DynStorage>> for ColdExtentGate<'_> {
    fn open_format<F: FormatDriverBuilder<Box<dyn DynStorage>>>(
        &mut self,
        _builder: F,
    ) -> io::Result<FormatAccess<Box<dyn DynStorage>>> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "flat VMDK has no nested image layers",
        ))
    }

    fn open_storage(&mut self, options: StorageOpenOptions) -> io::Result<Box<dyn DynStorage>> {
        // Flat VMDK extents inherit default open options: buffered, read-only.
        if options.get_direct() || options.get_writable() {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "VMDK extents open read-only and buffered",
            ));
        }
        let path = options.get_filename().ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidInput, "VMDK extent has no path")
        })?;
        let file = OpenOptions::new().read(true).open(path)?;
        record_identity(&mut self.identities.borrow_mut(), &file.metadata()?);
        Ok(Box::new(ImagoFile::try_from(file)?))
    }
}

/// Open a cold-attached VMDK from its descriptor storage, appending every
/// extent inode it opens to `identities`.
pub(crate) fn open_cold(
    descriptor: ImagoFile,
    identities: &mut FileIdentities,
) -> io::Result<FormatAccess<Box<dyn DynStorage>>> {
    let recorded = RefCell::new(std::mem::take(identities));
    let opened = Vmdk::<Box<dyn DynStorage>, Arc<FormatAccess<_>>>::builder(Box::new(descriptor))
        .open(ColdExtentGate {
            identities: &recorded,
        });
    *identities = recorded.into_inner();
    Ok(FormatAccess::new(opened?))
}

/// A restored read-only VMDK backend, the descriptor-derived discard
/// alignment and every host file it reads (descriptor first).
pub(crate) struct OpenedVmdk {
    pub(crate) access: FormatAccess<Box<dyn DynStorage>>,
    pub(crate) discard_alignment: usize,
    pub(crate) identities: FileIdentities,
}

pub(crate) enum OpenError {
    Closure(VmdkClosureFault),
    Io(io::Error),
}

/// Reconstruct the read-only VMDK from held resources only. The returned
/// backend owns duplicates of the descriptor and every referenced extent for
/// the device lifetime; the caller's handles may be dropped afterwards.
pub(crate) fn open_held(closure: &ReadonlyVmdk) -> Result<OpenedVmdk, OpenError> {
    let metadata = closure.descriptor.metadata().map_err(OpenError::Io)?;
    let length = metadata.len();
    if length == 0 || length > MAX_DESCRIPTOR_BYTES {
        return Err(OpenError::Closure(VmdkClosureFault::DescriptorLength));
    }
    let mut identities = vec![identity(&metadata)];
    let mut text = vec![0; length as usize];
    closure
        .descriptor
        .read_exact_at(&mut text, 0)
        .map_err(OpenError::Io)?;
    let records = admit(&text, &closure.extents, &mut identities).map_err(OpenError::Closure)?;
    let size = records
        .iter()
        .try_fold(0u64, |size, bound| {
            bound
                .record
                .sectors
                .checked_mul(SECTOR_SIZE)
                .and_then(|bytes| size.checked_add(bytes))
        })
        .ok_or(OpenError::Closure(VmdkClosureFault::ExtentRange))?;

    let storage = closure
        .descriptor
        .try_clone()
        .and_then(ImagoFile::try_from)
        .map_err(OpenError::Io)?;
    let discard_alignment = storage.discard_align();
    let next = Cell::new(0);
    let fault = Cell::new(None);
    let gate = HeldExtentGate {
        records: &records,
        next: &next,
        fault: &fault,
    };
    let vmdk = Vmdk::<Box<dyn DynStorage>, Arc<FormatAccess<_>>>::builder(Box::new(storage))
        .open(gate)
        .map_err(|error| match fault.get() {
            Some(fault) => OpenError::Closure(fault),
            None => OpenError::Io(error),
        })?;
    let access = FormatAccess::new(vmdk);
    if next.get() != records.len() || access.size() != size {
        return Err(OpenError::Closure(VmdkClosureFault::Reader));
    }
    Ok(OpenedVmdk {
        access,
        discard_alignment,
        identities,
    })
}

#[cfg(test)]
mod tests {
    use std::fs::File;
    use std::io::Write;
    use std::os::unix::fs::FileExt;
    use std::path::PathBuf;

    use utils::tempfile::TempFile;

    use crate::virtio::block::vmdk::{
        FlatRecord, HEADER, MAX_DESCRIPTOR_BYTES, OpenError, VmdkClosureFault, open_held,
        parse_generated,
    };
    use crate::virtio::block::{MAX_VMDK_FLAT_RECORDS, ReadonlyVmdk, VmdkExtent};

    fn descriptor(records: &[(u64, &str, u64)]) -> String {
        let mut text = HEADER.to_owned();
        for (sectors, path, offset) in records {
            text.push_str(&format!("RW {sectors} FLAT \"{path}\" {offset}\n"));
        }
        text
    }

    fn held(text: &str) -> TempFile {
        let file = TempFile::new().unwrap();
        file.as_file().write_all(text.as_bytes()).unwrap();
        file
    }

    fn extent(bytes: &[u8]) -> TempFile {
        let file = TempFile::new().unwrap();
        file.as_file().write_all_at(bytes, 0).unwrap();
        file
    }

    fn read_only(file: &TempFile) -> File {
        File::open(file.as_path()).unwrap()
    }

    fn path(file: &TempFile) -> &str {
        file.as_path().to_str().unwrap()
    }

    fn closure(descriptor: &TempFile, extents: &[&TempFile]) -> ReadonlyVmdk {
        ReadonlyVmdk {
            descriptor: read_only(descriptor),
            extents: extents
                .iter()
                .map(|file| VmdkExtent {
                    path: PathBuf::from(path(file)),
                    file: read_only(file),
                })
                .collect(),
        }
    }

    fn closure_fault(closure: &ReadonlyVmdk) -> VmdkClosureFault {
        match open_held(closure) {
            Err(OpenError::Closure(fault)) => fault,
            Err(OpenError::Io(error)) => panic!("expected closure refusal, got I/O {error}"),
            Ok(_) => panic!("expected closure refusal, got an opened VMDK"),
        }
    }

    #[test]
    fn vmdk_generated_grammar_is_exact_and_canonical() {
        let text = descriptor(&[(4_194_304, "/pool/a b", 0), (1, "/pool/a b", 4_194_304)]);
        assert_eq!(
            parse_generated(text.as_bytes()).unwrap(),
            vec![
                FlatRecord {
                    sectors: 4_194_304,
                    path: "/pool/a b",
                    offset: 0
                },
                FlatRecord {
                    sectors: 1,
                    path: "/pool/a b",
                    offset: 4_194_304
                },
            ]
        );
        let valid = descriptor(&[(8, "/pool/x", 0)]);
        let mut invalid = vec![
            HEADER.to_owned(),
            valid.trim_end_matches('\n').to_owned(),
            format!("{valid}\n"),
            valid.replace("twoGbMaxExtentFlat", "monolithicFlat"),
            valid.replace("CID=fffffffe", "CID=00000001"),
            valid.replace("version=1\n", "version=1\nddb.adapterType=\"ide\"\n"),
            format!("{valid}parentFileNameHint=\"/parent.vmdk\"\n"),
            valid.replace("RW ", "RDONLY "),
            valid.replace("RW 8", "RW  8"),
            valid.replace("FLAT", "ZERO"),
            valid.replace("RW 8 FLAT \"/pool/x\" 0", "NOACCESS 8"),
            valid.replace(" 0\n", " 00\n"),
            valid.replace(" 0\n", " +0\n"),
            valid.replace(" 0\n", " 0 \n"),
            valid.replace(" 0\n", "\n"),
            valid.replace("RW 8", "RW 08"),
            valid.replace("RW 8", "RW 0"),
            valid.replace("RW 8", "RW 4194305"),
            valid.replace("RW 8", "RW 18446744073709551616"),
            valid.replace("/pool/x", "pool/x"),
            valid.replace("/pool/x", "/pool/../x"),
            valid.replace("/pool/x", "/pool/./x"),
            valid.replace("/pool/x", "/pool/x "),
            valid.replace("/pool/x", "/pool/\tx"),
            valid.replace("/pool/x", "/pool\\x"),
            valid.replace("\"/pool/x\"", "\"/pool/x\"\"\""),
            valid.replace('\n', "\r\n"),
        ];
        invalid.push(String::new());
        for text in &invalid {
            assert_eq!(
                parse_generated(text.as_bytes()),
                Err(VmdkClosureFault::DescriptorGrammar),
                "{text:?}"
            );
        }
        let mut bytes = valid.into_bytes();
        bytes.insert(HEADER.len() + 18, 0xff);
        assert_eq!(
            parse_generated(&bytes),
            Err(VmdkClosureFault::DescriptorGrammar)
        );
    }

    #[test]
    fn vmdk_record_limit_is_inclusive() {
        let records = vec![(1, "/pool/x", 0); MAX_VMDK_FLAT_RECORDS];
        assert_eq!(
            parse_generated(descriptor(&records).as_bytes())
                .unwrap()
                .len(),
            MAX_VMDK_FLAT_RECORDS
        );
        let records = vec![(1, "/pool/x", 0); MAX_VMDK_FLAT_RECORDS + 1];
        assert_eq!(
            parse_generated(descriptor(&records).as_bytes()),
            Err(VmdkClosureFault::RecordLimit)
        );
    }

    #[test]
    fn vmdk_held_closure_reads_split_and_repeated_extents_without_paths() {
        let mut first = vec![0; 3 * 512];
        first[0] = 11;
        first[512] = 22;
        first[1024] = 33;
        let first = extent(&first);
        let second = extent(&[44; 512]);
        // Split ranges of one file plus a repeat of its first sector.
        let text = descriptor(&[
            (1, path(&first), 0),
            (2, path(&first), 1),
            (1, path(&second), 0),
            (1, path(&first), 0),
        ]);
        let descriptor = held(&text);
        let closure = closure(&descriptor, &[&first, &second]);
        // Remove every path the descriptor names: restore must use handles only.
        std::fs::remove_file(descriptor.as_path()).unwrap();
        std::fs::remove_file(first.as_path()).unwrap();
        std::fs::remove_file(second.as_path()).unwrap();
        let opened = match open_held(&closure) {
            Ok(opened) => opened,
            Err(OpenError::Closure(fault)) => panic!("{fault:?}"),
            Err(OpenError::Io(error)) => panic!("{error}"),
        };
        drop(closure);
        assert_eq!(opened.access.size(), 5 * 512);
        let mut observed = [0u8; 1];
        for (offset, expected) in [(0, 11), (512, 22), (1024, 33), (1536, 44), (2048, 11)] {
            opened.access.read(&mut observed[..], offset).unwrap();
            assert_eq!(observed, [expected], "guest offset {offset}");
        }
        assert!(opened.access.write(&[1u8][..], 0).is_err());
    }

    #[test]
    fn vmdk_closure_rejects_missing_unreferenced_duplicate_and_out_of_range_extents() {
        let first = extent(&[1; 1024]);
        let second = extent(&[2; 512]);
        let text = descriptor(&[(2, path(&first), 0)]);
        let descriptor_file = held(&text);

        assert_eq!(
            closure_fault(&closure(&descriptor_file, &[])),
            VmdkClosureFault::UndeclaredExtent
        );
        assert_eq!(
            closure_fault(&closure(&descriptor_file, &[&first, &second])),
            VmdkClosureFault::UnreferencedExtent
        );
        assert_eq!(
            closure_fault(&closure(&descriptor_file, &[&first, &first])),
            VmdkClosureFault::DuplicateExtent
        );
        // Same inode under a different spelling is not the named record.
        let mut respelled = closure(&descriptor_file, &[&first]);
        respelled.extents[0].path = PathBuf::from(format!("/{}", path(&first)));
        assert_eq!(
            closure_fault(&respelled),
            VmdkClosureFault::UndeclaredExtent
        );

        for records in [
            vec![(3, path(&first), 0)],
            vec![(1, path(&first), 2)],
            vec![(1, path(&first), u64::MAX)],
        ] {
            let text = descriptor(&records);
            let descriptor_file = held(&text);
            assert_eq!(
                closure_fault(&closure(&descriptor_file, &[&first])),
                VmdkClosureFault::ExtentRange,
                "{records:?}"
            );
        }
        let exact = held(&descriptor(&[(1, path(&first), 1)]));
        assert!(open_held(&closure(&exact, &[&first])).is_ok());
    }

    #[test]
    fn vmdk_closure_rejects_writable_extents_and_unbounded_descriptors() {
        let backing = extent(&[3; 512]);
        let text = descriptor(&[(1, path(&backing), 0)]);
        let descriptor_file = held(&text);
        let mut writable = closure(&descriptor_file, &[&backing]);
        writable.extents[0].file = File::options()
            .read(true)
            .write(true)
            .open(backing.as_path())
            .unwrap();
        assert_eq!(closure_fault(&writable), VmdkClosureFault::ExtentAccess);

        #[cfg(target_os = "linux")]
        {
            use std::os::unix::fs::OpenOptionsExt;
            let mut direct = closure(&descriptor_file, &[&backing]);
            if let Ok(file) = File::options()
                .read(true)
                .custom_flags(nix::fcntl::OFlag::O_DIRECT.bits())
                .open(backing.as_path())
            {
                direct.extents[0].file = file;
                assert_eq!(closure_fault(&direct), VmdkClosureFault::ExtentAccess);
            }
        }

        let empty = TempFile::new().unwrap();
        assert_eq!(
            closure_fault(&closure(&empty, &[&backing])),
            VmdkClosureFault::DescriptorLength
        );
        let oversized = TempFile::new().unwrap();
        oversized
            .as_file()
            .set_len(MAX_DESCRIPTOR_BYTES + 1)
            .unwrap();
        assert_eq!(
            closure_fault(&closure(&oversized, &[&backing])),
            VmdkClosureFault::DescriptorLength
        );
        let foreign = held(&format!(
            "# Disk DescriptorFile\nversion=1\nCID=fffffffe\nparentCID=ffffffff\ncreateType=\"monolithicFlat\"\nRW 1 FLAT \"{}\" 0\n",
            path(&backing)
        ));
        assert_eq!(
            closure_fault(&closure(&foreign, &[&backing])),
            VmdkClosureFault::DescriptorGrammar
        );
    }
}

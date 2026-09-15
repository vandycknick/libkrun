use std::collections::HashMap;
use std::ffi::{CStr, CString};
use std::io::{self, Write};
use std::mem;
use std::os::fd::OwnedFd;
use std::os::unix::ffi::OsStrExt;
use std::path::{Component, Path};
use std::sync::atomic::AtomicI32;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use nix::errno::Errno;
use nix::fcntl::{AtFlags, OFlag, open, openat};
use nix::sys::stat::{Mode, fstat, fstatat};
use nix::sys::uio::pread;

use crate::virtio::bindings;
use crate::virtio::fs::filesystem::{
    Context, DirEntry, Entry, Extensions, FileSystem, FsOptions, GetxattrReply, IoctlReply,
    ListxattrReply, OpenOptions, SetattrValid, ZeroCopyReader, ZeroCopyWriter,
};
use crate::virtio::fs::fuse;
use crate::virtio::linux_errno;

const ROOT_INODE: u64 = fuse::ROOT_ID;
const TRANSLATOR_INODE: u64 = 2;
const TRANSLATOR_NAME: &[u8] = b"rosetta";
const MAX_TRANSLATOR_SIZE: usize = 128 * 1024 * 1024;
const CAPTURED_RESPONSE_SIZE: usize = 1024;
const SHA256_SIZE: usize = 32;
const TIMEOUT: Duration = Duration::MAX;
// This is deliberately much larger than one virtio-fs request queue while
// still placing a fixed per-device bound on guest-controlled open state.
const MAX_OPEN_HANDLES: usize = 65_536;
const LINUX_O_ACCMODE: i32 = 0b11;
const LINUX_O_RDONLY: i32 = 0;
const LINUX_W_OK: u32 = 2;
const LINUX_DT_DIR: u32 = 4;
const LINUX_DT_REG: u32 = 8;
const LINUX_S_IFDIR: u16 = 0o040000;
const LINUX_S_IFREG: u16 = 0o100000;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RosettaProfile {
    CapturedCompatibilityV1,
}

#[derive(Clone)]
pub struct RosettaFsConfig {
    profile: RosettaProfile,
    snapshot: Arc<Vec<u8>>,
    captured_result: i32,
    captured_response: Arc<[u8; CAPTURED_RESPONSE_SIZE]>,
}

impl std::fmt::Debug for RosettaFsConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RosettaFsConfig")
            .field("profile", &self.profile)
            .field("snapshot_len", &self.snapshot.len())
            .field("captured_result", &self.captured_result)
            .field("captured_response_len", &CAPTURED_RESPONSE_SIZE)
            .finish()
    }
}

impl RosettaFsConfig {
    pub fn from_host(
        profile: RosettaProfile,
        host_root: &Path,
        expected_sha256: &[u8],
        captured_result: i32,
        captured_response: &[u8],
    ) -> io::Result<Self> {
        let host_root_bytes = host_root.as_os_str().as_bytes();
        if !host_root.is_absolute()
            || host_root.to_str().is_none()
            || host_root_bytes.is_empty()
            || host_root_bytes.len() > 4096
            || host_root_bytes.contains(&0)
            || expected_sha256.len() != SHA256_SIZE
            || captured_response.len() != CAPTURED_RESPONSE_SIZE
            || captured_result < 0
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "invalid Rosetta profile",
            ));
        }
        let snapshot = snapshot_translator(host_root)?;
        if sha256(&snapshot)? != expected_sha256 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "translator digest mismatch",
            ));
        }
        let response: [u8; CAPTURED_RESPONSE_SIZE] = captured_response
            .try_into()
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "invalid response length"))?;
        Ok(Self {
            profile,
            snapshot: Arc::new(snapshot),
            captured_result,
            captured_response: Arc::new(response),
        })
    }
}

#[derive(Clone, Copy, Eq, PartialEq)]
struct FileIdentity {
    dev: u64,
    ino: u64,
    mode: u16,
    size: i64,
    mtime_sec: i64,
    mtime_nsec: i64,
    ctime_sec: i64,
    ctime_nsec: i64,
}

fn identity(st: &libc::stat) -> FileIdentity {
    FileIdentity {
        dev: st.st_dev as u64,
        ino: st.st_ino,
        mode: st.st_mode,
        size: st.st_size,
        mtime_sec: st.st_mtime,
        mtime_nsec: st.st_mtime_nsec,
        ctime_sec: st.st_ctime,
        ctime_nsec: st.st_ctime_nsec,
    }
}

fn nix_error(error: Errno) -> io::Error {
    io::Error::from_raw_os_error(error as i32)
}

struct OpenedEntry {
    fd: OwnedFd,
    parent: OwnedFd,
    name: CString,
}

fn open_root_componentwise(path: &Path) -> io::Result<OpenedEntry> {
    if !path.is_absolute() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "host root must be absolute",
        ));
    }
    let mut current = open(
        Path::new("/"),
        OFlag::O_RDONLY | OFlag::O_DIRECTORY | OFlag::O_CLOEXEC,
        Mode::empty(),
    )
    .map_err(nix_error)?;
    let mut opened = None;
    for component in path.components() {
        let Component::Normal(component) = component else {
            if matches!(component, Component::RootDir) {
                continue;
            }
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "invalid host root component",
            ));
        };
        let name = CString::new(component.as_bytes())
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "invalid host root"))?;
        let next = openat(
            &current,
            name.as_c_str(),
            OFlag::O_RDONLY | OFlag::O_DIRECTORY | OFlag::O_NOFOLLOW | OFlag::O_CLOEXEC,
            Mode::empty(),
        )
        .map_err(nix_error)?;
        if identity(&fstat(&next).map_err(nix_error)?)
            != identity(
                &fstatat(&current, name.as_c_str(), AtFlags::AT_SYMLINK_NOFOLLOW)
                    .map_err(nix_error)?,
            )
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "host root changed",
            ));
        }
        opened = Some(OpenedEntry {
            fd: next,
            parent: current,
            name,
        });
        current = opened
            .as_ref()
            .ok_or_else(|| {
                io::Error::new(io::ErrorKind::InvalidData, "host root component missing")
            })?
            .fd
            .try_clone()?;
    }
    opened.ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "host root cannot be filesystem root",
        )
    })
}

fn verify_current(entry: &OpenedEntry, expected: FileIdentity) -> io::Result<()> {
    if identity(&fstat(&entry.fd).map_err(nix_error)?) != expected
        || identity(
            &fstatat(
                &entry.parent,
                entry.name.as_c_str(),
                AtFlags::AT_SYMLINK_NOFOLLOW,
            )
            .map_err(nix_error)?,
        ) != expected
    {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "source changed"));
    }
    Ok(())
}

fn snapshot_translator(host_root: &Path) -> io::Result<Vec<u8>> {
    snapshot_translator_after_open(host_root, || Ok(()))
}

fn snapshot_translator_after_open(
    host_root: &Path,
    after_open: impl FnOnce() -> io::Result<()>,
) -> io::Result<Vec<u8>> {
    let root = open_root_componentwise(host_root)?;
    let root_identity = identity(&fstat(&root.fd).map_err(nix_error)?);
    verify_current(&root, root_identity)?;
    let name = CString::from(c"rosetta");
    let file = OpenedEntry {
        fd: openat(
            &root.fd,
            name.as_c_str(),
            OFlag::O_RDONLY | OFlag::O_NOFOLLOW | OFlag::O_CLOEXEC,
            Mode::empty(),
        )
        .map_err(nix_error)?,
        parent: root.fd.try_clone()?,
        name,
    };
    let before = identity(&fstat(&file.fd).map_err(nix_error)?);
    if before.mode as libc::mode_t & libc::S_IFMT != libc::S_IFREG
        || before.mode as libc::mode_t & 0o111 == 0
        || before.size < 0
        || before.size as u64 > MAX_TRANSLATOR_SIZE as u64
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "translator must be a bounded executable regular file",
        ));
    }
    verify_current(&file, before)?;
    after_open()?;
    let len = before.size as usize;
    let mut snapshot = Vec::new();
    snapshot
        .try_reserve_exact(len)
        .map_err(|_| io::Error::from(io::ErrorKind::OutOfMemory))?;
    snapshot.resize(len, 0);
    let mut offset = 0;
    while offset < len {
        let read = match pread(&file.fd, &mut snapshot[offset..], offset as libc::off_t) {
            Ok(read) => read,
            Err(Errno::EINTR) => continue,
            Err(error) => return Err(nix_error(error)),
        };
        if read == 0 {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "translator changed while reading",
            ));
        }
        offset += read;
    }
    verify_current(&file, before)?;
    verify_current(&root, root_identity)?;
    Ok(snapshot)
}

// nix does not expose Apple's CommonCrypto digest API.
#[link(name = "System")]
unsafe extern "C" {
    fn CC_SHA256(data: *const libc::c_void, len: u32, md: *mut u8) -> *mut u8;
}

fn sha256(data: &[u8]) -> io::Result<[u8; SHA256_SIZE]> {
    let len = u32::try_from(data.len())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "SHA-256 input is too large"))?;
    let mut digest = [0; SHA256_SIZE];
    let result = unsafe { CC_SHA256(data.as_ptr().cast(), len, digest.as_mut_ptr()) };
    if result != digest.as_mut_ptr() {
        return Err(io::Error::other("CommonCrypto SHA-256 failed"));
    }
    Ok(digest)
}

#[derive(Clone, Copy, Eq, PartialEq)]
enum HandleKind {
    File,
    Directory,
}

struct HandleTable {
    next: u64,
    limit: usize,
    destroyed: bool,
    active: HashMap<u64, HandleKind>,
}

#[derive(Clone)]
pub struct ImmutableRosettaFs {
    config: RosettaFsConfig,
    handles: Arc<Mutex<HandleTable>>,
}

impl ImmutableRosettaFs {
    pub fn new(config: RosettaFsConfig) -> Self {
        Self::with_handle_limit(config, MAX_OPEN_HANDLES)
    }

    fn with_handle_limit(config: RosettaFsConfig, handle_limit: usize) -> Self {
        Self {
            config,
            handles: Arc::new(Mutex::new(HandleTable {
                next: 1,
                limit: handle_limit,
                destroyed: false,
                active: HashMap::new(),
            })),
        }
    }

    fn stat(inode: u64, size: usize) -> bindings::stat64 {
        let mut st: bindings::stat64 = unsafe { mem::zeroed() };
        st.st_ino = inode;
        st.st_mode = if inode == ROOT_INODE {
            LINUX_S_IFDIR | 0o555
        } else {
            LINUX_S_IFREG | 0o555
        };
        st.st_nlink = if inode == ROOT_INODE { 2 } else { 1 };
        st.st_size = size as i64;
        st.st_blksize = 4096;
        st.st_blocks = size.div_ceil(512) as i64;
        st
    }

    fn entry(&self, inode: u64) -> io::Result<Entry> {
        let size = match inode {
            ROOT_INODE => 0,
            TRANSLATOR_INODE => self.config.snapshot.len(),
            _ => return Err(linux_errno::enoent()),
        };
        Ok(Entry {
            inode,
            generation: 1,
            attr: Self::stat(inode, size),
            attr_flags: 0,
            attr_timeout: TIMEOUT,
            entry_timeout: TIMEOUT,
        })
    }

    fn allocate_handle(&self, kind: HandleKind) -> io::Result<u64> {
        let mut handles = self.handles.lock().map_err(|_| linux_errno::ebadf())?;
        if handles.destroyed {
            return Err(linux_errno::ebadf());
        }
        if handles.active.len() >= handles.limit {
            return Err(linux_errno::emfile());
        }
        handles
            .active
            .try_reserve(1)
            .map_err(|_| linux_errno::emfile())?;
        let id = handles.next;
        handles.next = handles
            .next
            .checked_add(1)
            .ok_or_else(linux_errno::emfile)?;
        handles.active.insert(id, kind);
        Ok(id)
    }

    fn check_handle(&self, handle: u64, kind: HandleKind) -> io::Result<()> {
        let handles = self.handles.lock().map_err(|_| linux_errno::ebadf())?;
        if !handles.destroyed && handles.active.get(&handle) == Some(&kind) {
            Ok(())
        } else {
            Err(linux_errno::ebadf())
        }
    }

    fn release_handle(&self, handle: u64, kind: HandleKind) -> io::Result<()> {
        let mut handles = self.handles.lock().map_err(|_| linux_errno::ebadf())?;
        if handles.destroyed || handles.active.get(&handle) != Some(&kind) {
            return Err(linux_errno::ebadf());
        }
        handles.active.remove(&handle);
        Ok(())
    }
}

impl FileSystem for ImmutableRosettaFs {
    type Inode = u64;
    type Handle = u64;

    fn init(&self, _capable: FsOptions) -> io::Result<FsOptions> {
        Ok(FsOptions::empty())
    }

    fn destroy(&self) {
        let mut handles = match self.handles.lock() {
            Ok(handles) => handles,
            Err(poisoned) => poisoned.into_inner(),
        };
        handles.destroyed = true;
        handles.active.clear();
    }

    fn lookup(&self, _ctx: Context, parent: u64, name: &CStr) -> io::Result<Entry> {
        if parent != ROOT_INODE {
            return Err(linux_errno::enotdir());
        }
        match name.to_bytes() {
            b"." => self.entry(ROOT_INODE),
            b".." => Err(linux_errno::enoent()),
            TRANSLATOR_NAME => self.entry(TRANSLATOR_INODE),
            _ => Err(linux_errno::enoent()),
        }
    }

    fn getattr(
        &self,
        _ctx: Context,
        inode: u64,
        handle: Option<u64>,
    ) -> io::Result<(bindings::stat64, Duration)> {
        if let Some(handle) = handle {
            let kind = if inode == ROOT_INODE {
                HandleKind::Directory
            } else if inode == TRANSLATOR_INODE {
                HandleKind::File
            } else {
                return Err(linux_errno::enoent());
            };
            self.check_handle(handle, kind)?;
        }
        let entry = self.entry(inode)?;
        Ok((entry.attr, TIMEOUT))
    }

    fn open(
        &self,
        _ctx: Context,
        inode: u64,
        _kill_priv: bool,
        flags: u32,
    ) -> io::Result<(Option<u64>, OpenOptions)> {
        if inode == ROOT_INODE {
            return Err(linux_errno::eisdir());
        }
        if inode != TRANSLATOR_INODE {
            return Err(linux_errno::enoent());
        }
        let flags = flags as i32;
        if flags & LINUX_O_ACCMODE != LINUX_O_RDONLY || flags & bindings::LINUX_O_TRUNC != 0 {
            return Err(linux_errno::erofs());
        }
        Ok((
            Some(self.allocate_handle(HandleKind::File)?),
            OpenOptions::empty(),
        ))
    }

    fn read<W: Write + ZeroCopyWriter>(
        &self,
        _ctx: Context,
        inode: u64,
        handle: u64,
        mut w: W,
        size: u32,
        offset: u64,
        _lock_owner: Option<u64>,
        _flags: u32,
    ) -> io::Result<usize> {
        if inode != TRANSLATOR_INODE {
            return Err(if inode == ROOT_INODE {
                linux_errno::eisdir()
            } else {
                linux_errno::enoent()
            });
        }
        self.check_handle(handle, HandleKind::File)?;
        let offset = usize::try_from(offset).map_err(|_| linux_errno::einval())?;
        if offset >= self.config.snapshot.len() {
            return Ok(0);
        }
        let end = offset
            .saturating_add(size as usize)
            .min(self.config.snapshot.len());
        w.write(&self.config.snapshot[offset..end])
    }

    fn release(
        &self,
        _ctx: Context,
        inode: u64,
        _flags: u32,
        handle: u64,
        _flush: bool,
        _flock_release: bool,
        _lock_owner: Option<u64>,
    ) -> io::Result<()> {
        if inode != TRANSLATOR_INODE {
            return Err(linux_errno::ebadf());
        }
        self.release_handle(handle, HandleKind::File)
    }

    fn opendir(
        &self,
        _ctx: Context,
        inode: u64,
        flags: u32,
    ) -> io::Result<(Option<u64>, OpenOptions)> {
        if inode != ROOT_INODE {
            return Err(if inode == TRANSLATOR_INODE {
                linux_errno::enotdir()
            } else {
                linux_errno::enoent()
            });
        }
        let flags = flags as i32;
        if flags & LINUX_O_ACCMODE != LINUX_O_RDONLY || flags & bindings::LINUX_O_TRUNC != 0 {
            return Err(linux_errno::erofs());
        }
        Ok((
            Some(self.allocate_handle(HandleKind::Directory)?),
            OpenOptions::empty(),
        ))
    }

    fn readdir<F>(
        &self,
        _ctx: Context,
        inode: u64,
        handle: u64,
        _size: u32,
        offset: u64,
        mut add_entry: F,
    ) -> io::Result<()>
    where
        F: FnMut(DirEntry) -> io::Result<usize>,
    {
        if inode != ROOT_INODE {
            return Err(linux_errno::enotdir());
        }
        self.check_handle(handle, HandleKind::Directory)?;
        let entries = [
            (ROOT_INODE, LINUX_DT_DIR, b".".as_slice()),
            (ROOT_INODE, LINUX_DT_DIR, b"..".as_slice()),
            (TRANSLATOR_INODE, LINUX_DT_REG, TRANSLATOR_NAME),
        ];
        for (index, (ino, type_, name)) in entries.iter().enumerate().skip(offset as usize) {
            if add_entry(DirEntry {
                ino: *ino,
                offset: index as u64 + 1,
                type_: *type_,
                name,
            })? == 0
            {
                break;
            }
        }
        Ok(())
    }

    fn releasedir(&self, _ctx: Context, inode: u64, _flags: u32, handle: u64) -> io::Result<()> {
        if inode != ROOT_INODE {
            return Err(linux_errno::ebadf());
        }
        self.release_handle(handle, HandleKind::Directory)
    }

    fn access(&self, _ctx: Context, inode: u64, mask: u32) -> io::Result<()> {
        self.entry(inode)?;
        if mask & LINUX_W_OK != 0 {
            Err(linux_errno::erofs())
        } else {
            Ok(())
        }
    }

    fn statfs(&self, _ctx: Context, inode: u64) -> io::Result<bindings::statvfs64> {
        self.entry(inode)?;
        let mut stat: bindings::statvfs64 = unsafe { mem::zeroed() };
        stat.f_bsize = 4096;
        stat.f_frsize = 4096;
        stat.f_files = 2;
        stat.f_namemax = 255;
        stat.f_flag = libc::ST_RDONLY;
        Ok(stat)
    }

    fn ioctl(
        &self,
        _ctx: Context,
        inode: u64,
        handle: u64,
        flags: u32,
        cmd: u32,
        _arg: u64,
        in_size: u32,
        out_size: u32,
        _exit_code: &Arc<AtomicI32>,
    ) -> io::Result<IoctlReply> {
        if inode != TRANSLATOR_INODE || self.check_handle(handle, HandleKind::File).is_err() {
            return Err(linux_errno::ebadf());
        }
        if flags != 0 || in_size != 0 {
            return Err(linux_errno::enotty());
        }
        if cmd >> 8 == 0x804561 {
            if out_size as usize > CAPTURED_RESPONSE_SIZE {
                return Err(linux_errno::enotty());
            }
            return Ok(IoctlReply {
                result: self.config.captured_result,
                data: self.config.captured_response[..out_size as usize].to_vec(),
            });
        }
        match (cmd, out_size) {
            (0x80806123, 128) => Ok(IoctlReply {
                result: 0,
                data: vec![1; 128],
            }),
            (0x6124, 0) => Ok(IoctlReply {
                result: 0,
                data: Vec::new(),
            }),
            _ => Err(linux_errno::enotty()),
        }
    }

    fn setattr(
        &self,
        _ctx: Context,
        _inode: u64,
        _attr: bindings::stat64,
        _handle: Option<u64>,
        _valid: SetattrValid,
    ) -> io::Result<(bindings::stat64, Duration)> {
        Err(linux_errno::erofs())
    }
    fn symlink(
        &self,
        _ctx: Context,
        _linkname: &CStr,
        _parent: u64,
        _name: &CStr,
        _extensions: Extensions,
    ) -> io::Result<Entry> {
        Err(linux_errno::erofs())
    }
    fn mknod(
        &self,
        _ctx: Context,
        _inode: u64,
        _name: &CStr,
        _mode: u32,
        _rdev: u32,
        _umask: u32,
        _extensions: Extensions,
    ) -> io::Result<Entry> {
        Err(linux_errno::erofs())
    }
    fn mkdir(
        &self,
        _ctx: Context,
        _parent: u64,
        _name: &CStr,
        _mode: u32,
        _umask: u32,
        _extensions: Extensions,
    ) -> io::Result<Entry> {
        Err(linux_errno::erofs())
    }
    fn unlink(&self, _ctx: Context, _parent: u64, _name: &CStr) -> io::Result<()> {
        Err(linux_errno::erofs())
    }
    fn rmdir(&self, _ctx: Context, _parent: u64, _name: &CStr) -> io::Result<()> {
        Err(linux_errno::erofs())
    }
    fn rename(
        &self,
        _ctx: Context,
        _olddir: u64,
        _oldname: &CStr,
        _newdir: u64,
        _newname: &CStr,
        _flags: u32,
    ) -> io::Result<()> {
        Err(linux_errno::erofs())
    }
    fn link(
        &self,
        _ctx: Context,
        _inode: u64,
        _newparent: u64,
        _newname: &CStr,
    ) -> io::Result<Entry> {
        Err(linux_errno::erofs())
    }
    fn create(
        &self,
        _ctx: Context,
        _parent: u64,
        _name: &CStr,
        _mode: u32,
        _kill_priv: bool,
        _flags: u32,
        _umask: u32,
        _extensions: Extensions,
    ) -> io::Result<(Entry, Option<u64>, OpenOptions)> {
        Err(linux_errno::erofs())
    }
    fn write<R: io::Read + ZeroCopyReader>(
        &self,
        _ctx: Context,
        _inode: u64,
        _handle: u64,
        _r: R,
        _size: u32,
        _offset: u64,
        _lock_owner: Option<u64>,
        _delayed_write: bool,
        _kill_priv: bool,
        _flags: u32,
    ) -> io::Result<usize> {
        Err(linux_errno::erofs())
    }
    fn fallocate(
        &self,
        _ctx: Context,
        _inode: u64,
        _handle: u64,
        _mode: u32,
        _offset: u64,
        _length: u64,
    ) -> io::Result<()> {
        Err(linux_errno::erofs())
    }
    fn setxattr(
        &self,
        _ctx: Context,
        _inode: u64,
        _name: &CStr,
        _value: &[u8],
        _flags: u32,
    ) -> io::Result<()> {
        Err(linux_errno::erofs())
    }
    fn removexattr(&self, _ctx: Context, _inode: u64, _name: &CStr) -> io::Result<()> {
        Err(linux_errno::erofs())
    }
    fn getxattr(
        &self,
        _ctx: Context,
        _inode: u64,
        _name: &CStr,
        _size: u32,
    ) -> io::Result<GetxattrReply> {
        Err(linux_errno::enodata())
    }
    fn listxattr(&self, _ctx: Context, _inode: u64, size: u32) -> io::Result<ListxattrReply> {
        if size == 0 {
            Ok(ListxattrReply::Count(0))
        } else {
            Ok(ListxattrReply::Names(Vec::new()))
        }
    }
    fn setupmapping(
        &self,
        _ctx: Context,
        _inode: u64,
        _handle: u64,
        _foffset: u64,
        _len: u64,
        _flags: u64,
        _moffset: u64,
        _host_shm_base: u64,
        _shm_size: u64,
        _map_sender: &Option<crossbeam_channel::Sender<utils::worker_message::WorkerMessage>>,
    ) -> io::Result<()> {
        Err(linux_errno::enosys())
    }
    fn removemapping(
        &self,
        _ctx: Context,
        _requests: Vec<fuse::RemovemappingOne>,
        _host_shm_base: u64,
        _shm_size: u64,
        _map_sender: &Option<crossbeam_channel::Sender<utils::worker_message::WorkerMessage>>,
    ) -> io::Result<()> {
        Err(linux_errno::enosys())
    }
}

#[cfg(test)]
mod tests {
    use std::ffi::CString;
    use std::fs;
    use std::fs::File;
    use std::io::{self, Write};
    use std::mem::size_of;
    use std::os::unix::fs::{PermissionsExt, symlink};
    use std::path::{Path, PathBuf};
    use std::sync::Arc;
    use std::sync::atomic::{AtomicI32, AtomicU64, Ordering};

    use vm_memory::{ByteValued, GuestAddress};

    use crate::virtio::descriptor_utils::{
        DescriptorType, Reader, Writer, create_descriptor_chain,
    };
    use crate::virtio::fs::augment_fs::AugmentFs;
    use crate::virtio::fs::filesystem::{Context, FileSystem, ZeroCopyWriter};
    use crate::virtio::fs::fuse::{
        InHeader, IoctlIn, IoctlOut, Opcode, OpenIn, OpenOut, OutHeader,
    };
    use crate::virtio::fs::immutable::{
        ImmutableRosettaFs, LINUX_O_RDONLY, LINUX_W_OK, RosettaFsConfig, RosettaProfile,
        TRANSLATOR_INODE, sha256, snapshot_translator_after_open,
    };
    use crate::virtio::fs::inode_alloc::InodeAllocator;
    use crate::virtio::fs::server::Server;
    use crate::virtio::{RuntimeGuestMemory, bindings};

    const UNIQUE: u64 = 0x98ab_7654_3210_fedc;
    const REQUEST_ADDRESS: GuestAddress = GuestAddress(0x1000);
    const LINUX_O_WRONLY: u32 = 1;

    struct TempRoot(PathBuf);

    impl TempRoot {
        fn new(data: &[u8]) -> Self {
            static NEXT: AtomicU64 = AtomicU64::new(0);
            let path = std::env::temp_dir().join(format!(
                "libkrun-rosetta-{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            ));
            fs::create_dir(&path).unwrap();
            let translator = path.join("rosetta");
            fs::write(&translator, data).unwrap();
            fs::set_permissions(&translator, fs::Permissions::from_mode(0o755)).unwrap();
            Self(path.canonicalize().unwrap())
        }

        fn path(&self) -> &Path {
            &self.0
        }
    }

    impl Drop for TempRoot {
        fn drop(&mut self) {
            fs::remove_dir_all(&self.0).unwrap();
        }
    }

    fn context() -> Context {
        Context {
            uid: 0,
            gid: 0,
            pid: 1,
        }
    }

    fn config(snapshot: &[u8], result: i32) -> RosettaFsConfig {
        RosettaFsConfig {
            profile: RosettaProfile::CapturedCompatibilityV1,
            snapshot: Arc::new(snapshot.to_vec()),
            captured_result: result,
            captured_response: Arc::new(std::array::from_fn(|index| index as u8)),
        }
    }

    #[derive(Default)]
    struct VecWriter(Vec<u8>);

    impl Write for VecWriter {
        fn write(&mut self, data: &[u8]) -> io::Result<usize> {
            self.0.extend_from_slice(data);
            Ok(data.len())
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    impl ZeroCopyWriter for VecWriter {
        fn write_from(&mut self, _file: &File, _count: usize, _off: u64) -> io::Result<usize> {
            Err(io::Error::from(io::ErrorKind::Unsupported))
        }
    }

    struct ServerReply {
        written: usize,
        header: OutHeader,
        ioctl: Option<IoctlOut>,
        data: Vec<u8>,
        exit_code: i32,
    }

    fn dispatch_open(flags: u32, directory: bool) -> (OutHeader, Option<OpenOut>) {
        let server = Server::new(AugmentFs::new_without_exit_ioctl(
            ImmutableRosettaFs::new(config(b"synthetic executable", 0)),
            &InodeAllocator::new(),
            Vec::new(),
        ));
        let request_len = size_of::<InHeader>() + size_of::<OpenIn>();
        let response_address = GuestAddress(REQUEST_ADDRESS.0 + request_len as u64);
        let memory = RuntimeGuestMemory::from_ranges(&[(GuestAddress(0), 0x10_000)]).unwrap();
        let header = InHeader {
            len: request_len as u32,
            opcode: if directory {
                Opcode::Opendir as u32
            } else {
                Opcode::Open as u32
            },
            unique: UNIQUE,
            nodeid: if directory { 1 } else { TRANSLATOR_INODE },
            ..Default::default()
        };
        let open = OpenIn {
            flags,
            ..Default::default()
        };
        memory
            .write_slice(header.as_slice(), REQUEST_ADDRESS)
            .unwrap();
        memory
            .write_slice(
                open.as_slice(),
                GuestAddress(REQUEST_ADDRESS.0 + size_of::<InHeader>() as u64),
            )
            .unwrap();
        let chain = create_descriptor_chain(
            &memory,
            GuestAddress(0),
            REQUEST_ADDRESS,
            vec![
                (DescriptorType::Readable, request_len as u32),
                (
                    DescriptorType::Writable,
                    (size_of::<OutHeader>() + size_of::<OpenOut>()) as u32,
                ),
            ],
            0,
        )
        .unwrap();
        let reader = Reader::new(&memory, chain.clone()).unwrap();
        let writer = Writer::new(&memory, chain).unwrap();
        server
            .handle_message(
                reader,
                writer,
                false,
                &None,
                &Arc::new(AtomicI32::new(0)),
                &None,
            )
            .unwrap();
        let header: OutHeader = memory.read_obj(response_address).unwrap();
        let open = (header.error == 0).then(|| {
            memory
                .read_obj(GuestAddress(
                    response_address.0 + size_of::<OutHeader>() as u64,
                ))
                .unwrap()
        });
        (header, open)
    }

    fn dispatch_ioctl(
        result: i32,
        flags: u32,
        cmd: u32,
        in_size: u32,
        out_size: u32,
        handle_delta: u64,
        writer_capacity: usize,
    ) -> ServerReply {
        let inner = ImmutableRosettaFs::new(config(b"synthetic executable", result));
        let handle = inner
            .open(context(), TRANSLATOR_INODE, false, LINUX_O_RDONLY as u32)
            .unwrap()
            .0
            .unwrap()
            + handle_delta;
        let server = Server::new(AugmentFs::new_without_exit_ioctl(
            inner,
            &InodeAllocator::new(),
            Vec::new(),
        ));
        dispatch_ioctl_on_server(
            &server,
            handle,
            flags,
            cmd,
            in_size,
            out_size,
            writer_capacity,
        )
    }

    fn dispatch_ioctl_on_server(
        server: &Server<AugmentFs<ImmutableRosettaFs>>,
        handle: u64,
        flags: u32,
        cmd: u32,
        in_size: u32,
        out_size: u32,
        writer_capacity: usize,
    ) -> ServerReply {
        let request_len = size_of::<InHeader>() + size_of::<IoctlIn>();
        let response_address = GuestAddress(REQUEST_ADDRESS.0 + request_len as u64);
        let memory = RuntimeGuestMemory::from_ranges(&[(GuestAddress(0), 0x20_000)]).unwrap();
        let header = InHeader {
            len: request_len as u32,
            opcode: Opcode::Ioctl as u32,
            unique: UNIQUE,
            nodeid: TRANSLATOR_INODE,
            ..Default::default()
        };
        let ioctl = IoctlIn {
            fh: handle,
            flags,
            cmd,
            in_size,
            out_size,
            ..Default::default()
        };
        memory
            .write_slice(header.as_slice(), REQUEST_ADDRESS)
            .unwrap();
        memory
            .write_slice(
                ioctl.as_slice(),
                GuestAddress(REQUEST_ADDRESS.0 + size_of::<InHeader>() as u64),
            )
            .unwrap();
        let chain = create_descriptor_chain(
            &memory,
            GuestAddress(0),
            REQUEST_ADDRESS,
            vec![
                (DescriptorType::Readable, request_len as u32),
                (DescriptorType::Writable, writer_capacity as u32),
            ],
            0,
        )
        .unwrap();
        let reader = Reader::new(&memory, chain.clone()).unwrap();
        let writer = Writer::new(&memory, chain).unwrap();
        let exit_code = Arc::new(AtomicI32::new(47));
        let written = server
            .handle_message(reader, writer, false, &None, &exit_code, &None)
            .unwrap();
        let out_header: OutHeader = memory.read_obj(response_address).unwrap();
        let ioctl = if out_header.error == 0 {
            Some(
                memory
                    .read_obj(GuestAddress(
                        response_address.0 + size_of::<OutHeader>() as u64,
                    ))
                    .unwrap(),
            )
        } else {
            None
        };
        let data_len = written.saturating_sub(size_of::<OutHeader>() + size_of::<IoctlOut>());
        let mut data = vec![0; data_len];
        if !data.is_empty() {
            memory
                .read_slice(
                    &mut data,
                    GuestAddress(
                        response_address.0
                            + size_of::<OutHeader>() as u64
                            + size_of::<IoctlOut>() as u64,
                    ),
                )
                .unwrap();
        }
        ServerReply {
            written,
            header: out_header,
            ioctl,
            data,
            exit_code: exit_code.load(Ordering::SeqCst),
        }
    }

    #[test]
    fn common_crypto_sha256_known_vector() {
        assert_eq!(
            sha256(b"abc").unwrap(),
            [
                0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea, 0x41, 0x41, 0x40, 0xde, 0x5d, 0xae,
                0x22, 0x23, 0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17, 0x7a, 0x9c, 0xb4, 0x10, 0xff, 0x61,
                0xf2, 0x00, 0x15, 0xad
            ]
        );
    }

    #[test]
    fn constructor_snapshots_actual_executable_bytes() {
        let root = TempRoot::new(b"first synthetic translator");
        let response = [0x5a; 1024];
        let expected = sha256(b"first synthetic translator").unwrap();
        let config = RosettaFsConfig::from_host(
            RosettaProfile::CapturedCompatibilityV1,
            root.path(),
            &expected,
            1,
            &response,
        )
        .unwrap();

        fs::write(root.path().join("rosetta"), b"later host contents").unwrap();
        assert_eq!(&*config.snapshot, b"first synthetic translator");
        assert_eq!(config.captured_result, 1);
        assert_eq!(&*config.captured_response, &response);
    }

    #[test]
    fn constructor_rejects_changed_identity_digest_and_symlinks() {
        let root = TempRoot::new(b"expected");
        let wrong_digest = sha256(b"different").unwrap();
        assert!(
            RosettaFsConfig::from_host(
                RosettaProfile::CapturedCompatibilityV1,
                root.path(),
                &wrong_digest,
                0,
                &[0; 1024],
            )
            .is_err()
        );

        let target = root.path().join("actual");
        fs::rename(root.path().join("rosetta"), &target).unwrap();
        symlink(&target, root.path().join("rosetta")).unwrap();
        assert!(
            RosettaFsConfig::from_host(
                RosettaProfile::CapturedCompatibilityV1,
                root.path(),
                &sha256(b"expected").unwrap(),
                0,
                &[0; 1024],
            )
            .is_err()
        );
    }

    #[test]
    fn constructor_detects_atomic_and_in_place_changes_after_open() {
        let root = TempRoot::new(b"original");
        let replacement = root.path().join("replacement");
        fs::write(&replacement, b"replaced").unwrap();
        fs::set_permissions(&replacement, fs::Permissions::from_mode(0o755)).unwrap();
        assert!(
            snapshot_translator_after_open(root.path(), || {
                fs::rename(&replacement, root.path().join("rosetta"))
            })
            .is_err()
        );

        fs::write(root.path().join("rosetta"), b"original").unwrap();
        fs::set_permissions(
            root.path().join("rosetta"),
            fs::Permissions::from_mode(0o755),
        )
        .unwrap();
        assert!(
            snapshot_translator_after_open(root.path(), || {
                fs::write(root.path().join("rosetta"), b"modified")
            })
            .is_err()
        );
    }

    #[test]
    fn immutable_namespace_uses_checked_non_reused_handles() {
        let fs = ImmutableRosettaFs::new(config(b"bytes", 0));
        let translator = CString::new("rosetta").unwrap();
        let unknown = CString::new("companion").unwrap();
        let dotdot = CString::new("..").unwrap();
        assert_eq!(fs.lookup(context(), 1, &translator).unwrap().inode, 2);
        assert_eq!(
            fs.lookup(context(), 1, &unknown)
                .err()
                .unwrap()
                .raw_os_error(),
            Some(2)
        );
        assert_eq!(
            fs.lookup(context(), 1, &dotdot)
                .err()
                .unwrap()
                .raw_os_error(),
            Some(2)
        );

        let first = fs
            .open(context(), 2, false, LINUX_O_RDONLY as u32)
            .unwrap()
            .0
            .unwrap();
        fs.release(context(), 2, 0, first, false, false, None)
            .unwrap();
        assert_eq!(
            fs.release(context(), 2, 0, first, false, false, None)
                .unwrap_err()
                .raw_os_error(),
            Some(9)
        );
        let second = fs
            .open(context(), 2, false, LINUX_O_RDONLY as u32)
            .unwrap()
            .0
            .unwrap();
        assert_ne!(first, second);
        assert_eq!(
            fs.open(context(), 2, false, LINUX_O_WRONLY)
                .unwrap_err()
                .raw_os_error(),
            Some(30)
        );

        let mut writer = VecWriter::default();
        assert_eq!(
            fs.read(context(), 2, second, &mut writer, 3, 1, None, 0)
                .unwrap(),
            3
        );
        assert_eq!(writer.0, b"yte");

        let directory = fs
            .opendir(context(), 1, LINUX_O_RDONLY as u32)
            .unwrap()
            .0
            .unwrap();
        let mut names = Vec::new();
        fs.readdir(context(), 1, directory, 4096, 0, |entry| {
            names.push(entry.name.to_vec());
            Ok(1)
        })
        .unwrap();
        assert_eq!(names, [b".".to_vec(), b"..".to_vec(), b"rosetta".to_vec()]);
        fs.releasedir(context(), 1, 0, directory).unwrap();
        assert_eq!(
            fs.readdir(context(), 1, directory, 4096, 0, |_| Ok(1))
                .unwrap_err()
                .raw_os_error(),
            Some(9)
        );
        assert_eq!(
            fs.access(context(), 2, LINUX_W_OK)
                .unwrap_err()
                .raw_os_error(),
            Some(30)
        );
        assert_eq!(fs.statfs(context(), 1).unwrap().f_flag, libc::ST_RDONLY);
    }

    #[test]
    fn real_server_validates_raw_linux_open_flags() {
        let read_cloexec = (LINUX_O_RDONLY | bindings::LINUX_O_CLOEXEC) as u32;
        let (header, open) = dispatch_open(read_cloexec, false);
        assert_eq!(header.error, 0);
        assert!(open.is_some());

        let read_append = (LINUX_O_RDONLY | bindings::LINUX_O_APPEND) as u32;
        let (header, open) = dispatch_open(read_append, false);
        assert_eq!(header.error, 0);
        assert!(open.is_some());

        let read_truncate = (LINUX_O_RDONLY | bindings::LINUX_O_TRUNC) as u32;
        let (header, open) = dispatch_open(read_truncate, false);
        assert_eq!(header.error, -30);
        assert!(open.is_none());

        let (header, open) = dispatch_open(read_cloexec, true);
        assert_eq!(header.error, 0);
        assert!(open.is_some());
        let (header, open) = dispatch_open(read_truncate, true);
        assert_eq!(header.error, -30);
        assert!(open.is_none());
    }

    #[test]
    fn handle_limit_is_bounded_and_recovers_without_reusing_ids() {
        let fs = ImmutableRosettaFs::with_handle_limit(config(b"bytes", 0), 2);
        let first = fs
            .open(context(), 2, false, LINUX_O_RDONLY as u32)
            .unwrap()
            .0
            .unwrap();
        let directory = fs
            .opendir(context(), 1, LINUX_O_RDONLY as u32)
            .unwrap()
            .0
            .unwrap();
        assert_eq!(
            fs.open(context(), 2, false, LINUX_O_RDONLY as u32)
                .unwrap_err()
                .raw_os_error(),
            Some(24)
        );

        fs.releasedir(context(), 1, 0, directory).unwrap();
        let recovered = fs
            .open(context(), 2, false, LINUX_O_RDONLY as u32)
            .unwrap()
            .0
            .unwrap();
        assert!(recovered > directory);
        assert_ne!(recovered, first);
    }

    #[test]
    fn real_server_destroy_clears_and_fences_handles() {
        let config = config(b"bytes", 0);
        let inner = ImmutableRosettaFs::with_handle_limit(config.clone(), 2);
        let state = inner.clone();
        let handle = inner
            .open(context(), 2, false, LINUX_O_RDONLY as u32)
            .unwrap()
            .0
            .unwrap();
        let server = Server::new(AugmentFs::new_without_exit_ioctl(
            inner,
            &InodeAllocator::new(),
            Vec::new(),
        ));
        let request_len = size_of::<InHeader>();
        let memory = RuntimeGuestMemory::from_ranges(&[(GuestAddress(0), 0x10_000)]).unwrap();
        let header = InHeader {
            len: request_len as u32,
            opcode: Opcode::Destroy as u32,
            unique: UNIQUE,
            nodeid: 1,
            ..Default::default()
        };
        memory
            .write_slice(header.as_slice(), REQUEST_ADDRESS)
            .unwrap();
        let chain = create_descriptor_chain(
            &memory,
            GuestAddress(0),
            REQUEST_ADDRESS,
            vec![
                (DescriptorType::Readable, request_len as u32),
                (DescriptorType::Writable, size_of::<OutHeader>() as u32),
            ],
            0,
        )
        .unwrap();
        let reader = Reader::new(&memory, chain.clone()).unwrap();
        let writer = Writer::new(&memory, chain).unwrap();
        assert_eq!(
            server
                .handle_message(
                    reader,
                    writer,
                    false,
                    &None,
                    &Arc::new(AtomicI32::new(0)),
                    &None,
                )
                .unwrap(),
            0
        );

        assert_eq!(
            state
                .read(context(), 2, handle, VecWriter::default(), 1, 0, None, 0,)
                .unwrap_err()
                .raw_os_error(),
            Some(9)
        );
        let ioctl_after_destroy =
            dispatch_ioctl_on_server(&server, handle, 0, 0x80456122, 0, 0, size_of::<OutHeader>());
        assert_eq!(ioctl_after_destroy.header.error, -9);
        assert_eq!(
            state
                .open(context(), 2, false, LINUX_O_RDONLY as u32)
                .unwrap_err()
                .raw_os_error(),
            Some(9)
        );

        let fresh = ImmutableRosettaFs::with_handle_limit(config, 2);
        assert_eq!(
            fresh
                .open(context(), 2, false, LINUX_O_RDONLY as u32)
                .unwrap()
                .0,
            Some(1)
        );
    }

    #[test]
    fn real_server_preserves_status_prefix_unique_and_bounds() {
        for result in [0, 1] {
            for (cmd, size) in [
                (0x80456122, 0),
                (0x80456125, 1),
                (0x804561ab, 68),
                (0x80456122, 69),
                (0x80456125, 70),
                (0x804561ab, 1023),
                (0x80456122, 1024),
            ] {
                let capacity = size_of::<OutHeader>() + size_of::<IoctlOut>() + size;
                let reply = dispatch_ioctl(result, 0, cmd, 0, size as u32, 0, capacity);
                assert_eq!(reply.written, capacity);
                assert_eq!(reply.header.unique, UNIQUE);
                assert_eq!(reply.header.error, 0);
                assert_eq!(reply.ioctl.unwrap().result, result);
                assert_eq!(
                    reply.data,
                    (0..size).map(|index| index as u8).collect::<Vec<_>>()
                );
            }
        }

        let oversized = dispatch_ioctl(0, 0, 0x80456122, 0, 1025, 0, size_of::<OutHeader>());
        assert_eq!(oversized.header.error, -25);
        assert!(oversized.ioctl.is_none());

        let invalid_handle = dispatch_ioctl(0, 0, 0x80456122, 0, 0, 1, size_of::<OutHeader>());
        assert_eq!(invalid_handle.header.error, -9);
    }

    #[test]
    fn real_server_enforces_profile_forms_and_isolates_exit_ioctl() {
        let ones = dispatch_ioctl(
            7,
            0,
            0x80806123,
            0,
            128,
            0,
            size_of::<OutHeader>() + size_of::<IoctlOut>() + 128,
        );
        assert_eq!(ones.ioctl.unwrap().result, 0);
        assert_eq!(ones.data, vec![1; 128]);

        let empty = dispatch_ioctl(
            7,
            0,
            0x6124,
            0,
            0,
            0,
            size_of::<OutHeader>() + size_of::<IoctlOut>(),
        );
        assert_eq!(empty.ioctl.unwrap().result, 0);
        assert!(empty.data.is_empty());

        for (flags, cmd, input, output) in [
            (1, 0x80456122, 0, 0),
            (0, 0x80456122, 1, 0),
            (0, 0x80806123, 0, 127),
            (0, 0x6124, 0, 1),
            (0, 0x1234, 0, 0),
            (0, 0x7602, 0, 0),
        ] {
            let reply = dispatch_ioctl(7, flags, cmd, input, output, 0, size_of::<OutHeader>());
            assert_eq!(reply.header.error, -25);
            assert_eq!(reply.exit_code, 47);
        }
    }

    #[test]
    fn config_validation_is_strict() {
        let root = TempRoot::new(b"bytes");
        let digest = sha256(b"bytes").unwrap();
        for (digest, result, response) in [
            (&digest[..31], 0, &[0; 1024][..]),
            (&digest[..], -1, &[0; 1024][..]),
            (&digest[..], 0, &[0; 1023][..]),
        ] {
            assert_eq!(
                RosettaFsConfig::from_host(
                    RosettaProfile::CapturedCompatibilityV1,
                    root.path(),
                    digest,
                    result,
                    response,
                )
                .unwrap_err()
                .kind(),
                io::ErrorKind::InvalidInput
            );
        }
    }
}

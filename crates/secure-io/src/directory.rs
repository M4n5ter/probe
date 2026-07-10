use std::{
    ffi::{OsStr, OsString},
    fmt,
    fs::File,
    os::fd::{AsFd, BorrowedFd, OwnedFd},
    path::{Component, Path, PathBuf},
};

use rustix::{
    fs::{
        FileType, Mode, OFlags, ResolveFlags, fchmod, fstat, fsync, mkdirat, open, openat, openat2,
    },
    io::Errno,
    process::geteuid,
};

const DIRECTORY_MODE: Mode = Mode::RWXU;
const FILE_MODE: Mode = Mode::RUSR.union(Mode::WUSR);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PathViolation {
    MustBeAbsolute,
    MustBeRelative,
    RootNotAllowed,
    EmptyNotAllowed,
    ParentTraversal,
    NonNormalComponent,
}

impl fmt::Display for PathViolation {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::MustBeAbsolute => "path must be absolute",
            Self::MustBeRelative => "path must be relative",
            Self::RootNotAllowed => "filesystem root is not a private directory",
            Self::EmptyNotAllowed => "relative path must contain at least one component",
            Self::ParentTraversal => "parent traversal is not allowed",
            Self::NonNormalComponent => "path may contain only normal components",
        })
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FilesystemOperation {
    OpenRoot,
    OpenDirectory,
    CreateDirectory,
    SetPermissions,
    Inspect,
    SyncDirectory,
    OpenFile,
    CreateFile,
    CreateAnonymousFile,
}

impl fmt::Display for FilesystemOperation {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::OpenRoot => "open filesystem root",
            Self::OpenDirectory => "open directory",
            Self::CreateDirectory => "create directory",
            Self::SetPermissions => "set owner-private permissions",
            Self::Inspect => "inspect opened filesystem object",
            Self::SyncDirectory => "synchronize directory",
            Self::OpenFile => "open file",
            Self::CreateFile => "create file exclusively",
            Self::CreateAnonymousFile => "create anonymous file",
        })
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FilesystemObject {
    Directory,
    RegularFile,
}

impl fmt::Display for FilesystemObject {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Directory => "directory",
            Self::RegularFile => "regular file",
        })
    }
}

#[derive(Debug)]
pub enum PrivateDirectoryError {
    InvalidPath {
        path: PathBuf,
        violation: PathViolation,
    },
    NotFound {
        path: PathBuf,
    },
    AlreadyExists {
        path: PathBuf,
    },
    Symlink {
        path: PathBuf,
    },
    InvalidDirectoryComponent {
        path: PathBuf,
    },
    NotRegularFile {
        path: PathBuf,
    },
    OwnerMismatch {
        path: PathBuf,
        object: FilesystemObject,
        owner_uid: u32,
        effective_uid: u32,
    },
    InsecurePermissions {
        path: PathBuf,
        object: FilesystemObject,
        mode: u32,
    },
    UnexpectedLinkCount {
        path: PathBuf,
        expected: u64,
        actual: u64,
    },
    ResolutionRace {
        path: PathBuf,
    },
    ContainmentViolation {
        path: PathBuf,
    },
    Openat2Unsupported,
    Io {
        operation: FilesystemOperation,
        path: PathBuf,
        source: std::io::Error,
    },
}

impl fmt::Display for PrivateDirectoryError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidPath { path, violation } => {
                write!(
                    formatter,
                    "invalid secure filesystem path {}: {violation}",
                    path.display()
                )
            }
            Self::NotFound { path } => {
                write!(
                    formatter,
                    "secure filesystem path does not exist: {}",
                    path.display()
                )
            }
            Self::AlreadyExists { path } => write!(
                formatter,
                "secure file creation requires a new path, but {} already exists",
                path.display()
            ),
            Self::Symlink { path } => write!(
                formatter,
                "secure filesystem path contains a symlink or magic link: {}",
                path.display()
            ),
            Self::InvalidDirectoryComponent { path } => {
                write!(
                    formatter,
                    "secure directory component is not a directory or is a rejected symlink: {}",
                    path.display()
                )
            }
            Self::NotRegularFile { path } => {
                write!(
                    formatter,
                    "secure file path is not a regular file: {}",
                    path.display()
                )
            }
            Self::OwnerMismatch {
                path,
                object,
                owner_uid,
                effective_uid,
            } => write!(
                formatter,
                "secure {object} {} is owned by uid {owner_uid}, not effective uid {effective_uid}",
                path.display()
            ),
            Self::InsecurePermissions { path, object, mode } => write!(
                formatter,
                "secure {object} {} has group or other permission bits set ({mode:o})",
                path.display()
            ),
            Self::UnexpectedLinkCount {
                path,
                expected,
                actual,
            } => write!(
                formatter,
                "secure regular file {} has {actual} link(s), expected {expected}",
                path.display(),
            ),
            Self::ResolutionRace { path } => write!(
                formatter,
                "secure path resolution raced with a filesystem change at {}; retry from a fresh root fd",
                path.display()
            ),
            Self::ContainmentViolation { path } => write!(
                formatter,
                "secure path resolution attempted to escape its root at {}",
                path.display()
            ),
            Self::Openat2Unsupported => formatter.write_str(
                "the running Linux kernel does not support openat2, which is required for secure path containment",
            ),
            Self::Io {
                operation,
                path,
                source,
            } => write!(
                formatter,
                "failed to {operation} at {}: {source}",
                path.display()
            ),
        }
    }
}

impl std::error::Error for PrivateDirectoryError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io { source, .. } => Some(source),
            _ => None,
        }
    }
}

#[derive(Debug)]
pub struct PrivateDirectory {
    fd: OwnedFd,
    path: PathBuf,
}

impl PrivateDirectory {
    pub fn ensure(path: &Path) -> Result<Self, PrivateDirectoryError> {
        let components = absolute_components(path)?;
        let root = open(
            "/",
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
            Mode::empty(),
        )
        .map_err(|source| io_error(FilesystemOperation::OpenRoot, Path::new("/"), source))?;
        let fd = walk_directories(root.as_fd(), Path::new("/"), &components, WalkMode::Ensure)?;
        Ok(Self {
            fd,
            path: path.to_path_buf(),
        })
    }

    pub fn open(path: &Path) -> Result<Self, PrivateDirectoryError> {
        let components = absolute_components(path)?;
        let root = open(
            "/",
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
            Mode::empty(),
        )
        .map_err(|source| io_error(FilesystemOperation::OpenRoot, Path::new("/"), source))?;
        let fd = walk_directories(root.as_fd(), Path::new("/"), &components, WalkMode::Open)?;
        Ok(Self {
            fd,
            path: path.to_path_buf(),
        })
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn into_fd(self) -> OwnedFd {
        self.fd
    }

    pub fn ensure_dir(&self, relative: &Path) -> Result<Self, PrivateDirectoryError> {
        let components = relative_components(relative)?;
        let path = self.path.join(relative);
        let fd = walk_directories(
            self.fd.as_fd(),
            &self.path,
            &components,
            WalkMode::EnsurePrivateHierarchy,
        )?;
        Ok(Self { fd, path })
    }

    pub fn create_new_file(&self, relative: &Path) -> Result<File, PrivateDirectoryError> {
        relative_components(relative)?;
        let path = self.path.join(relative);
        let fd = openat2(
            &self.fd,
            relative,
            OFlags::RDWR
                | OFlags::CREATE
                | OFlags::EXCL
                | OFlags::CLOEXEC
                | OFlags::NOFOLLOW
                | OFlags::NONBLOCK,
            FILE_MODE,
            containment_flags(),
        )
        .map_err(|source| map_file_open_error(&path, FilesystemOperation::CreateFile, source))?;
        fchmod(&fd, FILE_MODE)
            .map_err(|source| io_error(FilesystemOperation::SetPermissions, &path, source))?;
        validate_regular_file(&fd, &path)?;
        Ok(File::from(fd))
    }

    pub fn open_file_read(&self, relative: &Path) -> Result<File, PrivateDirectoryError> {
        self.open_file(relative, OFlags::RDONLY)
    }

    pub fn open_file_read_write(&self, relative: &Path) -> Result<File, PrivateDirectoryError> {
        self.open_file(relative, OFlags::RDWR)
    }

    pub fn create_anonymous_file(&self) -> Result<File, PrivateDirectoryError> {
        let fd = openat(
            &self.fd,
            ".",
            OFlags::RDWR | OFlags::TMPFILE | OFlags::CLOEXEC,
            FILE_MODE,
        )
        .map_err(|source| io_error(FilesystemOperation::CreateAnonymousFile, &self.path, source))?;
        fchmod(&fd, FILE_MODE)
            .map_err(|source| io_error(FilesystemOperation::SetPermissions, &self.path, source))?;
        validate_anonymous_file(&fd, &self.path)?;
        Ok(File::from(fd))
    }

    pub fn sync(&self) -> Result<(), PrivateDirectoryError> {
        fsync(&self.fd)
            .map_err(|source| io_error(FilesystemOperation::SyncDirectory, &self.path, source))
    }

    fn open_file(&self, relative: &Path, access: OFlags) -> Result<File, PrivateDirectoryError> {
        relative_components(relative)?;
        let path = self.path.join(relative);
        let fd = openat2(
            &self.fd,
            relative,
            access | OFlags::CLOEXEC | OFlags::NOFOLLOW | OFlags::NONBLOCK,
            Mode::empty(),
            containment_flags(),
        )
        .map_err(|source| map_file_open_error(&path, FilesystemOperation::OpenFile, source))?;
        validate_regular_file(&fd, &path)?;
        Ok(File::from(fd))
    }
}

impl AsFd for PrivateDirectory {
    fn as_fd(&self) -> BorrowedFd<'_> {
        self.fd.as_fd()
    }
}

#[derive(Clone, Copy, Eq, PartialEq)]
enum WalkMode {
    Open,
    Ensure,
    EnsurePrivateHierarchy,
}

impl WalkMode {
    fn creates_missing(self) -> bool {
        self != Self::Open
    }

    fn validates_existing_intermediates(self) -> bool {
        self == Self::EnsurePrivateHierarchy
    }
}

fn walk_directories(
    start: BorrowedFd<'_>,
    start_path: &Path,
    components: &[OsString],
    mode: WalkMode,
) -> Result<OwnedFd, PrivateDirectoryError> {
    let mut current = None;
    let mut parent_path = start_path.to_path_buf();

    for (index, component) in components.iter().enumerate() {
        let parent_fd = current.as_ref().map_or(start, AsFd::as_fd);
        let path = parent_path.join(component);
        let (next, created) =
            open_or_create_directory(parent_fd, component, &path, mode.creates_missing())?;
        let is_final = index + 1 == components.len();

        if created {
            fchmod(&next, DIRECTORY_MODE)
                .map_err(|source| io_error(FilesystemOperation::SetPermissions, &path, source))?;
        }
        if !is_final && (created || mode.validates_existing_intermediates()) {
            validate_private_directory(&next, &path)?;
        }
        if created {
            fsync(parent_fd).map_err(|source| {
                io_error(FilesystemOperation::SyncDirectory, &parent_path, source)
            })?;
        }

        current = Some(next);
        parent_path = path;
    }

    let final_fd = current.ok_or_else(|| PrivateDirectoryError::InvalidPath {
        path: start_path.to_path_buf(),
        violation: PathViolation::EmptyNotAllowed,
    })?;
    validate_private_directory(&final_fd, &parent_path)?;
    Ok(final_fd)
}

fn open_or_create_directory(
    parent: BorrowedFd<'_>,
    component: &OsStr,
    path: &Path,
    create: bool,
) -> Result<(OwnedFd, bool), PrivateDirectoryError> {
    match open_directory(parent, component) {
        Ok(fd) => Ok((fd, false)),
        Err(Errno::NOENT) if create => {
            let created = match mkdirat(parent, component, DIRECTORY_MODE) {
                Ok(()) => true,
                Err(Errno::EXIST) => false,
                Err(source) => {
                    return Err(io_error(FilesystemOperation::CreateDirectory, path, source));
                }
            };
            open_directory(parent, component)
                .map(|fd| (fd, created))
                .map_err(|source| map_directory_open_error(path, source))
        }
        Err(source) => Err(map_directory_open_error(path, source)),
    }
}

fn open_directory(parent: BorrowedFd<'_>, component: &OsStr) -> rustix::io::Result<OwnedFd> {
    openat2(
        parent,
        component,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
        Mode::empty(),
        containment_flags(),
    )
}

fn validate_private_directory(fd: &OwnedFd, path: &Path) -> Result<(), PrivateDirectoryError> {
    let stat = fstat(fd).map_err(|source| io_error(FilesystemOperation::Inspect, path, source))?;
    if !FileType::from_raw_mode(stat.st_mode).is_dir() {
        return Err(PrivateDirectoryError::InvalidDirectoryComponent {
            path: path.to_path_buf(),
        });
    }

    let effective_uid = geteuid().as_raw();
    if stat.st_uid != effective_uid {
        return Err(PrivateDirectoryError::OwnerMismatch {
            path: path.to_path_buf(),
            object: FilesystemObject::Directory,
            owner_uid: stat.st_uid,
            effective_uid,
        });
    }

    let mode = Mode::from_raw_mode(stat.st_mode).as_raw_mode();
    if mode & 0o077 != 0 {
        return Err(PrivateDirectoryError::InsecurePermissions {
            path: path.to_path_buf(),
            object: FilesystemObject::Directory,
            mode,
        });
    }
    Ok(())
}

fn validate_regular_file(fd: &OwnedFd, path: &Path) -> Result<(), PrivateDirectoryError> {
    validate_file(fd, path, 1)
}

fn validate_anonymous_file(fd: &OwnedFd, path: &Path) -> Result<(), PrivateDirectoryError> {
    validate_file(fd, path, 0)
}

fn validate_file(
    fd: &OwnedFd,
    path: &Path,
    expected_links: u64,
) -> Result<(), PrivateDirectoryError> {
    let stat = fstat(fd).map_err(|source| io_error(FilesystemOperation::Inspect, path, source))?;
    if !FileType::from_raw_mode(stat.st_mode).is_file() {
        return Err(PrivateDirectoryError::NotRegularFile {
            path: path.to_path_buf(),
        });
    }

    let effective_uid = geteuid().as_raw();
    if stat.st_uid != effective_uid {
        return Err(PrivateDirectoryError::OwnerMismatch {
            path: path.to_path_buf(),
            object: FilesystemObject::RegularFile,
            owner_uid: stat.st_uid,
            effective_uid,
        });
    }

    let mode = Mode::from_raw_mode(stat.st_mode).as_raw_mode();
    if mode & 0o077 != 0 {
        return Err(PrivateDirectoryError::InsecurePermissions {
            path: path.to_path_buf(),
            object: FilesystemObject::RegularFile,
            mode,
        });
    }

    if stat.st_nlink != expected_links {
        return Err(PrivateDirectoryError::UnexpectedLinkCount {
            path: path.to_path_buf(),
            expected: expected_links,
            actual: stat.st_nlink,
        });
    }
    Ok(())
}

fn absolute_components(path: &Path) -> Result<Vec<OsString>, PrivateDirectoryError> {
    if !path.is_absolute() {
        return Err(invalid_path(path, PathViolation::MustBeAbsolute));
    }

    let mut components = Vec::new();
    for component in path.components() {
        match component {
            Component::RootDir => {}
            Component::Normal(component) => components.push(component.to_os_string()),
            Component::ParentDir => {
                return Err(invalid_path(path, PathViolation::ParentTraversal));
            }
            Component::CurDir | Component::Prefix(_) => {
                return Err(invalid_path(path, PathViolation::NonNormalComponent));
            }
        }
    }
    if components.is_empty() {
        return Err(invalid_path(path, PathViolation::RootNotAllowed));
    }
    Ok(components)
}

fn relative_components(path: &Path) -> Result<Vec<OsString>, PrivateDirectoryError> {
    if path.is_absolute() {
        return Err(invalid_path(path, PathViolation::MustBeRelative));
    }

    let mut components = Vec::new();
    for component in path.components() {
        match component {
            Component::Normal(component) => components.push(component.to_os_string()),
            Component::ParentDir => {
                return Err(invalid_path(path, PathViolation::ParentTraversal));
            }
            Component::RootDir | Component::CurDir | Component::Prefix(_) => {
                return Err(invalid_path(path, PathViolation::NonNormalComponent));
            }
        }
    }
    if components.is_empty() {
        return Err(invalid_path(path, PathViolation::EmptyNotAllowed));
    }
    Ok(components)
}

fn containment_flags() -> ResolveFlags {
    ResolveFlags::BENEATH | ResolveFlags::NO_MAGICLINKS | ResolveFlags::NO_SYMLINKS
}

fn map_directory_open_error(path: &Path, source: Errno) -> PrivateDirectoryError {
    match source {
        Errno::NOENT => PrivateDirectoryError::NotFound {
            path: path.to_path_buf(),
        },
        Errno::LOOP => PrivateDirectoryError::Symlink {
            path: path.to_path_buf(),
        },
        Errno::NOTDIR => PrivateDirectoryError::InvalidDirectoryComponent {
            path: path.to_path_buf(),
        },
        source => map_resolution_error(path, FilesystemOperation::OpenDirectory, source),
    }
}

fn map_file_open_error(
    path: &Path,
    operation: FilesystemOperation,
    source: Errno,
) -> PrivateDirectoryError {
    match source {
        Errno::NOENT => PrivateDirectoryError::NotFound {
            path: path.to_path_buf(),
        },
        Errno::EXIST => PrivateDirectoryError::AlreadyExists {
            path: path.to_path_buf(),
        },
        Errno::LOOP => PrivateDirectoryError::Symlink {
            path: path.to_path_buf(),
        },
        Errno::NOTDIR => PrivateDirectoryError::InvalidDirectoryComponent {
            path: path.to_path_buf(),
        },
        Errno::ISDIR => PrivateDirectoryError::NotRegularFile {
            path: path.to_path_buf(),
        },
        source => map_resolution_error(path, operation, source),
    }
}

fn map_resolution_error(
    path: &Path,
    operation: FilesystemOperation,
    source: Errno,
) -> PrivateDirectoryError {
    match source {
        Errno::AGAIN => PrivateDirectoryError::ResolutionRace {
            path: path.to_path_buf(),
        },
        Errno::XDEV => PrivateDirectoryError::ContainmentViolation {
            path: path.to_path_buf(),
        },
        Errno::NOSYS => PrivateDirectoryError::Openat2Unsupported,
        source => io_error(operation, path, source),
    }
}

fn invalid_path(path: &Path, violation: PathViolation) -> PrivateDirectoryError {
    PrivateDirectoryError::InvalidPath {
        path: path.to_path_buf(),
        violation,
    }
}

fn io_error(operation: FilesystemOperation, path: &Path, source: Errno) -> PrivateDirectoryError {
    PrivateDirectoryError::Io {
        operation,
        path: path.to_path_buf(),
        source: source.into(),
    }
}

#[cfg(test)]
mod tests {
    use std::{
        fs,
        io::{Read, Seek, SeekFrom, Write},
        os::fd::{AsFd as _, AsRawFd},
        os::unix::fs::{PermissionsExt, symlink},
    };

    use rustix::io::{FdFlags, fcntl_getfd};
    use tempfile::tempdir;

    use super::*;

    #[test]
    fn creates_owner_private_nested_directories_and_file() -> Result<(), Box<dyn std::error::Error>>
    {
        let temp = tempdir()?;
        let root_path = temp.path().join("state");

        let root = PrivateDirectory::ensure(&root_path)?;
        let nested = root.ensure_dir(Path::new("evidence/segments"))?;
        let mut file = nested.create_new_file(Path::new("active.segment"))?;
        file.write_all(b"record")?;
        file.seek(SeekFrom::Start(0))?;
        let mut contents = Vec::new();
        file.read_to_end(&mut contents)?;

        assert_eq!(contents, b"record");
        assert_eq!(mode(&root_path)?, 0o700);
        assert_eq!(mode(&root_path.join("evidence"))?, 0o700);
        assert_eq!(mode(&root_path.join("evidence/segments"))?, 0o700);
        assert_eq!(
            mode(&root_path.join("evidence/segments/active.segment"))?,
            0o600
        );
        assert_cloexec(&root)?;
        assert_cloexec(&nested)?;
        assert_cloexec(&file)?;
        Ok(())
    }

    #[test]
    fn creates_anonymous_owner_private_files_without_directory_entries()
    -> Result<(), Box<dyn std::error::Error>> {
        let temp = tempdir()?;
        let root_path = temp.path().join("state");
        let root = PrivateDirectory::ensure(&root_path)?;
        let before = fs::read_dir(&root_path)?.count();

        let mut file = root.create_anonymous_file()?;
        file.write_all(b"staged metadata")?;
        file.seek(SeekFrom::Start(0))?;
        let mut contents = Vec::new();
        file.read_to_end(&mut contents)?;

        assert_eq!(contents, b"staged metadata");
        let stat = fstat(file.as_fd())?;
        assert_eq!(stat.st_nlink, 0);
        assert_eq!(
            Mode::from_raw_mode(stat.st_mode).as_raw_mode() & 0o777,
            0o600
        );
        assert_eq!(fs::read_dir(&root_path)?.count(), before);
        Ok(())
    }

    #[test]
    fn opens_existing_private_directory_and_files() -> Result<(), Box<dyn std::error::Error>> {
        let temp = tempdir()?;
        let root_path = temp.path().join("state");
        let root = PrivateDirectory::ensure(&root_path)?;
        let mut created = root.create_new_file(Path::new("data"))?;
        created.write_all(b"before")?;
        drop(created);

        let reopened = PrivateDirectory::open(&root_path)?;
        let mut read = reopened.open_file_read(Path::new("data"))?;
        let mut contents = String::new();
        read.read_to_string(&mut contents)?;
        assert_eq!(contents, "before");

        let mut read_write = reopened.open_file_read_write(Path::new("data"))?;
        read_write.seek(SeekFrom::End(0))?;
        read_write.write_all(b" after")?;
        assert_eq!(fs::read_to_string(root_path.join("data"))?, "before after");
        reopened.sync()?;
        Ok(())
    }

    #[test]
    fn rejects_insecure_existing_final_directory() -> Result<(), Box<dyn std::error::Error>> {
        let temp = tempdir()?;
        let path = temp.path().join("shared");
        fs::create_dir(&path)?;
        fs::set_permissions(&path, fs::Permissions::from_mode(0o750))?;

        let error = PrivateDirectory::open(&path).expect_err("shared directory must be rejected");

        assert!(matches!(
            error,
            PrivateDirectoryError::InsecurePermissions { mode: 0o750, .. }
        ));
        Ok(())
    }

    #[test]
    fn rejects_insecure_contained_directory_hierarchy() -> Result<(), Box<dyn std::error::Error>> {
        let temp = tempdir()?;
        let root_path = temp.path().join("state");
        let root = PrivateDirectory::ensure(&root_path)?;
        let shared = root_path.join("shared");
        fs::create_dir(&shared)?;
        fs::set_permissions(&shared, fs::Permissions::from_mode(0o755))?;

        let error = root
            .ensure_dir(Path::new("shared/child"))
            .expect_err("insecure child hierarchy must be rejected");

        assert!(matches!(
            error,
            PrivateDirectoryError::InsecurePermissions { mode: 0o755, .. }
        ));
        assert!(!shared.join("child").exists());
        Ok(())
    }

    #[test]
    fn rejects_absolute_root_relative_and_parent_paths() -> Result<(), Box<dyn std::error::Error>> {
        let temp = tempdir()?;
        let root = PrivateDirectory::ensure(&temp.path().join("state"))?;

        assert_invalid_path(
            PrivateDirectory::ensure(Path::new("relative")),
            PathViolation::MustBeAbsolute,
        );
        assert_invalid_path(
            PrivateDirectory::open(Path::new("/")),
            PathViolation::RootNotAllowed,
        );
        assert_invalid_path(
            PrivateDirectory::ensure(&temp.path().join("state/../escape")),
            PathViolation::ParentTraversal,
        );
        assert_invalid_path(
            root.ensure_dir(Path::new("../escape")),
            PathViolation::ParentTraversal,
        );
        assert_invalid_path(
            root.create_new_file(Path::new("/absolute")),
            PathViolation::MustBeRelative,
        );
        assert_invalid_path(
            root.open_file_read(Path::new("")),
            PathViolation::EmptyNotAllowed,
        );
        Ok(())
    }

    #[test]
    fn rejects_directory_symlink_escapes() -> Result<(), Box<dyn std::error::Error>> {
        let temp = tempdir()?;
        let outside = temp.path().join("outside");
        let root_path = temp.path().join("state");
        fs::create_dir(&outside)?;
        let root = PrivateDirectory::ensure(&root_path)?;

        symlink(&outside, root_path.join("link"))?;

        let absolute_error = PrivateDirectory::ensure(&root_path.join("link/child"))
            .expect_err("absolute traversal through a symlink must fail");
        let relative_error = root
            .ensure_dir(Path::new("link/child"))
            .expect_err("contained traversal through a symlink must fail");
        assert_directory_symlink_rejected(absolute_error);
        assert_directory_symlink_rejected(relative_error);
        assert!(!outside.join("child").exists());
        Ok(())
    }

    #[test]
    fn rejects_procfs_magic_link() -> Result<(), Box<dyn std::error::Error>> {
        let temp = tempdir()?;
        let root = PrivateDirectory::ensure(&temp.path().join("state"))?;
        let magic_link = PathBuf::from(format!("/proc/self/fd/{}", root.as_fd().as_raw_fd()));

        let error = PrivateDirectory::open(&magic_link)
            .expect_err("procfs magic link must not open as a private directory");

        assert_directory_symlink_rejected(error);
        Ok(())
    }

    #[test]
    fn rejects_file_symlink_escapes() -> Result<(), Box<dyn std::error::Error>> {
        let temp = tempdir()?;
        let outside = temp.path().join("outside");
        let root_path = temp.path().join("state");
        fs::create_dir(&outside)?;
        fs::write(outside.join("secret"), b"outside")?;
        let root = PrivateDirectory::ensure(&root_path)?;

        symlink(outside.join("secret"), root_path.join("secret-link"))?;
        symlink(&outside, root_path.join("dir-link"))?;

        let target_error = root
            .open_file_read(Path::new("secret-link"))
            .expect_err("symlinked file must fail");
        let parent_error = root
            .create_new_file(Path::new("dir-link/new"))
            .expect_err("symlinked file parent must fail");
        assert!(matches!(
            target_error,
            PrivateDirectoryError::Symlink { .. }
        ));
        assert!(matches!(
            parent_error,
            PrivateDirectoryError::Symlink { .. }
        ));
        assert!(!outside.join("new").exists());
        Ok(())
    }

    #[test]
    fn creates_files_exclusively() -> Result<(), Box<dyn std::error::Error>> {
        let temp = tempdir()?;
        let root = PrivateDirectory::ensure(&temp.path().join("state"))?;
        let _file = root.create_new_file(Path::new("unique"))?;

        let error = root
            .create_new_file(Path::new("unique"))
            .expect_err("exclusive create must reject an existing file");

        assert!(matches!(error, PrivateDirectoryError::AlreadyExists { .. }));
        Ok(())
    }

    #[test]
    fn rejects_insecure_and_hard_linked_files() -> Result<(), Box<dyn std::error::Error>> {
        let temp = tempdir()?;
        let root_path = temp.path().join("state");
        let root = PrivateDirectory::ensure(&root_path)?;

        let insecure = root_path.join("insecure");
        fs::write(&insecure, b"insecure")?;
        fs::set_permissions(&insecure, fs::Permissions::from_mode(0o640))?;
        let insecure_error = root
            .open_file_read(Path::new("insecure"))
            .expect_err("group-readable file must be rejected");
        assert!(matches!(
            insecure_error,
            PrivateDirectoryError::InsecurePermissions {
                object: FilesystemObject::RegularFile,
                mode: 0o640,
                ..
            }
        ));

        let outside = temp.path().join("outside-canary");
        fs::write(&outside, b"unchanged")?;
        fs::set_permissions(&outside, fs::Permissions::from_mode(0o600))?;
        fs::hard_link(&outside, root_path.join("alias"))?;
        let hard_link_error = root
            .open_file_read_write(Path::new("alias"))
            .expect_err("hard-linked file must be rejected");
        assert!(matches!(
            hard_link_error,
            PrivateDirectoryError::UnexpectedLinkCount { .. }
        ));
        assert_eq!(fs::read(&outside)?, b"unchanged");
        Ok(())
    }

    #[test]
    fn rejects_non_regular_file_targets() -> Result<(), Box<dyn std::error::Error>> {
        let temp = tempdir()?;
        let root_path = temp.path().join("state");
        let root = PrivateDirectory::ensure(&root_path)?;
        root.ensure_dir(Path::new("directory"))?;
        fs::write(root_path.join("plain-file"), b"data")?;
        rustix::fs::mkfifoat(&root, "fifo", Mode::RWXU)?;

        let read_error = root
            .open_file_read(Path::new("directory"))
            .expect_err("directory must not open as a file");
        let read_write_error = root
            .open_file_read_write(Path::new("directory"))
            .expect_err("directory must not open as a writable file");
        assert!(matches!(
            read_error,
            PrivateDirectoryError::NotRegularFile { .. }
        ));
        assert!(matches!(
            read_write_error,
            PrivateDirectoryError::NotRegularFile { .. }
        ));

        let fifo_error = root
            .open_file_read(Path::new("fifo"))
            .expect_err("fifo must not open as a regular file");
        assert!(matches!(
            fifo_error,
            PrivateDirectoryError::NotRegularFile { .. }
        ));

        let directory_error = PrivateDirectory::open(&root_path.join("plain-file"))
            .expect_err("regular file must not open as a private directory");
        assert!(matches!(
            directory_error,
            PrivateDirectoryError::InvalidDirectoryComponent { .. }
        ));
        Ok(())
    }

    fn mode(path: &Path) -> Result<u32, std::io::Error> {
        Ok(fs::metadata(path)?.permissions().mode() & 0o777)
    }

    fn assert_invalid_path<T>(result: Result<T, PrivateDirectoryError>, expected: PathViolation) {
        assert!(matches!(
            result,
            Err(PrivateDirectoryError::InvalidPath {
                violation,
                ..
            }) if violation == expected
        ));
    }

    fn assert_directory_symlink_rejected(error: PrivateDirectoryError) {
        assert!(matches!(
            error,
            PrivateDirectoryError::Symlink { .. }
                | PrivateDirectoryError::InvalidDirectoryComponent { .. }
        ));
    }

    fn assert_cloexec(fd: impl AsFd) -> Result<(), std::io::Error> {
        let flags = fcntl_getfd(fd).map_err(std::io::Error::from)?;
        assert!(flags.contains(FdFlags::CLOEXEC));
        Ok(())
    }
}

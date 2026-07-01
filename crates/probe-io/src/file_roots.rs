use std::{
    collections::HashSet,
    error::Error,
    fmt,
    path::{Component, Path, PathBuf},
};

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct AllowedFileRoots {
    roots: Vec<PathBuf>,
}

impl AllowedFileRoots {
    pub fn new(roots: Vec<PathBuf>) -> Result<Self, AllowedFileRootsError> {
        let violations = Self::validate_paths(&roots);
        if violations.is_empty() {
            Ok(Self { roots })
        } else {
            Err(AllowedFileRootsError { violations })
        }
    }

    pub fn validate_paths(roots: &[PathBuf]) -> Vec<AllowedFileRootViolation> {
        let mut seen = HashSet::new();
        let mut violations = Vec::new();
        for (index, root) in roots.iter().enumerate() {
            let kind = if root.as_os_str().is_empty() {
                Some(AllowedFileRootViolationKind::Empty)
            } else if !root.is_absolute() {
                Some(AllowedFileRootViolationKind::Relative)
            } else if root == Path::new("/") {
                Some(AllowedFileRootViolationKind::RootDirectory)
            } else if contains_parent_component(root) {
                Some(AllowedFileRootViolationKind::ParentComponent)
            } else if !seen.insert(root.clone()) {
                Some(AllowedFileRootViolationKind::Duplicate)
            } else {
                None
            };

            if let Some(kind) = kind {
                violations.push(AllowedFileRootViolation {
                    index,
                    path: root.clone(),
                    kind,
                });
            }
        }
        violations
    }

    pub fn is_empty(&self) -> bool {
        self.roots.is_empty()
    }

    pub fn as_slice(&self) -> &[PathBuf] {
        &self.roots
    }

    pub fn contains(&self, path: &Path) -> bool {
        self.root_for(path).is_some()
    }

    pub(crate) fn root_for<'a>(&'a self, path: &'a Path) -> Option<(&'a Path, &'a Path)> {
        self.roots
            .iter()
            .filter_map(|root| {
                path.strip_prefix(root)
                    .ok()
                    .filter(|relative| is_safe_root_relative_path(relative))
                    .map(|relative| (root.as_path(), relative))
            })
            .max_by_key(|(root, _)| root.components().count())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AllowedFileRootsError {
    violations: Vec<AllowedFileRootViolation>,
}

impl AllowedFileRootsError {
    pub fn violations(&self) -> &[AllowedFileRootViolation] {
        &self.violations
    }
}

impl fmt::Display for AllowedFileRootsError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.violations.as_slice() {
            [] => formatter.write_str("invalid allowed file roots"),
            [violation] => write!(formatter, "{violation}"),
            [first, ..] => write!(
                formatter,
                "{first}; {} additional allowed file root violation(s)",
                self.violations.len() - 1
            ),
        }
    }
}

impl Error for AllowedFileRootsError {}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AllowedFileRootViolation {
    pub index: usize,
    pub path: PathBuf,
    pub kind: AllowedFileRootViolationKind,
}

impl fmt::Display for AllowedFileRootViolation {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.kind {
            AllowedFileRootViolationKind::Empty => formatter.write_str("file root cannot be empty"),
            AllowedFileRootViolationKind::Relative => write!(
                formatter,
                "file root {} must be absolute",
                self.path.display()
            ),
            AllowedFileRootViolationKind::RootDirectory => {
                formatter.write_str("file root cannot be /")
            }
            AllowedFileRootViolationKind::ParentComponent => write!(
                formatter,
                "file root {} cannot contain parent directory components",
                self.path.display()
            ),
            AllowedFileRootViolationKind::Duplicate => {
                write!(formatter, "file root {} is duplicated", self.path.display())
            }
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AllowedFileRootViolationKind {
    Empty,
    Relative,
    RootDirectory,
    ParentComponent,
    Duplicate,
}

fn contains_parent_component(path: &Path) -> bool {
    path.components()
        .any(|component| matches!(component, Component::ParentDir))
}

fn is_safe_root_relative_path(path: &Path) -> bool {
    let mut has_component = false;
    for component in path.components() {
        match component {
            Component::Normal(_) => has_component = true,
            Component::CurDir
            | Component::ParentDir
            | Component::RootDir
            | Component::Prefix(_) => return false,
        }
    }
    has_component
}

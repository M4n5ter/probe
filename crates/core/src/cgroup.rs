use std::fmt;

use thiserror::Error;

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct CgroupPath(String);

#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum CgroupPathError {
    #[error("path must not be empty")]
    Empty,
    #[error("root cgroup path is too broad")]
    Root,
    #[error("path must not contain empty components")]
    EmptyComponent,
    #[error("path must not contain . or .. components")]
    DotComponent,
    #[error("path must not contain control characters")]
    ControlCharacter,
}

impl CgroupPath {
    pub fn parse(path: impl AsRef<str>) -> Result<Self, CgroupPathError> {
        let path = path.as_ref().trim();
        if path.is_empty() {
            return Err(CgroupPathError::Empty);
        }

        let path = path.trim_matches('/');
        if path.is_empty() {
            return Err(CgroupPathError::Root);
        }

        let mut normalized = Vec::new();
        for component in path.split('/') {
            if component.is_empty() {
                return Err(CgroupPathError::EmptyComponent);
            }
            if component == "." || component == ".." {
                return Err(CgroupPathError::DotComponent);
            }
            if component.chars().any(char::is_control) {
                return Err(CgroupPathError::ControlCharacter);
            }
            normalized.push(component);
        }

        Ok(Self(normalized.join("/")))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn into_string(self) -> String {
        self.0
    }

    pub fn contains(&self, other: &Self) -> bool {
        other.0 == self.0
            || other
                .0
                .as_bytes()
                .get(self.0.len())
                .is_some_and(|separator| *separator == b'/' && other.0.starts_with(self.0.as_str()))
    }

    pub fn narrowest_overlap(&self, other: &Self) -> Option<Self> {
        if self.contains(other) {
            Some(other.clone())
        } else if other.contains(self) {
            Some(self.clone())
        } else {
            None
        }
    }

    pub fn collapse_covered(paths: Vec<Self>) -> Vec<Self> {
        let mut unique = Vec::new();
        for path in paths {
            if !unique.contains(&path) {
                unique.push(path);
            }
        }

        unique
            .iter()
            .enumerate()
            .filter_map(|(candidate_index, candidate)| {
                let covered = unique.iter().enumerate().any(|(cover_index, cover)| {
                    cover_index != candidate_index
                        && cover.contains(candidate)
                        && (!candidate.contains(cover) || cover_index < candidate_index)
                });
                (!covered).then(|| candidate.clone())
            })
            .collect()
    }
}

impl fmt::Display for CgroupPath {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl AsRef<str> for CgroupPath {
    fn as_ref(&self) -> &str {
        self.as_str()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cgroup_path_normalizes_leading_and_trailing_slashes() {
        let path = CgroupPath::parse("/system.slice/demo.service/")
            .expect("test cgroup path should be valid");

        assert_eq!(path.as_str(), "system.slice/demo.service");
    }

    #[test]
    fn cgroup_path_rejects_root_path() {
        assert_eq!(CgroupPath::parse("/"), Err(CgroupPathError::Root));
    }

    #[test]
    fn cgroup_path_contains_descendants() {
        let parent = CgroupPath::parse("system.slice/demo.service")
            .expect("test cgroup path should be valid");
        let child = CgroupPath::parse("/system.slice/demo.service/workers")
            .expect("test cgroup path should be valid");
        let sibling = CgroupPath::parse("system.slice/other.service")
            .expect("test cgroup path should be valid");

        assert!(parent.contains(&child));
        assert!(parent.contains(&parent));
        assert!(!parent.contains(&sibling));
    }

    #[test]
    fn cgroup_path_collapse_removes_paths_covered_by_parent() {
        let paths = CgroupPath::collapse_covered(vec![
            CgroupPath::parse("system.slice/demo.service/workers")
                .expect("test cgroup path should be valid"),
            CgroupPath::parse("system.slice/demo.service")
                .expect("test cgroup path should be valid"),
        ]);

        assert_eq!(
            paths,
            vec![
                CgroupPath::parse("system.slice/demo.service")
                    .expect("test cgroup path should be valid")
            ]
        );
    }
}

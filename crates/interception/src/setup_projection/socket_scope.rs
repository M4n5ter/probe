use probe_core::CgroupPath;

use super::model::TransparentInterceptionSetupProjectionError;

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct TransparentInterceptionSocketOwnerScope {
    uids: Vec<u32>,
    gids: Vec<u32>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct TransparentInterceptionSocketCgroupScope {
    paths: Vec<CgroupPath>,
}

impl TransparentInterceptionSocketOwnerScope {
    pub fn any() -> Self {
        Self::default()
    }

    pub fn new(uids: Vec<u32>, gids: Vec<u32>) -> Self {
        Self { uids, gids }
    }

    pub fn is_any(&self) -> bool {
        self.uids.is_empty() && self.gids.is_empty()
    }

    pub fn uids(&self) -> &[u32] {
        &self.uids
    }

    pub fn gids(&self) -> &[u32] {
        &self.gids
    }

    pub(crate) fn equivalent_to(&self, other: &Self) -> bool {
        same_values(&self.uids, &other.uids) && same_values(&self.gids, &other.gids)
    }

    pub(crate) fn contains_scope(&self, other: &Self) -> bool {
        owner_values_contain(&self.uids, &other.uids)
            && owner_values_contain(&self.gids, &other.gids)
    }
}

impl TransparentInterceptionSocketCgroupScope {
    pub fn any() -> Self {
        Self::default()
    }

    pub fn new(paths: Vec<String>) -> Result<Self, TransparentInterceptionSetupProjectionError> {
        let paths = paths
            .into_iter()
            .map(|path| {
                CgroupPath::parse(&path).map_err(|reason| {
                    TransparentInterceptionSetupProjectionError::Unsupported {
                        reason: format!("invalid cgroup path {path:?}: {reason}"),
                    }
                })
            })
            .collect::<Result<Vec<_>, _>>()?;
        Ok(Self {
            paths: CgroupPath::collapse_covered(paths),
        })
    }

    pub fn is_any(&self) -> bool {
        self.paths.is_empty()
    }

    pub fn paths(&self) -> impl ExactSizeIterator<Item = &str> + '_ {
        self.paths.iter().map(CgroupPath::as_str)
    }

    pub(crate) fn path_values(&self) -> &[CgroupPath] {
        &self.paths
    }

    pub(crate) fn equivalent_to(&self, other: &Self) -> bool {
        self.contains_scope(other) && other.contains_scope(self)
    }

    pub(crate) fn contains_scope(&self, other: &Self) -> bool {
        self.paths.is_empty()
            || (!other.paths.is_empty()
                && other
                    .paths
                    .iter()
                    .all(|path| self.paths.iter().any(|prefix| prefix.contains(path))))
    }
}

fn same_values<T>(left: &[T], right: &[T]) -> bool
where
    T: Eq,
{
    left.len() == right.len() && left.iter().all(|value| right.contains(value))
}

fn owner_values_contain(left: &[u32], right: &[u32]) -> bool {
    left.is_empty() || (!right.is_empty() && right.iter().all(|value| left.contains(value)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn socket_cgroup_scope_removes_paths_covered_by_parent() {
        let scope = TransparentInterceptionSocketCgroupScope::new(vec![
            "system.slice/demo.service/workers".to_string(),
            "system.slice/demo.service".to_string(),
        ])
        .expect("test cgroup paths should be valid");

        assert_eq!(
            scope.paths().collect::<Vec<_>>(),
            vec!["system.slice/demo.service"]
        );
    }
}

use std::collections::BTreeSet;

use crate::tls::LibsslUprobeAttachTargetId;

use super::{
    error::LibsslUprobeAttachError,
    recipe::{LibsslUprobeAttachRecipeRequest, is_plaintext},
};

pub(in crate::tls::plaintext) struct LibsslUprobeAttachSummary {
    has_plaintext_recipe: bool,
    committed_targets: BTreeSet<LibsslUprobeAttachTargetId>,
    first_failure_reason: Option<String>,
    failure_count: usize,
}

impl LibsslUprobeAttachSummary {
    pub(in crate::tls::plaintext) fn from_recipes(
        recipes: &[LibsslUprobeAttachRecipeRequest],
    ) -> Self {
        Self {
            has_plaintext_recipe: recipes.iter().any(is_plaintext),
            committed_targets: BTreeSet::new(),
            first_failure_reason: None,
            failure_count: 0,
        }
    }

    pub(super) fn record_committed_target(&mut self, target: LibsslUprobeAttachTargetId) {
        self.committed_targets.insert(target);
    }

    pub(super) fn record_failure(&mut self, error: &LibsslUprobeAttachError) {
        self.failure_count = self.failure_count.saturating_add(1);
        self.first_failure_reason
            .get_or_insert_with(|| error.to_string());
    }

    pub(in crate::tls::plaintext) fn has_committed_targets(&self) -> bool {
        !self.committed_targets.is_empty()
    }

    pub(in crate::tls::plaintext) fn committed_targets(
        &self,
    ) -> impl Iterator<Item = LibsslUprobeAttachTargetId> + '_ {
        self.committed_targets.iter().cloned()
    }

    pub(in crate::tls::plaintext) fn unresolvable_plaintext_reason(&self) -> String {
        if self.has_plaintext_recipe {
            let mut reason =
                "libssl uprobe best-effort attach did not commit any ready target".to_string();
            if let Some(first_failure_reason) = &self.first_failure_reason {
                reason.push_str("; first attach failure: ");
                reason.push_str(first_failure_reason);
                if self.failure_count > 1 {
                    reason.push_str(&format!(
                        "; additional attach failures: {}",
                        self.failure_count - 1
                    ));
                }
            }
            reason
        } else {
            "libssl uprobe attach plan did not contain a plaintext recipe".to_string()
        }
    }
}

#[cfg(test)]
mod tests {
    use std::path::{Path, PathBuf};

    use probe_core::ProcessGeneration;

    use crate::{
        LibsslLibraryKind, LibsslMappedFileIdentity, LibsslMappedLibrary,
        LibsslUprobeProcessGenerationFailure, LibsslUprobeSymbol, LibsslUprobeTarget,
        LibsslUprobeTargetDiscoveryReport, tls::LibsslUprobeProcessVerifier,
    };

    use super::*;
    use crate::tls::LibsslUprobeAttachPlan;

    use super::super::recipe::attach_recipes_from_plan;

    #[test]
    fn attach_summary_reports_session_committed_target() -> Result<(), Box<dyn std::error::Error>> {
        let plan = LibsslUprobeAttachPlan::from_discovery_report(discovery_report(
            42,
            vec![target(
                "/usr/lib/libssl.so.3",
                vec![LibsslUprobeSymbol::SslSetFd, LibsslUprobeSymbol::SslRead],
            )],
        ));
        let recipes = attach_recipes_from_plan(&plan)?;
        let committed_target = recipes[0].target_id();
        let mut summary = LibsslUprobeAttachSummary::from_recipes(&recipes);

        assert!(!summary.has_committed_targets());

        summary.record_committed_target(committed_target);
        assert!(summary.has_committed_targets());
        Ok(())
    }

    #[test]
    fn attach_summary_reports_uncommitted_plaintext_plan() -> Result<(), Box<dyn std::error::Error>>
    {
        let plan = LibsslUprobeAttachPlan::from_discovery_report(discovery_report(
            42,
            vec![target(
                "/usr/lib/libssl.so.3",
                vec![LibsslUprobeSymbol::SslRead],
            )],
        ));
        let recipes = attach_recipes_from_plan(&plan)?;
        let summary = LibsslUprobeAttachSummary::from_recipes(&recipes);

        assert!(!summary.has_committed_targets());
        assert!(
            summary
                .unresolvable_plaintext_reason()
                .contains("did not commit any ready target")
        );
        Ok(())
    }

    #[test]
    fn attach_summary_reports_plan_without_plaintext_recipe()
    -> Result<(), Box<dyn std::error::Error>> {
        let plan = LibsslUprobeAttachPlan::from_discovery_report(discovery_report(
            42,
            vec![target(
                "/usr/lib/libssl.so.3",
                vec![LibsslUprobeSymbol::SslSetFd],
            )],
        ));
        let recipes = attach_recipes_from_plan(&plan)?;
        let summary = LibsslUprobeAttachSummary::from_recipes(&recipes);

        assert_eq!(
            summary.unresolvable_plaintext_reason(),
            "libssl uprobe attach plan did not contain a plaintext recipe"
        );
        Ok(())
    }

    #[test]
    fn attach_summary_disabled_reason_preserves_first_attach_failure()
    -> Result<(), Box<dyn std::error::Error>> {
        let plan = LibsslUprobeAttachPlan::from_discovery_report(discovery_report(
            42,
            vec![target(
                "/usr/lib/libssl.so.3",
                vec![LibsslUprobeSymbol::SslRead],
            )],
        ));
        let recipes = attach_recipes_from_plan(&plan)?;
        let mut summary = LibsslUprobeAttachSummary::from_recipes(&recipes);

        summary.record_failure(&LibsslUprobeAttachError::AttachProcess {
            pid: 42,
            source: Box::new(LibsslUprobeProcessGenerationFailure::Changed {
                path: PathBuf::from("/proc/42/stat"),
                expected_start_time_ticks: 7,
                actual_start_time_ticks: 8,
            }),
        });

        let reason = summary.unresolvable_plaintext_reason();
        assert!(reason.contains("did not commit any ready target"));
        assert!(reason.contains("first attach failure"));
        assert!(reason.contains("process stat /proc/42/stat no longer matches expected starttime"));
        Ok(())
    }

    fn mapped_library(path: &str) -> LibsslMappedLibrary {
        let mapped_path = PathBuf::from(path);
        LibsslMappedLibrary {
            read_path: Path::new("/proc/42/root").join(path.trim_start_matches('/')),
            mapped_path,
            identity: LibsslMappedFileIdentity {
                device_major: 8,
                device_minor: 1,
                inode: 100,
            },
            deleted: false,
        }
    }

    fn target(path: &str, symbols: Vec<LibsslUprobeSymbol>) -> LibsslUprobeTarget {
        LibsslUprobeTarget {
            library: mapped_library(path),
            library_kind: LibsslLibraryKind::OpenSslLike,
            executable_mappings: Vec::new(),
            symbols,
        }
    }

    fn discovery_report(
        pid: u32,
        targets: Vec<LibsslUprobeTarget>,
    ) -> LibsslUprobeTargetDiscoveryReport {
        LibsslUprobeTargetDiscoveryReport::new(
            process_generation(pid),
            process_verifier(),
            targets,
            Vec::new(),
        )
    }

    fn process_generation(pid: u32) -> ProcessGeneration {
        ProcessGeneration {
            pid,
            start_time_ticks: u64::from(pid) * 100,
        }
    }

    fn process_verifier() -> LibsslUprobeProcessVerifier {
        LibsslUprobeProcessVerifier::new("/proc")
    }
}

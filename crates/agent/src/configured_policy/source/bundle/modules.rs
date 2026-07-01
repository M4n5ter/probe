use std::{
    collections::{BTreeMap, BTreeSet},
    fmt,
    path::PathBuf,
};

const BUNDLE_MODULES_DIR: &str = "modules";
const MAX_POLICY_MODULES: usize = 64;

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub(in crate::configured_policy::source) struct ModuleName(String);

#[derive(Debug)]
pub(in crate::configured_policy::source) struct DeclaredModules {
    names: Vec<ModuleName>,
}

#[derive(Debug)]
pub(in crate::configured_policy::source) struct RemotePolicyModuleSource {
    pub(in crate::configured_policy::source) name: String,
    pub(in crate::configured_policy::source) source: String,
}

#[derive(Debug)]
pub(in crate::configured_policy::source) enum RemotePolicyModuleError {
    NotDeclared {
        module: String,
    },
    Duplicate {
        module: String,
    },
    Missing {
        module: String,
    },
    TooLarge {
        module: String,
        size: u64,
        limit: u64,
    },
}

impl DeclaredModules {
    pub(in crate::configured_policy::source) fn new(names: Vec<String>) -> Result<Self, String> {
        if names.len() > MAX_POLICY_MODULES {
            return Err(format!(
                "policy bundle declares {} modules, exceeding the {MAX_POLICY_MODULES} module limit",
                names.len()
            ));
        }

        let mut seen = BTreeSet::new();
        let mut modules = Vec::with_capacity(names.len());
        for name in names {
            let module = ModuleName::parse(name)?;
            if !seen.insert(module.clone()) {
                return Err(format!(
                    "policy module {} is declared more than once",
                    module.as_str()
                ));
            }
            modules.push(module);
        }

        Ok(Self { names: modules })
    }

    pub(in crate::configured_policy::source) fn iter(&self) -> impl Iterator<Item = &ModuleName> {
        self.names.iter()
    }

    pub(in crate::configured_policy::source) fn len(&self) -> usize {
        self.names.len()
    }

    pub(in crate::configured_policy::source) fn resolve_remote_sources(
        &self,
        modules: impl IntoIterator<Item = RemotePolicyModuleSource>,
        source_limit: u64,
    ) -> Result<Vec<policy::PolicyModule>, RemotePolicyModuleError> {
        let mut declared = self
            .names
            .iter()
            .map(|name| (name.as_str(), false))
            .collect::<BTreeMap<_, _>>();
        let mut loaded = Vec::new();

        for module in modules {
            let Some(seen) = declared.get_mut(module.name.as_str()) else {
                return Err(RemotePolicyModuleError::NotDeclared {
                    module: module.name,
                });
            };
            if *seen {
                return Err(RemotePolicyModuleError::Duplicate {
                    module: module.name,
                });
            }
            validate_source_size(&module.name, &module.source, source_limit)?;
            *seen = true;
            loaded.push(policy::PolicyModule {
                name: module.name,
                source: module.source,
            });
        }

        if let Some((module, _)) = declared.into_iter().find(|(_, seen)| !*seen) {
            return Err(RemotePolicyModuleError::Missing {
                module: module.to_string(),
            });
        }
        Ok(loaded)
    }
}

impl ModuleName {
    fn parse(name: String) -> Result<Self, String> {
        if !is_valid_module_name(&name) {
            return Err(format!(
                "policy module name {name:?} is not a dotted Lua identifier"
            ));
        }
        Ok(Self(name))
    }

    pub(in crate::configured_policy::source) fn as_str(&self) -> &str {
        &self.0
    }

    pub(in crate::configured_policy::source) fn relative_path(&self) -> PathBuf {
        let mut path = PathBuf::from(BUNDLE_MODULES_DIR);
        for segment in self.0.split('.') {
            path.push(segment);
        }
        path.set_extension("lua");
        path
    }
}

impl fmt::Display for ModuleName {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

fn validate_source_size(
    module: &str,
    source: &str,
    limit: u64,
) -> Result<(), RemotePolicyModuleError> {
    let size = source.len() as u64;
    if size > limit {
        return Err(RemotePolicyModuleError::TooLarge {
            module: module.to_string(),
            size,
            limit,
        });
    }
    Ok(())
}

fn is_valid_module_name(module: &str) -> bool {
    !module.is_empty()
        && module
            .split('.')
            .all(|segment| !segment.is_empty() && is_lua_identifier(segment))
}

fn is_lua_identifier(segment: &str) -> bool {
    let mut chars = segment.chars();
    chars
        .next()
        .is_some_and(|ch| ch == '_' || ch.is_ascii_alphabetic())
        && chars.all(|ch| ch == '_' || ch.is_ascii_alphanumeric())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn module_name_maps_to_bundle_local_path() {
        let modules = DeclaredModules::new(vec!["guard.matcher".to_string()])
            .expect("valid module name must parse");
        let paths = modules
            .iter()
            .map(ModuleName::relative_path)
            .collect::<Vec<_>>();

        assert_eq!(paths, vec![PathBuf::from("modules/guard/matcher.lua")]);
    }

    #[test]
    fn module_name_rejects_non_identifier_segment() {
        let error = DeclaredModules::new(vec!["guard.1matcher".to_string()])
            .expect_err("invalid Lua module names must be rejected");

        assert!(error.contains("dotted Lua identifier"));
    }

    #[test]
    fn remote_modules_must_exactly_match_manifest() {
        let modules = DeclaredModules::new(vec!["guard.matcher".to_string()])
            .expect("valid module name must parse");

        let loaded = modules
            .resolve_remote_sources(
                [RemotePolicyModuleSource {
                    name: "guard.matcher".to_string(),
                    source: "return {}".to_string(),
                }],
                64,
            )
            .expect("declared remote module must load");

        assert_eq!(loaded[0].name, "guard.matcher");
    }
}

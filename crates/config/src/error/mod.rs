use thiserror::Error;

#[derive(Debug, Error)]
pub enum ConfigError {
    #[error("failed to parse TOML config: {0}")]
    Toml(#[from] toml::de::Error),
    #[error("invalid config: {0}")]
    Validation(#[from] ConfigValidationError),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConfigValidationError {
    violations: Vec<ConfigViolation>,
}

impl ConfigValidationError {
    pub fn new(violations: Vec<ConfigViolation>) -> Self {
        Self { violations }
    }

    pub fn violations(&self) -> &[ConfigViolation] {
        &self.violations
    }
}

impl std::fmt::Display for ConfigValidationError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        for (index, violation) in self.violations.iter().enumerate() {
            if index > 0 {
                formatter.write_str("; ")?;
            }
            write!(formatter, "{}: {}", violation.field, violation.reason)?;
        }
        Ok(())
    }
}

impl std::error::Error for ConfigValidationError {}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConfigViolation {
    pub field: String,
    pub reason: String,
}

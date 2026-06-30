use std::{fmt, str::FromStr};

use serde::{Deserialize, Deserializer, Serialize, de};
use thiserror::Error;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ApplicationProtocol {
    #[serde(rename = "http1")]
    Http1,
}

impl ApplicationProtocol {
    pub fn config_name(self) -> &'static str {
        match self {
            Self::Http1 => "http1",
        }
    }

    pub fn alpn_name(self) -> &'static str {
        match self {
            Self::Http1 => "http/1.1",
        }
    }

    pub fn from_wire_name(value: &str) -> Result<Self, ApplicationProtocolParseError> {
        match value {
            "http1" | "http/1.1" => Ok(Self::Http1),
            _ => Err(ApplicationProtocolParseError {
                value: value.to_string(),
            }),
        }
    }
}

impl FromStr for ApplicationProtocol {
    type Err = ApplicationProtocolParseError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Self::from_wire_name(value)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Error)]
#[error("unsupported application protocol {value:?}; supported protocols: http1, http/1.1")]
pub struct ApplicationProtocolParseError {
    value: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(transparent)]
pub struct ApplicationProtocolPolicy {
    protocols: Vec<ApplicationProtocol>,
}

impl ApplicationProtocolPolicy {
    pub fn new(
        protocols: impl IntoIterator<Item = ApplicationProtocol>,
    ) -> Result<Self, ApplicationProtocolPolicyError> {
        let protocols = protocols
            .into_iter()
            .fold(Vec::new(), |mut policy, protocol| {
                if !policy.contains(&protocol) {
                    policy.push(protocol);
                }
                policy
            });
        if protocols.is_empty() {
            return Err(ApplicationProtocolPolicyError::Empty);
        }
        Ok(Self { protocols })
    }

    pub fn protocols(&self) -> &[ApplicationProtocol] {
        &self.protocols
    }
}

impl Default for ApplicationProtocolPolicy {
    fn default() -> Self {
        Self {
            protocols: vec![ApplicationProtocol::Http1],
        }
    }
}

impl<'de> Deserialize<'de> for ApplicationProtocolPolicy {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let protocols = Vec::<ApplicationProtocol>::deserialize(deserializer)?;
        Self::new(protocols).map_err(de::Error::custom)
    }
}

impl TryFrom<Vec<ApplicationProtocol>> for ApplicationProtocolPolicy {
    type Error = ApplicationProtocolPolicyError;

    fn try_from(protocols: Vec<ApplicationProtocol>) -> Result<Self, Self::Error> {
        Self::new(protocols)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum ApplicationProtocolPolicyError {
    #[error("application protocol policy must include at least one protocol")]
    Empty,
}

impl fmt::Display for ApplicationProtocol {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.config_name())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn policy_deduplicates_without_reordering() {
        let policy = ApplicationProtocolPolicy::new([
            ApplicationProtocol::Http1,
            ApplicationProtocol::Http1,
        ])
        .expect("duplicates should normalize into a non-empty policy");

        assert_eq!(policy.protocols(), [ApplicationProtocol::Http1]);
    }

    #[test]
    fn policy_rejects_empty_protocols() {
        let error = ApplicationProtocolPolicy::new([]).expect_err("empty policy must fail closed");

        assert_eq!(error, ApplicationProtocolPolicyError::Empty);
    }

    #[test]
    fn protocol_parser_accepts_config_and_alpn_names() {
        assert_eq!(
            "http1".parse::<ApplicationProtocol>(),
            Ok(ApplicationProtocol::Http1)
        );
        assert_eq!(
            "http/1.1".parse::<ApplicationProtocol>(),
            Ok(ApplicationProtocol::Http1)
        );
    }
}

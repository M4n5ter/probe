use std::net::IpAddr;

use serde::Deserialize;

use super::command::IpCommand;
use crate::transparent_interception::TransparentInterceptionError;

pub(super) fn load(ip: &mut dyn IpCommand) -> Result<Vec<IpAddr>, TransparentInterceptionError> {
    let args = ["-j", "address", "show"].map(String::from);
    let result = ip
        .run(&args)
        .map_err(|error| TransparentInterceptionError::Nftables(error.to_string()))?;
    if !result.success {
        return Err(TransparentInterceptionError::Nftables(
            result.failure_reason("ip address show"),
        ));
    }
    parse(&result.stdout)
}

fn parse(bytes: &[u8]) -> Result<Vec<IpAddr>, TransparentInterceptionError> {
    let links = serde_json::from_slice::<Vec<IpAddressLink>>(bytes).map_err(|error| {
        TransparentInterceptionError::Nftables(format!("failed to parse ip address JSON: {error}"))
    })?;
    Ok(links
        .into_iter()
        .flat_map(|link| link.addr_info)
        .filter_map(|address| address.local)
        .collect())
}

#[derive(Debug, Deserialize)]
struct IpAddressLink {
    #[serde(default)]
    addr_info: Vec<IpAddressInfo>,
}

#[derive(Debug, Deserialize)]
struct IpAddressInfo {
    local: Option<IpAddr>,
}

#[cfg(test)]
mod tests {
    use std::{collections::VecDeque, io, net::Ipv4Addr};

    use super::super::command::CommandResult;
    use super::*;

    #[test]
    fn parses_local_interface_addresses() -> Result<(), Box<dyn std::error::Error>> {
        let addresses = parse(
            br#"[
                {
                    "ifname": "lo",
                    "addr_info": [
                        {"family": "inet", "local": "127.0.0.1"},
                        {"family": "inet6", "local": "::1"}
                    ]
                },
                {
                    "ifname": "eth0",
                    "addr_info": [
                        {"family": "inet", "local": "192.0.2.10"},
                        {"family": "inet6", "local": "2001:db8::10"}
                    ]
                }
            ]"#,
        )?;

        assert_eq!(
            addresses,
            vec![
                IpAddr::V4(Ipv4Addr::LOCALHOST),
                "::1".parse()?,
                IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10)),
                "2001:db8::10".parse()?,
            ]
        );
        Ok(())
    }

    #[test]
    fn load_uses_ip_json_address_show() -> Result<(), Box<dyn std::error::Error>> {
        let mut ip = FakeIp::with_results([Ok(CommandResult {
            success: true,
            stdout: br#"[{"addr_info":[{"local":"192.0.2.10"}]}]"#.to_vec(),
            stderr: Vec::new(),
        })]);

        let addresses = load(&mut ip)?;

        assert_eq!(addresses, vec![IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10))]);
        assert_eq!(
            ip.calls(),
            vec![vec![
                "-j".to_string(),
                "address".to_string(),
                "show".to_string()
            ]]
        );
        Ok(())
    }

    #[test]
    fn load_reports_ip_failure() {
        let mut ip = FakeIp::with_results([Ok(CommandResult {
            success: false,
            stdout: Vec::new(),
            stderr: b"permission denied\n".to_vec(),
        })]);

        let error = load(&mut ip).expect_err("ip command failure should fail address inventory");

        assert!(error.to_string().contains("permission denied"));
    }

    #[derive(Clone, Default)]
    struct FakeIp {
        inner: std::sync::Arc<std::sync::Mutex<FakeIpInner>>,
    }

    #[derive(Default)]
    struct FakeIpInner {
        calls: Vec<Vec<String>>,
        results: VecDeque<io::Result<CommandResult>>,
    }

    impl FakeIp {
        fn with_results(results: impl IntoIterator<Item = io::Result<CommandResult>>) -> Self {
            Self {
                inner: std::sync::Arc::new(std::sync::Mutex::new(FakeIpInner {
                    calls: Vec::new(),
                    results: results.into_iter().collect(),
                })),
            }
        }

        fn calls(&self) -> Vec<Vec<String>> {
            self.inner
                .lock()
                .expect("fake ip mutex poisoned")
                .calls
                .clone()
        }
    }

    impl IpCommand for FakeIp {
        fn run(&mut self, args: &[String]) -> io::Result<CommandResult> {
            let mut inner = self.inner.lock().expect("fake ip mutex poisoned");
            inner.calls.push(args.to_vec());
            inner
                .results
                .pop_front()
                .expect("fake ip result should be configured")
        }
    }
}

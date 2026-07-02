use std::{
    collections::BTreeMap,
    path::{Path, PathBuf},
    str::FromStr,
};

use probe_config::{
    AgentConfig, EnforcementPolicyConfig, EnforcementPolicyReloadConfig,
    EnforcementPolicySourceConfig, ExporterConfig, ExporterTlsConfig, ExporterTransportConfig,
    TlsMaterialConfig, TransparentInterceptionProxyConfig,
};
use probe_core::{Direction, Selector, SelectorTerm};
use serde::Serialize;
use toml_edit::{Array, ArrayOfTables, DocumentMut, Item, Table, value};

use super::{
    config_edit::TuiError,
    wire::{
        capture_selection_name, compression_codec_name, connection_backend_name,
        enforcement_mode_name, exporter_transport_name, interception_strategy_name,
    },
};

pub(super) fn render_preserving_config(
    original_source: &str,
    config: &AgentConfig,
    path: &Path,
) -> Result<String, TuiError> {
    let mut document =
        DocumentMut::from_str(original_source).map_err(|source| TuiError::ParseTomlDocument {
            path: path.display().to_string(),
            source,
        })?;
    set_root_value(&mut document, "agent_id", value(&config.agent_id));
    set_root_value(
        &mut document,
        "config_version",
        value(&config.config_version),
    );
    set_value(
        &mut document,
        &["capture"],
        "selection",
        value(capture_selection_name(config.capture.selection)),
    );
    set_optional_selector(
        &mut document,
        &["capture"],
        "deep_observe_selector",
        config.capture.deep_observe_selector.as_ref(),
    )?;
    set_value(
        &mut document,
        &["export", "worker"],
        "enabled",
        value(config.export.worker.enabled),
    );
    sync_exporters(&mut document, &config.exporters)?;
    set_optional_u64(
        &mut document,
        &["storage", "retention", "ingress"],
        "max_records",
        config.storage.retention.ingress.max_records,
    )?;
    set_optional_u64(
        &mut document,
        &["storage", "retention", "export"],
        "max_records",
        config.storage.retention.export.max_records,
    )?;
    set_value(
        &mut document,
        &["enforcement"],
        "mode",
        value(enforcement_mode_name(config.enforcement.mode)),
    );
    set_value(
        &mut document,
        &["enforcement"],
        "backend",
        value(connection_backend_name(config.enforcement.backend)),
    );
    set_optional_selector(
        &mut document,
        &["enforcement"],
        "selector",
        config.enforcement.selector.as_ref(),
    )?;
    sync_enforcement_policy(&mut document, config)?;
    set_value(
        &mut document,
        &["enforcement", "interception"],
        "strategy",
        value(interception_strategy_name(
            config.enforcement.interception.strategy,
        )),
    );
    set_optional_selector(
        &mut document,
        &["enforcement", "interception"],
        "selector",
        config.enforcement.interception.selector.as_ref(),
    )?;
    sync_interception_proxy(
        &mut document,
        &config.enforcement.interception.proxy,
        config.enforcement.interception.strategy.is_enabled(),
    )?;
    sync_mitm_contract(&mut document, config)?;
    set_value(
        &mut document,
        &["tls", "plaintext", "instrumentation"],
        "enabled",
        value(config.tls.plaintext.instrumentation.enabled),
    );
    set_optional_path(
        &mut document,
        &["tls", "plaintext", "instrumentation"],
        "libssl_uprobe_object_path",
        config
            .tls
            .plaintext
            .instrumentation
            .libssl_uprobe_object_path
            .as_deref(),
    );
    set_optional_selector(
        &mut document,
        &["tls", "plaintext", "instrumentation"],
        "selector",
        config.tls.plaintext.instrumentation.selector.as_ref(),
    )?;
    sync_tls_material_store(&mut document, config)?;
    sync_tls_materials(&mut document, &config.tls.materials)?;
    set_value(
        &mut document,
        &["admin"],
        "enabled",
        value(config.admin.enabled),
    );
    set_value(
        &mut document,
        &["admin"],
        "socket_path",
        value(config.admin.socket_path.display().to_string()),
    );
    set_value(
        &mut document,
        &["admin", "prometheus"],
        "enabled",
        value(config.admin.prometheus.enabled),
    );
    set_value(
        &mut document,
        &["admin", "prometheus"],
        "listen_addr",
        value(config.admin.prometheus.listen_addr.to_string()),
    );
    Ok(document.to_string())
}

fn sync_exporters(
    document: &mut DocumentMut,
    exporters: &[ExporterConfig],
) -> Result<(), TuiError> {
    if exporters.is_empty() {
        return Ok(());
    };
    let Some(array) = exporters_array_mut(document) else {
        return Ok(());
    };
    for (index, exporter) in exporters.iter().enumerate() {
        if index >= array.len() {
            array.push(Table::new());
        }
        let Some(table) = array.get_mut(index) else {
            continue;
        };
        sync_exporter_table(table, exporter)?;
    }
    Ok(())
}

fn exporters_array_mut(document: &mut DocumentMut) -> Option<&mut ArrayOfTables> {
    let root = document.as_table_mut();
    if !root.contains_key("exporters") {
        root.insert("exporters", Item::ArrayOfTables(ArrayOfTables::new()));
    }
    root.get_mut("exporters")?.as_array_of_tables_mut()
}

fn sync_exporter_table(table: &mut Table, exporter: &ExporterConfig) -> Result<(), TuiError> {
    set_table_item(table, "id", value(&exporter.id));
    set_table_item(
        table,
        "transport",
        value(exporter_transport_name(&exporter.transport)),
    );
    set_table_item(
        table,
        "codec",
        value(compression_codec_name(exporter.codec)),
    );
    match &exporter.transport {
        ExporterTransportConfig::Webhook {
            endpoint,
            headers,
            tls,
        } => {
            set_table_item(table, "endpoint", value(endpoint));
            sync_exporter_headers(table, headers)?;
            sync_exporter_tls(table, tls)?;
            table.remove("path");
            table.remove("socket_path");
        }
        ExporterTransportConfig::File { path } => {
            set_table_item(table, "path", value(path.display().to_string()));
            table.remove("endpoint");
            table.remove("headers");
            table.remove("tls");
            table.remove("socket_path");
        }
        ExporterTransportConfig::UnixHttp {
            socket_path,
            endpoint,
            headers,
        } => {
            set_table_item(
                table,
                "socket_path",
                value(socket_path.display().to_string()),
            );
            set_table_item(table, "endpoint", value(endpoint));
            sync_exporter_headers(table, headers)?;
            table.remove("path");
            table.remove("tls");
        }
    }
    Ok(())
}

fn sync_exporter_headers(
    table: &mut Table,
    headers: &BTreeMap<String, String>,
) -> Result<(), TuiError> {
    if headers.is_empty() {
        table.remove("headers");
    } else {
        set_table_item(table, "headers", serialized_table_item(headers)?);
    }
    Ok(())
}

fn sync_exporter_tls(table: &mut Table, tls: &ExporterTlsConfig) -> Result<(), TuiError> {
    if tls == &ExporterTlsConfig::default() {
        table.remove("tls");
    } else {
        set_table_item(table, "tls", serialized_table_item(tls)?);
    }
    Ok(())
}

fn sync_interception_proxy(
    document: &mut DocumentMut,
    proxy: &TransparentInterceptionProxyConfig,
    strategy_enabled: bool,
) -> Result<(), TuiError> {
    let table = table_at_path(document, &["enforcement", "interception"]);
    if !strategy_enabled && proxy == &TransparentInterceptionProxyConfig::default() {
        table.remove("proxy");
        return Ok(());
    }
    set_table_item(table, "proxy", serialized_table_item(proxy)?);
    Ok(())
}

fn sync_mitm_contract(document: &mut DocumentMut, config: &AgentConfig) -> Result<(), TuiError> {
    let table = table_at_path(document, &["enforcement", "interception"]);
    if !config.enforcement.interception.mitm.is_configured() {
        table.remove("mitm");
        return Ok(());
    }
    set_table_item(
        table,
        "mitm",
        serialized_table_item(&config.enforcement.interception.mitm)?,
    );
    Ok(())
}

fn sync_enforcement_policy(
    document: &mut DocumentMut,
    config: &AgentConfig,
) -> Result<(), TuiError> {
    if config.enforcement.policy == EnforcementPolicyConfig::default() {
        let table = table_at_path(document, &["enforcement"]);
        table.remove("policy");
        return Ok(());
    }
    sync_enforcement_policy_source(document, &config.enforcement.policy.source)?;
    sync_enforcement_policy_reload(document, &config.enforcement.policy.reload)?;
    Ok(())
}

fn sync_enforcement_policy_source(
    document: &mut DocumentMut,
    source: &EnforcementPolicySourceConfig,
) -> Result<(), TuiError> {
    let policy_table = table_at_path(document, &["enforcement", "policy"]);
    if matches!(source, EnforcementPolicySourceConfig::None) {
        policy_table.remove("source");
        return Ok(());
    }
    set_table_item(policy_table, "source", serialized_table_item(source)?);
    Ok(())
}

fn sync_enforcement_policy_reload(
    document: &mut DocumentMut,
    reload: &EnforcementPolicyReloadConfig,
) -> Result<(), TuiError> {
    let policy_table = table_at_path(document, &["enforcement", "policy"]);
    if reload == &EnforcementPolicyReloadConfig::default() {
        policy_table.remove("reload");
        return Ok(());
    }
    set_table_item(policy_table, "reload", serialized_table_item(reload)?);
    Ok(())
}

fn sync_tls_material_store(
    document: &mut DocumentMut,
    config: &AgentConfig,
) -> Result<(), TuiError> {
    let roots = &config.tls.material_store.filesystem.allowed_roots;
    if roots.is_empty() {
        if let Some(table) = table_at_existing_path_mut(document, &["tls"]) {
            table.remove("material_store");
        }
        return Ok(());
    }
    set_value(
        document,
        &["tls", "material_store", "filesystem"],
        "allowed_roots",
        value(array_paths(roots)),
    );
    Ok(())
}

fn sync_tls_materials(
    document: &mut DocumentMut,
    materials: &[TlsMaterialConfig],
) -> Result<(), TuiError> {
    let table = table_at_path(document, &["tls"]);
    if materials.is_empty() {
        table.remove("materials");
        return Ok(());
    }
    let mut array = ArrayOfTables::new();
    for material in materials {
        array.push(toml_edit::ser::to_document(material)?.into_table());
    }
    set_table_item(table, "materials", Item::ArrayOfTables(array));
    Ok(())
}

fn serialized_table_item<T: Serialize>(value: &T) -> Result<Item, TuiError> {
    Ok(Item::Table(
        toml_edit::ser::to_document(value)?.into_table(),
    ))
}

fn set_root_value(document: &mut DocumentMut, key: &str, item: Item) {
    set_table_item(document.as_table_mut(), key, item);
}

fn set_value(document: &mut DocumentMut, table_path: &[&str], key: &str, item: Item) {
    set_table_item(table_at_path(document, table_path), key, item);
}

fn set_optional_selector(
    document: &mut DocumentMut,
    table_path: &[&str],
    key: &str,
    selector: Option<&Selector>,
) -> Result<(), TuiError> {
    let table = table_at_path(document, table_path);
    match selector {
        Some(selector) => {
            set_table_item(table, key, selector_item(selector)?);
        }
        None => {
            table.remove(key);
        }
    }
    Ok(())
}

fn set_optional_u64(
    document: &mut DocumentMut,
    table_path: &[&str],
    key: &str,
    records: Option<u64>,
) -> Result<(), TuiError> {
    match records {
        Some(records) => {
            let records = i64::try_from(records).map_err(|_| {
                TuiError::UnsupportedTomlShape(format!(
                    "{key} value {records} does not fit a TOML integer"
                ))
            })?;
            let table = table_at_path(document, table_path);
            set_table_item(table, key, value(records));
        }
        None => {
            if let Some(table) = table_at_existing_path_mut(document, table_path) {
                table.remove(key);
            }
        }
    }
    Ok(())
}

fn set_optional_path(
    document: &mut DocumentMut,
    table_path: &[&str],
    key: &str,
    path: Option<&Path>,
) {
    let table = table_at_path(document, table_path);
    match path {
        Some(path) if !path.as_os_str().is_empty() => {
            set_table_item(table, key, value(path.display().to_string()));
        }
        _ => {
            table.remove(key);
        }
    }
}

fn selector_item(selector: &Selector) -> Result<Item, TuiError> {
    if let Selector::Match { term } = selector {
        return Ok(Item::Table(selector_match_table(term)));
    }
    Ok(Item::Table(
        toml_edit::ser::to_document(selector)?.into_table(),
    ))
}

fn set_table_item(table: &mut Table, key: &str, item: Item) {
    if let Some(existing) = table.get_mut(key) {
        replace_item_preserving_value_decor(existing, item);
    } else {
        table.insert(key, item);
    }
}

fn replace_item_preserving_value_decor(existing: &mut Item, item: Item) {
    match (existing.as_value_mut(), item) {
        (Some(current), Item::Value(mut next)) => {
            let decor = current.decor().clone();
            *next.decor_mut() = decor;
            *current = next;
        }
        (_, item) => {
            *existing = item;
        }
    }
}

fn selector_match_table(term: &SelectorTerm) -> Table {
    let mut table = Table::new();
    table.insert("op", value("match"));

    let mut term_table = Table::new();
    term_table.insert("process", Item::Table(process_selector_table(term)));
    term_table.insert("traffic", Item::Table(traffic_selector_table(term)));
    table.insert("term", Item::Table(term_table));
    table
}

fn process_selector_table(term: &SelectorTerm) -> Table {
    let process = &term.process;
    let mut table = Table::new();
    table.insert("pids", value(array_u32(&process.pids)));
    table.insert("uids", value(array_u32(&process.uids)));
    table.insert("gids", value(array_u32(&process.gids)));
    table.insert("names", value(array_strings(&process.names)));
    table.insert(
        "exe_path_globs",
        value(array_strings(&process.exe_path_globs)),
    );
    table.insert(
        "cmdline_regexes",
        value(array_strings(&process.cmdline_regexes)),
    );
    table.insert(
        "systemd_services",
        value(array_strings(&process.systemd_services)),
    );
    table.insert(
        "container_ids",
        value(array_strings(&process.container_ids)),
    );
    table.insert("cgroup_paths", value(array_strings(&process.cgroup_paths)));
    table
}

fn traffic_selector_table(term: &SelectorTerm) -> Table {
    let traffic = &term.traffic;
    let mut table = Table::new();
    table.insert("local_ports", value(array_u16(&traffic.local_ports)));
    table.insert("remote_ports", value(array_u16(&traffic.remote_ports)));
    table.insert("directions", value(array_directions(&traffic.directions)));
    table.insert(
        "remote_addresses",
        value(array_strings(&traffic.remote_addresses)),
    );
    table
}

fn array_strings(values: &[String]) -> Array {
    let mut array = Array::new();
    for value in values {
        array.push(value.as_str());
    }
    array
}

fn array_paths(values: &[PathBuf]) -> Array {
    let mut array = Array::new();
    for value in values {
        array.push(value.display().to_string());
    }
    array
}

fn array_u16(values: &[u16]) -> Array {
    let mut array = Array::new();
    for value in values {
        array.push(i64::from(*value));
    }
    array
}

fn array_u32(values: &[u32]) -> Array {
    let mut array = Array::new();
    for value in values {
        array.push(i64::from(*value));
    }
    array
}

fn array_directions(values: &[Direction]) -> Array {
    let mut array = Array::new();
    for value in values {
        array.push(match value {
            Direction::Inbound => "inbound",
            Direction::Outbound => "outbound",
        });
    }
    array
}

fn table_at_path<'a>(document: &'a mut DocumentMut, path: &[&str]) -> &'a mut Table {
    let mut table = document.as_table_mut();
    for key in path {
        let item = table
            .entry(key)
            .or_insert_with(|| Item::Table(Table::new()));
        if item.as_table_mut().is_none() {
            *item = Item::Table(Table::new());
        }
        let Some(next_table) = item.as_table_mut() else {
            unreachable!("table item was just initialized");
        };
        table = next_table;
    }
    table
}

fn table_at_existing_path_mut<'a>(
    document: &'a mut DocumentMut,
    path: &[&str],
) -> Option<&'a mut Table> {
    let mut table = document.as_table_mut();
    for key in path {
        let item = table.get_mut(key)?;
        table = item.as_table_mut()?;
    }
    Some(table)
}

#[cfg(test)]
mod tests {
    use std::{collections::BTreeMap, path::Path};

    use probe_config::{
        AgentConfig, CaptureSelection, CompressionCodecName, ExporterTlsConfig,
        ExporterTransportConfig,
    };
    use probe_core::{ProcessSelector, Selector, TrafficSelector};

    use super::*;

    #[test]
    fn preserving_render_keeps_comments_and_updates_tui_managed_fields()
    -> Result<(), Box<dyn std::error::Error>> {
        let source = r#"
# keep this comment
agent_id = "old"
config_version = "local"

[capture]
selection = "auto"

[[exporters]]
id = "default"
transport = "file"
path = "/tmp/events.jsonl"
codec = "zstd"

[export.worker]
enabled = true

[storage.retention.ingress]
max_records = 10000

[storage.retention.export]
max_records = 10000
"#;
        let mut config = AgentConfig::from_toml_str(source)?;
        config.agent_id = "probe-a".to_string();
        config.capture.selection = CaptureSelection::Libpcap;
        config.export.worker.enabled = false;
        config.exporters[0].codec = CompressionCodecName::Gzip;
        config.storage.retention.ingress.max_records = Some(100_000);
        config.storage.retention.export.max_records = Some(1_000_000);

        let rendered = render_preserving_config(source, &config, Path::new("/tmp/agent.toml"))?;

        assert!(rendered.contains("# keep this comment"));
        assert!(rendered.contains("agent_id = \"probe-a\""));
        assert!(rendered.contains("selection = \"libpcap\""));
        assert!(rendered.contains("enabled = false"));
        assert!(rendered.contains("codec = \"gzip\""));
        assert!(rendered.contains("[admin]"));
        assert!(rendered.contains("socket_path = "));
        assert!(rendered.contains("[storage.retention.ingress]"));
        assert!(rendered.contains("[storage.retention.export]"));
        assert!(rendered.contains("max_records = 100000"));
        assert!(rendered.contains("max_records = 1000000"));
        AgentConfig::from_toml_str(&rendered)?.validate_basic()?;
        Ok(())
    }

    #[test]
    fn render_writes_non_empty_exporter_headers_and_tls() -> Result<(), Box<dyn std::error::Error>>
    {
        let source = r#"
agent_id = "probe"
config_version = "local"

[[exporters]]
id = "default"
transport = "file"
path = "/tmp/old.jsonl"
codec = "zstd"
"#;
        let mut config = AgentConfig::from_toml_str(source)?;
        config.exporters[0].transport = ExporterTransportConfig::Webhook {
            endpoint: "https://collector.example/batches".to_string(),
            headers: BTreeMap::from([("x-probe-node".to_string(), "node-a".to_string())]),
            tls: ExporterTlsConfig {
                trust_anchor_refs: vec!["collector-ca".to_string()],
                client_certificate_refs: vec!["client-cert".to_string()],
                client_private_key_ref: Some("client-key".to_string()),
            },
        };

        let rendered = render_preserving_config(source, &config, Path::new("/tmp/agent.toml"))?;
        let reloaded = AgentConfig::from_toml_str(&rendered)?;

        assert!(rendered.contains("[exporters.headers]"));
        assert!(rendered.contains("x-probe-node = \"node-a\""));
        assert!(rendered.contains("[exporters.tls]"));
        assert!(rendered.contains("trust_anchor_refs = [\"collector-ca\"]"));
        assert_eq!(reloaded, config);
        Ok(())
    }

    #[test]
    fn process_selector_is_written_as_human_readable_selector_table()
    -> Result<(), Box<dyn std::error::Error>> {
        let source = r#"
agent_id = "probe"
config_version = "local"

[capture]
selection = "auto"
"#;
        let mut config = AgentConfig::from_toml_str(source)?;
        config.capture.deep_observe_selector = Some(Selector::term(
            ProcessSelector {
                exe_path_globs: vec!["/usr/bin/curl".to_string()],
                ..ProcessSelector::default()
            },
            TrafficSelector::default(),
        ));

        let rendered = render_preserving_config(source, &config, Path::new("/tmp/agent.toml"))?;

        assert!(rendered.contains("[capture.deep_observe_selector]"));
        assert!(rendered.contains("op = \"match\""));
        assert!(rendered.contains("[capture.deep_observe_selector.term.process]"));
        assert!(rendered.contains("exe_path_globs = [\"/usr/bin/curl\"]"));
        AgentConfig::from_toml_str(&rendered)?.validate_basic()?;
        Ok(())
    }

    #[test]
    fn selector_item_uses_existing_selector_contract() -> Result<(), Box<dyn std::error::Error>> {
        let item = selector_item(&Selector::default())?;

        assert!(item.to_string().contains("op = \"match\""));
        Ok(())
    }
}

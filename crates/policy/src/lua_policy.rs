use std::{
    collections::BTreeMap,
    fmt,
    str::FromStr,
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
};

use mlua::{Function, HookTriggers, Lua, LuaOptions, LuaSerdeExt, StdLib, Table, Value, VmState};
use probe_core::{Action, DomainEvent, EventEnvelope, EventType, Verdict};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use thiserror::Error;

use crate::event_view::PolicyEventView;

const DEFAULT_INSTRUCTION_BUDGET: u64 = 100_000;
const DEFAULT_MEMORY_LIMIT_BYTES: usize = 16 * 1024 * 1024;
const INSTRUCTION_HOOK_INTERVAL: u32 = 1_000;
const POLICY_MODULE_CACHE_REGISTRY_KEY: &str = "probe_policy_module_cache";
const POLICY_MODULE_LOADING_REGISTRY_KEY: &str = "probe_policy_module_loading";
pub const POLICY_HOOKS: &[PolicyHook] = &[
    PolicyHook::ConnectionOpened,
    PolicyHook::ConnectionClosed,
    PolicyHook::HttpRequestHeaders,
    PolicyHook::HttpResponseHeaders,
    PolicyHook::HttpBodyChunk,
    PolicyHook::SseEvent,
    PolicyHook::WebSocketHandoff,
    PolicyHook::WebSocketFrame,
    PolicyHook::WebSocketMessage,
    PolicyHook::OpaqueStream,
    PolicyHook::Gap,
    PolicyHook::ProtocolError,
];

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PolicyHook {
    ConnectionOpened,
    ConnectionClosed,
    HttpRequestHeaders,
    HttpResponseHeaders,
    HttpBodyChunk,
    SseEvent,
    WebSocketHandoff,
    WebSocketFrame,
    WebSocketMessage,
    OpaqueStream,
    Gap,
    ProtocolError,
}

impl PolicyHook {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ConnectionOpened => "on_connection_opened",
            Self::ConnectionClosed => "on_connection_closed",
            Self::HttpRequestHeaders => "on_http_request_headers",
            Self::HttpResponseHeaders => "on_http_response_headers",
            Self::HttpBodyChunk => "on_http_body_chunk",
            Self::SseEvent => "on_sse_event",
            Self::WebSocketHandoff => "on_websocket_handoff",
            Self::WebSocketFrame => "on_websocket_frame",
            Self::WebSocketMessage => "on_websocket_message",
            Self::OpaqueStream => "on_opaque_stream",
            Self::Gap => "on_gap",
            Self::ProtocolError => "on_protocol_error",
        }
    }

    pub fn from_event_type(event_type: EventType) -> Option<Self> {
        match event_type {
            EventType::ConnectionOpened => Some(Self::ConnectionOpened),
            EventType::ConnectionClosed => Some(Self::ConnectionClosed),
            EventType::HttpRequestHeaders => Some(Self::HttpRequestHeaders),
            EventType::HttpResponseHeaders => Some(Self::HttpResponseHeaders),
            EventType::HttpBodyChunk => Some(Self::HttpBodyChunk),
            EventType::SseEvent => Some(Self::SseEvent),
            EventType::WebSocketHandoff => Some(Self::WebSocketHandoff),
            EventType::WebSocketFrame => Some(Self::WebSocketFrame),
            EventType::WebSocketMessage => Some(Self::WebSocketMessage),
            EventType::OpaqueStream => Some(Self::OpaqueStream),
            EventType::Gap => Some(Self::Gap),
            EventType::ProtocolError => Some(Self::ProtocolError),
            EventType::CaptureLoss
            | EventType::PolicyAlert
            | EventType::PolicyVerdict
            | EventType::PolicyRuntimeError
            | EventType::EnforcementDecision
            | EventType::L7MitmAudit => None,
        }
    }
}

impl fmt::Display for PolicyHook {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

impl FromStr for PolicyHook {
    type Err = UnknownPolicyHook;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        POLICY_HOOKS
            .iter()
            .copied()
            .find(|hook| hook.as_str() == value)
            .ok_or_else(|| UnknownPolicyHook {
                value: value.to_string(),
            })
    }
}

impl Serialize for PolicyHook {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(self.as_str())
    }
}

impl<'de> Deserialize<'de> for PolicyHook {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        String::deserialize(deserializer)?
            .parse()
            .map_err(serde::de::Error::custom)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Error)]
#[error("unknown policy hook: {value}")]
pub struct UnknownPolicyHook {
    value: String,
}

#[derive(Debug, Error)]
pub enum PolicyError {
    #[error("failed to initialize Lua policy: {0}")]
    Init(#[from] mlua::Error),
    #[error("policy bundle defines module {module} more than once")]
    DuplicateModule { module: String },
    #[error(
        "policy manifest declares hook {hook}, but source does not define a Lua function with that name"
    )]
    MissingHook { hook: PolicyHook },
    #[error("policy returned an invalid outcome: {0}")]
    InvalidOutcome(String),
    #[error("event type {event_type} cannot be delivered to a Lua policy hook")]
    UnsupportedPolicyEvent { event_type: EventType },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PolicyManifest {
    pub id: String,
    pub version: String,
    pub hooks: Vec<PolicyHook>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PolicyModule {
    pub name: String,
    pub source: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum PolicyOutcome {
    Alert(DomainEvent),
    Verdict(Verdict),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PolicyLimits {
    pub instruction_budget: u64,
    pub memory_limit_bytes: usize,
}

impl Default for PolicyLimits {
    fn default() -> Self {
        Self {
            instruction_budget: DEFAULT_INSTRUCTION_BUDGET,
            memory_limit_bytes: DEFAULT_MEMORY_LIMIT_BYTES,
        }
    }
}

pub struct PolicyRuntime {
    manifest: PolicyManifest,
    lua: Lua,
    limits: PolicyLimits,
    instruction_budget: Arc<AtomicU64>,
}

impl PolicyRuntime {
    pub fn from_source(manifest: PolicyManifest, source: &str) -> Result<Self, PolicyError> {
        Self::from_bundle_with_limits(manifest, source, Vec::new(), PolicyLimits::default())
    }

    pub fn from_source_with_required_hooks(
        manifest: PolicyManifest,
        source: &str,
    ) -> Result<Self, PolicyError> {
        Self::from_bundle_with_required_hooks(manifest, source, Vec::new())
    }

    pub fn from_bundle_with_required_hooks(
        manifest: PolicyManifest,
        source: &str,
        modules: Vec<PolicyModule>,
    ) -> Result<Self, PolicyError> {
        let runtime = Self::from_bundle(manifest, source, modules)?;
        runtime.validate_manifest_hooks()?;
        Ok(runtime)
    }

    pub fn from_source_with_limits(
        manifest: PolicyManifest,
        source: &str,
        limits: PolicyLimits,
    ) -> Result<Self, PolicyError> {
        Self::from_bundle_with_limits(manifest, source, Vec::new(), limits)
    }

    pub fn from_bundle(
        manifest: PolicyManifest,
        source: &str,
        modules: Vec<PolicyModule>,
    ) -> Result<Self, PolicyError> {
        Self::from_bundle_with_limits(manifest, source, modules, PolicyLimits::default())
    }

    pub fn from_bundle_with_limits(
        manifest: PolicyManifest,
        source: &str,
        modules: Vec<PolicyModule>,
        limits: PolicyLimits,
    ) -> Result<Self, PolicyError> {
        let modules = build_module_registry(modules)?;
        let lua = Lua::new_with(policy_stdlibs(), LuaOptions::default())?;
        lua.set_memory_limit(limits.memory_limit_bytes)?;
        let instruction_budget = Arc::new(AtomicU64::new(limits.instruction_budget));
        install_instruction_budget(&lua, Arc::clone(&instruction_budget))?;
        install_probe_api(&lua)?;
        remove_host_capabilities(&lua)?;
        validate_bundle_modules(&lua, modules.as_ref())?;
        install_bundle_module_loader(&lua, modules)?;
        instruction_budget.store(limits.instruction_budget, Ordering::Relaxed);
        lua.load(source).set_name(&manifest.id).exec()?;
        Ok(Self {
            manifest,
            lua,
            limits,
            instruction_budget,
        })
    }

    pub fn manifest(&self) -> &PolicyManifest {
        &self.manifest
    }

    pub fn handle_event(
        &self,
        hook: PolicyHook,
        event: &EventEnvelope,
    ) -> Result<Vec<PolicyOutcome>, PolicyError> {
        if !self.manifest.hooks.contains(&hook) {
            return Ok(Vec::new());
        }

        let hook = hook.as_str();
        let globals = self.lua.globals();
        let value = globals.get::<Value>(hook)?;
        let Value::Function(function) = value else {
            return Ok(Vec::new());
        };

        self.instruction_budget
            .store(self.limits.instruction_budget, Ordering::Relaxed);
        let event_view = PolicyEventView::from_envelope(event).map_err(|error| {
            PolicyError::UnsupportedPolicyEvent {
                event_type: error.event_type,
            }
        })?;
        let event_value = self.lua.to_value(&event_view)?;
        let returned: Value = function.call(event_value)?;
        value_to_outcomes(&self.lua, returned)
    }

    fn validate_manifest_hooks(&self) -> Result<(), PolicyError> {
        let globals = self.lua.globals();
        for hook in &self.manifest.hooks {
            let value = globals.get::<Value>(hook.as_str())?;
            if !matches!(value, Value::Function(_)) {
                return Err(PolicyError::MissingHook { hook: *hook });
            }
        }
        Ok(())
    }
}

fn build_module_registry(
    modules: Vec<PolicyModule>,
) -> Result<Arc<BTreeMap<String, String>>, PolicyError> {
    let mut registry = BTreeMap::new();
    for module in modules {
        if registry
            .insert(module.name.clone(), module.source)
            .is_some()
        {
            return Err(PolicyError::DuplicateModule {
                module: module.name,
            });
        }
    }
    Ok(Arc::new(registry))
}

fn validate_bundle_modules(
    lua: &Lua,
    modules: &BTreeMap<String, String>,
) -> Result<(), mlua::Error> {
    for (module, source) in modules {
        compile_bundle_module(lua, module, source)?;
    }
    Ok(())
}

fn compile_bundle_module(lua: &Lua, module: &str, source: &str) -> Result<Function, mlua::Error> {
    lua.load(source)
        .set_name(format!("@policy-module:{module}"))
        .into_function()
}

fn policy_stdlibs() -> StdLib {
    StdLib::TABLE | StdLib::STRING | StdLib::MATH | StdLib::BIT
}

fn install_instruction_budget(
    lua: &Lua,
    instruction_budget: Arc<AtomicU64>,
) -> Result<(), mlua::Error> {
    lua.set_hook(
        HookTriggers::new().every_nth_instruction(INSTRUCTION_HOOK_INTERVAL),
        move |_, _| {
            let remaining = instruction_budget.fetch_update(
                Ordering::Relaxed,
                Ordering::Relaxed,
                |remaining| remaining.checked_sub(u64::from(INSTRUCTION_HOOK_INTERVAL)),
            );
            match remaining {
                Ok(_) => Ok(VmState::Continue),
                Err(_) => Err(mlua::Error::RuntimeError(
                    "Lua policy exceeded instruction budget".to_string(),
                )),
            }
        },
    )
}

fn install_probe_api(lua: &Lua) -> Result<(), mlua::Error> {
    let probe = lua.create_table()?;
    probe.set(
        "emit_alert",
        lua.create_function(|lua, message: String| {
            let event = DomainEvent {
                name: "policy_alert".to_string(),
                severity: Action::Alert,
                message,
                metadata: serde_json::Value::Null,
            };
            lua.to_value(&event)
        })?,
    )?;
    probe.set(
        "verdict",
        lua.create_function(|_, table: Table| Ok(Value::Table(table)))?,
    )?;
    lua.globals().set("probe", probe)?;
    Ok(())
}

fn remove_host_capabilities(lua: &Lua) -> Result<(), mlua::Error> {
    let require = lua.create_function(|_, module: String| {
        Err::<Value, _>(mlua::Error::RuntimeError(format!(
            "Lua module loading is disabled in policy runtime: {module}"
        )))
    })?;
    let globals = lua.globals();
    for name in [
        "ffi",
        "io",
        "os",
        "package",
        "debug",
        "jit",
        "dofile",
        "loadfile",
        "load",
        "collectgarbage",
    ] {
        globals.set(name, Value::Nil)?;
    }
    globals.set("require", require)?;
    Ok(())
}

fn install_bundle_module_loader(
    lua: &Lua,
    modules: Arc<BTreeMap<String, String>>,
) -> Result<(), mlua::Error> {
    let cache = lua.create_table()?;
    lua.set_named_registry_value(POLICY_MODULE_CACHE_REGISTRY_KEY, cache)?;
    let loading = lua.create_table()?;
    lua.set_named_registry_value(POLICY_MODULE_LOADING_REGISTRY_KEY, loading)?;
    let require = lua.create_function(move |lua, module: String| {
        let Some(source) = modules.get(&module) else {
            return Err(mlua::Error::RuntimeError(format!(
                "Lua policy module is not declared in this bundle: {module}"
            )));
        };

        let cache: Table = lua.named_registry_value(POLICY_MODULE_CACHE_REGISTRY_KEY)?;
        let cached = cache.get::<Value>(module.as_str())?;
        if !matches!(cached, Value::Nil) {
            return Ok(cached);
        }

        let loading: Table = lua.named_registry_value(POLICY_MODULE_LOADING_REGISTRY_KEY)?;
        if loading.get::<bool>(module.as_str()).unwrap_or(false) {
            return Err(mlua::Error::RuntimeError(format!(
                "Lua policy module require cycle detected: {module}"
            )));
        }
        loading.set(module.as_str(), true)?;
        let loaded = match compile_bundle_module(lua, module.as_str(), source)
            .and_then(|function| function.call::<Value>(()))
        {
            Ok(loaded) => loaded,
            Err(error) => {
                loading.set(module.as_str(), Value::Nil)?;
                return Err(error);
            }
        };
        loading.set(module.as_str(), Value::Nil)?;
        let module_value = if matches!(loaded, Value::Nil) {
            Value::Boolean(true)
        } else {
            loaded
        };
        cache.set(module.as_str(), module_value.clone())?;
        Ok(module_value)
    })?;
    lua.globals().set("require", require)?;
    Ok(())
}

fn value_to_outcomes(lua: &Lua, value: Value) -> Result<Vec<PolicyOutcome>, PolicyError> {
    match value {
        Value::Nil => Ok(Vec::new()),
        Value::Table(table) if table.raw_len() > 0 => table
            .sequence_values::<Value>()
            .map(|value| value.and_then(|value| table_value_to_outcome(lua, value)))
            .collect::<Result<Vec<_>, _>>()
            .map_err(|error| PolicyError::InvalidOutcome(error.to_string())),
        Value::Table(table) => table_value_to_outcome(lua, Value::Table(table))
            .map(|outcome| vec![outcome])
            .map_err(|error| PolicyError::InvalidOutcome(error.to_string())),
        other => Err(PolicyError::InvalidOutcome(format!(
            "expected nil or table, got {}",
            other.type_name()
        ))),
    }
}

fn table_value_to_outcome(lua: &Lua, value: Value) -> Result<PolicyOutcome, mlua::Error> {
    let Value::Table(table) = &value else {
        return Err(mlua::Error::RuntimeError(format!(
            "expected table outcome, got {}",
            value.type_name()
        )));
    };

    if table.contains_key("action")? {
        return lua.from_value::<Verdict>(value).map(PolicyOutcome::Verdict);
    }

    lua.from_value::<DomainEvent>(value)
        .map(PolicyOutcome::Alert)
}

pub fn hook_for_event(event: &EventEnvelope) -> Option<PolicyHook> {
    PolicyHook::from_event_type(event.kind().event_type())
}

#[cfg(test)]
mod tests {
    use probe_core::{
        Action, AddressPort, BodyChunk, CaptureOrigin, CaptureSource, Direction, EventEnvelope,
        EventKind, EventProvenance, EventType, FlowContext, FlowIdentity, Gap, HttpHeaders,
        OpaqueStream, PolicyEmissionStage, ProcessContext, ProcessIdentity, ProtocolError,
        SseEvent, Timestamp, TransportProtocol, WebSocketFrame, WebSocketHandoff, WebSocketMessage,
        WebSocketMessageOpcode, WebSocketOpcode,
    };

    use crate::{
        POLICY_HOOKS, PolicyError, PolicyHook, PolicyLimits, PolicyManifest, PolicyModule,
        PolicyOutcome, PolicyRuntime, hook_for_event,
    };

    #[test]
    fn lua_policy_can_return_typed_alert_verdict() -> Result<(), Box<dyn std::error::Error>> {
        let runtime = PolicyRuntime::from_source(
            PolicyManifest {
                id: "demo".to_string(),
                version: "1.0.0".to_string(),
                hooks: vec![PolicyHook::HttpRequestHeaders],
            },
            r#"
            function on_http_request_headers(event)
              return {
                action = "alert",
                scope = "request",
                reason = "matched " .. event.kind.target,
                confidence = 90
              }
            end
            "#,
        )?;

        let event = demo_event();
        let outcomes = runtime.handle_event(primary_hook_for_event(&event), &event)?;
        let PolicyOutcome::Verdict(verdict) = outcomes.first().ok_or("missing outcome")? else {
            return Err("missing verdict".into());
        };

        assert_eq!(verdict.reason, "matched /chat");
        assert_eq!(verdict.confidence, 90);
        Ok(())
    }

    #[test]
    fn lua_policy_receives_explicit_event_view() -> Result<(), Box<dyn std::error::Error>> {
        let runtime = PolicyRuntime::from_source(
            PolicyManifest {
                id: "demo".to_string(),
                version: "1.0.0".to_string(),
                hooks: vec![PolicyHook::HttpRequestHeaders],
            },
            r#"
            function on_http_request_headers(event)
              return probe.emit_alert(
                event.flow.process.name .. " " ..
                tostring(event.flow.process.identity.pid) .. " " ..
                event.origin.source .. " " ..
                event.origin.provider .. " " ..
                event.enforcement_evidence.kind .. " " ..
                event.event_type .. " " ..
                event.kind.target
              )
            end
            "#,
        )?;
        let event = demo_event();
        let outcomes = runtime.handle_event(PolicyHook::HttpRequestHeaders, &event)?;

        let [PolicyOutcome::Alert(alert)] = outcomes.as_slice() else {
            panic!("expected one alert outcome: {outcomes:?}");
        };
        assert_eq!(
            alert.message,
            "demo 1 replay replay destructive_allowed http_request_headers /chat"
        );
        Ok(())
    }

    #[test]
    fn lua_policy_receives_tls_session_secret_origin_view() -> Result<(), Box<dyn std::error::Error>>
    {
        let runtime = PolicyRuntime::from_source(
            PolicyManifest {
                id: "demo".to_string(),
                version: "1.0.0".to_string(),
                hooks: vec![PolicyHook::HttpRequestHeaders],
            },
            r#"
            function on_http_request_headers(event)
              return probe.emit_alert(event.origin.source .. " " .. event.origin.provider)
            end
            "#,
        )?;
        let event =
            demo_event_with_origin(CaptureOrigin::from_source(CaptureSource::TlsSessionSecret));
        let outcomes = runtime.handle_event(PolicyHook::HttpRequestHeaders, &event)?;

        let [PolicyOutcome::Alert(alert)] = outcomes.as_slice() else {
            panic!("expected one alert outcome: {outcomes:?}");
        };
        assert_eq!(alert.message, "tls_session_secret plaintext");
        Ok(())
    }

    #[test]
    fn lua_policy_event_view_does_not_expose_lua_reserved_keys()
    -> Result<(), Box<dyn std::error::Error>> {
        let runtime = PolicyRuntime::from_source(
            PolicyManifest {
                id: "reserved-key-contract".to_string(),
                version: "1.0.0".to_string(),
                hooks: POLICY_HOOKS.to_vec(),
            },
            r#"
            local reserved = {}
            for word in string.gmatch(
              "and break do else elseif end false for function goto if in local nil not or repeat return then true until while",
              "%S+"
            ) do reserved[word] = true end

            local function scan(value, path)
              if type(value) ~= "table" then
                return nil
              end
              for key, child in pairs(value) do
                if type(key) == "string" and reserved[key] then
                  return path .. "." .. key
                end
                local nested = scan(child, path .. "." .. tostring(key))
                if nested ~= nil then
                  return nested
                end
              end
              return nil
            end

            local function payload_marker(event)
              local kind = event.kind
              if kind.type == "connection_opened" then
                return event.flow.protocol .. ":" .. tostring(event.flow.attribution_confidence)
              elseif kind.type == "connection_closed" then
                return event.flow.process.identity.exe_path
              elseif kind.type == "http_request_headers" then
                return kind.method .. ":" .. kind.target .. ":" ..
                  kind.headers[1][1] .. "=" .. kind.headers[1][2]
              elseif kind.type == "http_response_headers" then
                return tostring(kind.status) .. ":" .. kind.reason
              elseif kind.type == "http_body_chunk" then
                return tostring(kind.offset) .. ":" ..
                  tostring(kind.data[1]) .. ":" .. tostring(kind.end_stream)
              elseif kind.type == "sse_event" then
                return kind.event .. ":" .. kind.id .. ":" ..
                  tostring(kind.retry_ms) .. ":" .. kind.data
              elseif kind.type == "websocket_handoff" then
                return kind.target .. ":" .. kind.subprotocol .. ":" .. kind.extensions[1]
              elseif kind.type == "websocket_frame" then
                return kind.opcode.kind .. ":" ..
                  tostring(kind.payload_len) .. ":" .. tostring(kind.masked)
              elseif kind.type == "websocket_message" then
                return kind.opcode.kind .. ":" ..
                  tostring(kind.payload_len) .. ":" ..
                  kind.payload_text .. ":" ..
                  tostring(kind.first_frame_sequence) .. "-" ..
                  tostring(kind.final_frame_sequence)
              elseif kind.type == "opaque_stream" then
                return kind.direction .. ":" .. kind.reason .. ":" ..
                  tostring(kind.fingerprint[1])
              elseif kind.type == "gap" then
                return kind.direction .. ":" .. tostring(kind.expected_offset) .. ":" ..
                  tostring(kind.next_offset) .. ":" .. kind.reason
              elseif kind.type == "protocol_error" then
                return kind.direction .. ":" .. kind.reason
              end
              return "unknown"
            end

            function inspect_policy_event(event)
              local leaked = scan(event, "event")
              if leaked ~= nil then
                return { action = "deny", scope = "request", reason = leaked, confidence = 100 }
              end
              return {
                action = "allow",
                scope = "request",
                reason = event.kind.type .. " " ..
                  tostring(event.flow.local_endpoint.port) .. "->" ..
                  tostring(event.flow.remote_endpoint.port) .. " " ..
                  payload_marker(event),
                confidence = 100
              }
            end

            for _, hook in ipairs({
              "on_connection_opened", "on_connection_closed", "on_http_request_headers",
              "on_http_response_headers", "on_http_body_chunk", "on_sse_event",
              "on_websocket_handoff", "on_websocket_frame", "on_websocket_message",
              "on_opaque_stream", "on_gap", "on_protocol_error"
            }) do
              _G[hook] = inspect_policy_event
            end
            "#,
        )?;

        for (event, expected_reason) in lua_policy_event_view_contract_events() {
            let outcomes = runtime.handle_event(primary_hook_for_event(&event), &event)?;
            let Some(PolicyOutcome::Verdict(verdict)) = outcomes.first() else {
                return Err(format!("missing verdict for {}", event.kind().event_type()).into());
            };

            assert_eq!(verdict.action, Action::Allow, "{event:?}");
            assert_eq!(verdict.reason, expected_reason, "{event:?}");
        }
        Ok(())
    }

    #[test]
    fn lua_policy_can_emit_alert_and_verdict() -> Result<(), Box<dyn std::error::Error>> {
        let runtime = PolicyRuntime::from_source(
            PolicyManifest {
                id: "demo".to_string(),
                version: "1.0.0".to_string(),
                hooks: vec![PolicyHook::HttpRequestHeaders],
            },
            r#"
            function on_http_request_headers(event)
              return {
                probe.emit_alert("sensitive path"),
                probe.verdict({
                  action = "deny",
                  scope = "request",
                  reason = "dry-run protection",
                  confidence = 95
                })
              }
            end
            "#,
        )?;

        let event = demo_event();
        let outcomes = runtime.handle_event(primary_hook_for_event(&event), &event)?;

        assert!(
            matches!(outcomes.first(), Some(PolicyOutcome::Alert(alert)) if alert.message == "sensitive path")
        );
        assert!(
            matches!(outcomes.get(1), Some(PolicyOutcome::Verdict(verdict)) if verdict.reason == "dry-run protection")
        );
        Ok(())
    }

    #[test]
    fn lua_policy_can_handle_websocket_handoff() -> Result<(), Box<dyn std::error::Error>> {
        let runtime = PolicyRuntime::from_source(
            PolicyManifest {
                id: "websocket".to_string(),
                version: "1.0.0".to_string(),
                hooks: vec![PolicyHook::WebSocketHandoff],
            },
            r#"
            function on_websocket_handoff(event)
              return {
                action = "alert",
                scope = "flow",
                reason = event.kind.type .. " " .. event.kind.target .. " " .. event.kind.subprotocol,
                confidence = 80
              }
            end
            "#,
        )?;

        let event = websocket_handoff_event();
        let outcomes = runtime.handle_event(primary_hook_for_event(&event), &event)?;

        assert!(
            matches!(outcomes.first(), Some(PolicyOutcome::Verdict(verdict)) if verdict.reason == "websocket_handoff /chat chat")
        );
        Ok(())
    }

    #[test]
    fn lua_policy_can_handle_websocket_frame() -> Result<(), Box<dyn std::error::Error>> {
        let runtime = PolicyRuntime::from_source(
            PolicyManifest {
                id: "websocket-frame".to_string(),
                version: "1.0.0".to_string(),
                hooks: vec![PolicyHook::WebSocketFrame],
            },
            r#"
            function on_websocket_frame(event)
              return probe.emit_alert(
                event.kind.type .. " " .. event.kind.opcode.kind .. " " .. tostring(event.kind.payload_len)
              )
            end
            "#,
        )?;

        let event = websocket_frame_event();
        let outcomes = runtime.handle_event(primary_hook_for_event(&event), &event)?;

        assert!(
            matches!(outcomes.first(), Some(PolicyOutcome::Alert(alert)) if alert.message == "websocket_frame text 5")
        );
        Ok(())
    }

    #[test]
    fn lua_policy_can_handle_websocket_message() -> Result<(), Box<dyn std::error::Error>> {
        let runtime = PolicyRuntime::from_source(
            PolicyManifest {
                id: "websocket-message".to_string(),
                version: "1.0.0".to_string(),
                hooks: vec![PolicyHook::WebSocketMessage],
            },
            r#"
            function on_websocket_message(event)
              return probe.emit_alert(
                event.kind.type .. " " ..
                event.kind.opcode.kind .. " " ..
                tostring(event.kind.payload_len) .. " " ..
                event.kind.payload_text .. " " ..
                tostring(event.kind.first_frame_sequence) .. "-" ..
                tostring(event.kind.final_frame_sequence)
              )
            end
            "#,
        )?;

        let event = websocket_message_event();
        let outcomes = runtime.handle_event(primary_hook_for_event(&event), &event)?;

        assert!(
            matches!(outcomes.first(), Some(PolicyOutcome::Alert(alert)) if alert.message == "websocket_message text 5 hello 1-2")
        );
        Ok(())
    }

    #[test]
    fn lua_policy_does_not_expand_binary_websocket_payload()
    -> Result<(), Box<dyn std::error::Error>> {
        let runtime = PolicyRuntime::from_source(
            PolicyManifest {
                id: "websocket-binary-message".to_string(),
                version: "1.0.0".to_string(),
                hooks: vec![PolicyHook::WebSocketMessage],
            },
            r#"
            function on_websocket_message(event)
              return probe.emit_alert(
                tostring(event.kind.payload == nil) .. " " ..
                tostring(event.kind.payload_text == nil) .. " " ..
                event.kind.opcode.kind .. " " ..
                tostring(event.kind.payload_len)
              )
            end
            "#,
        )?;

        let event =
            websocket_message_event_with_payload(WebSocketMessageOpcode::Binary, vec![0, 255]);
        let outcomes = runtime.handle_event(primary_hook_for_event(&event), &event)?;

        assert!(
            matches!(outcomes.first(), Some(PolicyOutcome::Alert(alert)) if alert.message == "true true binary 2")
        );
        Ok(())
    }

    #[test]
    fn lua_policy_omits_large_websocket_payload_text_before_hook()
    -> Result<(), Box<dyn std::error::Error>> {
        let runtime = PolicyRuntime::from_source(
            PolicyManifest {
                id: "websocket-large-text-message".to_string(),
                version: "1.0.0".to_string(),
                hooks: vec![PolicyHook::WebSocketMessage],
            },
            r#"
            function on_websocket_message(event)
              if event.kind.payload_text == nil and event.kind.payload_len > 65536 then
                return probe.emit_alert("large text omitted " .. tostring(event.kind.payload_len))
              end
              return probe.emit_alert("unexpected payload text")
            end
            "#,
        )?;

        let event = websocket_message_event_with_payload(
            WebSocketMessageOpcode::Text,
            vec![b'a'; 64 * 1024 + 1],
        );
        let outcomes = runtime.handle_event(primary_hook_for_event(&event), &event)?;

        assert!(
            matches!(outcomes.first(), Some(PolicyOutcome::Alert(alert)) if alert.message == "large text omitted 65537")
        );
        Ok(())
    }

    #[test]
    fn lua_policy_cannot_require_ffi() -> Result<(), Box<dyn std::error::Error>> {
        let runtime = PolicyRuntime::from_source(
            PolicyManifest {
                id: "ffi".to_string(),
                version: "1.0.0".to_string(),
                hooks: vec![PolicyHook::HttpRequestHeaders],
            },
            r#"
            function on_http_request_headers(event)
              require("ffi")
            end
            "#,
        )?;

        let event = demo_event();
        let result = runtime.handle_event(primary_hook_for_event(&event), &event);
        assert!(result.is_err());
        Ok(())
    }

    #[test]
    fn lua_policy_can_require_declared_bundle_module() -> Result<(), Box<dyn std::error::Error>> {
        let runtime = PolicyRuntime::from_bundle_with_required_hooks(
            PolicyManifest {
                id: "modules".to_string(),
                version: "1.0.0".to_string(),
                hooks: vec![PolicyHook::HttpRequestHeaders],
            },
            r#"
            local matcher = require("guard.matcher")

            function on_http_request_headers(event)
              if matcher.matches(event.kind.target) then
                return probe.emit_alert("module matched " .. event.kind.target)
              end
              return nil
            end
            "#,
            vec![PolicyModule {
                name: "guard.matcher".to_string(),
                source: r#"
                local M = {}

                function M.matches(target)
                  return target == "/chat"
                end

                return M
                "#
                .to_string(),
            }],
        )?;

        let event = demo_event();
        let outcomes = runtime.handle_event(primary_hook_for_event(&event), &event)?;

        assert!(
            matches!(outcomes.first(), Some(PolicyOutcome::Alert(alert)) if alert.message == "module matched /chat")
        );
        Ok(())
    }

    #[test]
    fn lua_policy_rejects_undeclared_bundle_module() -> Result<(), Box<dyn std::error::Error>> {
        let result = PolicyRuntime::from_bundle_with_required_hooks(
            PolicyManifest {
                id: "missing-module".to_string(),
                version: "1.0.0".to_string(),
                hooks: vec![PolicyHook::HttpRequestHeaders],
            },
            r#"
            local matcher = require("guard.matcher")

            function on_http_request_headers(_)
              return matcher
            end
            "#,
            Vec::new(),
        );

        assert!(matches!(result, Err(PolicyError::Init(_))));
        Ok(())
    }

    #[test]
    fn lua_policy_rejects_duplicate_bundle_module_names() {
        let result = PolicyRuntime::from_bundle(
            PolicyManifest {
                id: "duplicate-module".to_string(),
                version: "1.0.0".to_string(),
                hooks: vec![PolicyHook::HttpRequestHeaders],
            },
            "function on_http_request_headers(_) return nil end",
            vec![
                PolicyModule {
                    name: "guard.matcher".to_string(),
                    source: "return {}".to_string(),
                },
                PolicyModule {
                    name: "guard.matcher".to_string(),
                    source: "return {}".to_string(),
                },
            ],
        );

        assert!(matches!(
            result,
            Err(PolicyError::DuplicateModule { module }) if module == "guard.matcher"
        ));
    }

    #[test]
    fn lua_policy_rejects_unused_bundle_module_syntax_error() {
        let result = PolicyRuntime::from_bundle_with_required_hooks(
            PolicyManifest {
                id: "unused-broken-module".to_string(),
                version: "1.0.0".to_string(),
                hooks: vec![PolicyHook::HttpRequestHeaders],
            },
            r#"
            function on_http_request_headers(_)
              return nil
            end
            "#,
            vec![PolicyModule {
                name: "guard.broken".to_string(),
                source: "function broken(".to_string(),
            }],
        );

        assert!(matches!(result, Err(PolicyError::Init(_))));
    }

    #[test]
    fn lua_policy_rejects_expression_only_bundle_module_source() {
        let result = PolicyRuntime::from_bundle_with_required_hooks(
            PolicyManifest {
                id: "expression-module".to_string(),
                version: "1.0.0".to_string(),
                hooks: vec![PolicyHook::HttpRequestHeaders],
            },
            r#"
            function on_http_request_headers(_)
              return nil
            end
            "#,
            vec![PolicyModule {
                name: "guard.matcher".to_string(),
                source: "{ matches = function(_) return true end }".to_string(),
            }],
        );

        assert!(matches!(result, Err(PolicyError::Init(_))));
    }

    #[test]
    fn lua_policy_does_not_execute_bundle_module_during_syntax_preflight()
    -> Result<(), Box<dyn std::error::Error>> {
        PolicyRuntime::from_bundle_with_required_hooks(
            PolicyManifest {
                id: "unused-runtime-broken-module".to_string(),
                version: "1.0.0".to_string(),
                hooks: vec![PolicyHook::HttpRequestHeaders],
            },
            r#"
            function on_http_request_headers(_)
              return nil
            end
            "#,
            vec![PolicyModule {
                name: "guard.unused".to_string(),
                source: r#"error("module body should stay lazy")"#.to_string(),
            }],
        )?;

        Ok(())
    }

    #[test]
    fn lua_policy_does_not_cache_failed_bundle_module_load()
    -> Result<(), Box<dyn std::error::Error>> {
        let runtime = PolicyRuntime::from_bundle_with_required_hooks(
            PolicyManifest {
                id: "failed-module".to_string(),
                version: "1.0.0".to_string(),
                hooks: vec![PolicyHook::HttpRequestHeaders],
            },
            r#"
            function on_http_request_headers(_)
              local broken = require("guard.broken")
              return probe.emit_alert(tostring(broken))
            end
            "#,
            vec![PolicyModule {
                name: "guard.broken".to_string(),
                source: r#"error("broken module")"#.to_string(),
            }],
        )?;

        let event = demo_event();

        assert!(
            runtime
                .handle_event(primary_hook_for_event(&event), &event)
                .is_err()
        );
        assert!(
            runtime
                .handle_event(primary_hook_for_event(&event), &event)
                .is_err()
        );
        Ok(())
    }

    #[test]
    fn lua_policy_rejects_bundle_module_require_cycle() {
        let result = PolicyRuntime::from_bundle_with_required_hooks(
            PolicyManifest {
                id: "module-cycle".to_string(),
                version: "1.0.0".to_string(),
                hooks: vec![PolicyHook::HttpRequestHeaders],
            },
            r#"
            local a = require("guard.a")

            function on_http_request_headers(_)
              return probe.emit_alert(tostring(a))
            end
            "#,
            vec![
                PolicyModule {
                    name: "guard.a".to_string(),
                    source: r#"return require("guard.b")"#.to_string(),
                },
                PolicyModule {
                    name: "guard.b".to_string(),
                    source: r#"return require("guard.a")"#.to_string(),
                },
            ],
        );

        assert!(matches!(result, Err(PolicyError::Init(_))));
    }

    #[test]
    fn lua_policy_cannot_use_host_libraries() -> Result<(), Box<dyn std::error::Error>> {
        let runtime = PolicyRuntime::from_source(
            PolicyManifest {
                id: "host_caps".to_string(),
                version: "1.0.0".to_string(),
                hooks: vec![PolicyHook::HttpRequestHeaders],
            },
            r#"
            function on_http_request_headers(event)
              if os ~= nil or io ~= nil or package ~= nil or debug ~= nil or jit ~= nil then
                return {
                  action = "deny",
                  scope = "request",
                  reason = "host capability leaked",
                  confidence = 100
                }
              end
              return {
                action = "allow",
                scope = "request",
                reason = "sandboxed",
                confidence = 100
              }
            end
            "#,
        )?;

        let event = demo_event();
        let outcomes = runtime.handle_event(primary_hook_for_event(&event), &event)?;

        assert!(
            matches!(outcomes.first(), Some(PolicyOutcome::Verdict(verdict)) if verdict.reason == "sandboxed")
        );
        Ok(())
    }

    #[test]
    fn lua_policy_instruction_budget_stops_infinite_loop() -> Result<(), Box<dyn std::error::Error>>
    {
        let runtime = PolicyRuntime::from_source(
            PolicyManifest {
                id: "loop".to_string(),
                version: "1.0.0".to_string(),
                hooks: vec![PolicyHook::HttpRequestHeaders],
            },
            r#"
            function on_http_request_headers(event)
              while true do
              end
            end
            "#,
        )?;

        let event = demo_event();
        let result = runtime.handle_event(primary_hook_for_event(&event), &event);
        assert!(result.is_err());
        Ok(())
    }

    #[test]
    fn lua_policy_memory_budget_stops_large_allocation() -> Result<(), Box<dyn std::error::Error>> {
        let runtime = PolicyRuntime::from_source_with_limits(
            PolicyManifest {
                id: "memory".to_string(),
                version: "1.0.0".to_string(),
                hooks: vec![PolicyHook::HttpRequestHeaders],
            },
            r#"
            function on_http_request_headers(event)
              local value = string.rep("x", 2 * 1024 * 1024)
              return {
                action = "allow",
                scope = "request",
                reason = value,
                confidence = 1
              }
            end
            "#,
            PolicyLimits {
                instruction_budget: 100_000,
                memory_limit_bytes: 1024 * 1024,
            },
        )?;

        let event = demo_event();
        let result = runtime.handle_event(primary_hook_for_event(&event), &event);
        assert!(result.is_err());
        Ok(())
    }

    #[test]
    fn secondary_events_do_not_have_policy_hooks() -> Result<(), Box<dyn std::error::Error>> {
        let trigger = demo_event().with_provenance(EventProvenance::primary(1, 0));
        let policy_alert = EventEnvelope::from_policy_emission(
            Timestamp {
                monotonic_ns: 2,
                wall_time_unix_ns: 1,
            },
            &trigger,
            "test-policy@1",
            0,
            0,
            PolicyEmissionStage::Output,
            EventKind::PolicyAlert(probe_core::DomainEvent {
                name: "audit".to_string(),
                severity: probe_core::Action::Alert,
                message: "secondary".to_string(),
                metadata: serde_json::Value::Null,
            }),
        );

        assert_eq!(hook_for_event(&policy_alert), None);
        let runtime = PolicyRuntime::from_source(
            PolicyManifest {
                id: "demo".to_string(),
                version: "1.0.0".to_string(),
                hooks: vec![PolicyHook::HttpRequestHeaders],
            },
            r#"
            function on_http_request_headers(event)
              return probe.emit_alert(event.kind.type)
            end
            "#,
        )?;
        let error = runtime
            .handle_event(PolicyHook::HttpRequestHeaders, &policy_alert)
            .expect_err("secondary events must not be valid Lua policy inputs");
        assert!(matches!(
            error,
            PolicyError::UnsupportedPolicyEvent {
                event_type: EventType::PolicyAlert
            }
        ));
        Ok(())
    }

    #[test]
    fn policy_hook_maps_from_primary_event_type() {
        for (event_type, hook) in policy_hook_mapping_cases() {
            assert_eq!(PolicyHook::from_event_type(event_type), Some(hook));
            assert!(POLICY_HOOKS.contains(&hook));

            let value = serde_json::to_value(hook).expect("hook must serialize");
            assert_eq!(
                serde_json::from_value::<PolicyHook>(value).expect("hook must deserialize"),
                hook
            );
        }

        for event_type in [
            EventType::CaptureLoss,
            EventType::PolicyAlert,
            EventType::PolicyVerdict,
            EventType::PolicyRuntimeError,
            EventType::EnforcementDecision,
            EventType::L7MitmAudit,
        ] {
            assert_eq!(PolicyHook::from_event_type(event_type), None);
        }
    }

    #[test]
    fn policy_hook_serializes_to_lua_callback_name() -> Result<(), Box<dyn std::error::Error>> {
        let manifest = PolicyManifest {
            id: "demo".to_string(),
            version: "1.0.0".to_string(),
            hooks: vec![
                PolicyHook::HttpRequestHeaders,
                PolicyHook::WebSocketHandoff,
                PolicyHook::WebSocketFrame,
                PolicyHook::WebSocketMessage,
            ],
        };

        let value = serde_json::to_value(&manifest)?;
        assert_eq!(value["hooks"][0], "on_http_request_headers");
        assert_eq!(value["hooks"][1], "on_websocket_handoff");
        assert_eq!(value["hooks"][2], "on_websocket_frame");
        assert_eq!(value["hooks"][3], "on_websocket_message");

        let parsed = serde_json::from_value::<PolicyManifest>(value)?;
        assert_eq!(
            parsed.hooks,
            vec![
                PolicyHook::HttpRequestHeaders,
                PolicyHook::WebSocketHandoff,
                PolicyHook::WebSocketFrame,
                PolicyHook::WebSocketMessage,
            ]
        );
        let error = serde_json::from_str::<PolicyHook>(r#""on_http2_headers""#)
            .expect_err("unknown hook names must fail");

        assert!(error.to_string().contains("unknown policy hook"));
        Ok(())
    }

    fn primary_hook_for_event(event: &EventEnvelope) -> PolicyHook {
        hook_for_event(event).expect("demo event should have a primary policy hook")
    }

    fn policy_hook_mapping_cases() -> [(EventType, PolicyHook); 12] {
        [
            (EventType::ConnectionOpened, PolicyHook::ConnectionOpened),
            (EventType::ConnectionClosed, PolicyHook::ConnectionClosed),
            (
                EventType::HttpRequestHeaders,
                PolicyHook::HttpRequestHeaders,
            ),
            (
                EventType::HttpResponseHeaders,
                PolicyHook::HttpResponseHeaders,
            ),
            (EventType::HttpBodyChunk, PolicyHook::HttpBodyChunk),
            (EventType::SseEvent, PolicyHook::SseEvent),
            (EventType::WebSocketHandoff, PolicyHook::WebSocketHandoff),
            (EventType::WebSocketFrame, PolicyHook::WebSocketFrame),
            (EventType::WebSocketMessage, PolicyHook::WebSocketMessage),
            (EventType::OpaqueStream, PolicyHook::OpaqueStream),
            (EventType::Gap, PolicyHook::Gap),
            (EventType::ProtocolError, PolicyHook::ProtocolError),
        ]
    }

    fn lua_policy_event_view_contract_events() -> Vec<(EventEnvelope, &'static str)> {
        vec![
            (
                demo_event_with_kind(EventKind::ConnectionOpened),
                "connection_opened 50000->80 tcp:100",
            ),
            (
                demo_event_with_kind(EventKind::ConnectionClosed),
                "connection_closed 50000->80 /usr/bin/demo",
            ),
            (
                demo_event(),
                "http_request_headers 50000->80 GET:/chat:host=example.test",
            ),
            (
                demo_event_with_kind(EventKind::HttpResponseHeaders(http_headers(
                    Direction::Inbound,
                    None,
                    None,
                    Some(200),
                    Some("OK"),
                    "content-type",
                    "text/plain",
                ))),
                "http_response_headers 50000->80 200:OK",
            ),
            (
                demo_event_with_kind(EventKind::HttpBodyChunk(BodyChunk {
                    direction: Direction::Inbound,
                    stream_sequence: 1,
                    offset: 0,
                    data: vec![65, 66].into(),
                    end_stream: true,
                })),
                "http_body_chunk 50000->80 0:65:true",
            ),
            (
                demo_event_with_kind(EventKind::SseEvent(SseEvent {
                    direction: Direction::Inbound,
                    stream_sequence: 1,
                    event: Some("message".to_string()),
                    id: Some("1".to_string()),
                    retry_ms: Some(1000),
                    data: "hello".to_string(),
                })),
                "sse_event 50000->80 message:1:1000:hello",
            ),
            (
                websocket_handoff_event(),
                "websocket_handoff 50000->80 /chat:chat:permessage-deflate",
            ),
            (
                websocket_frame_event(),
                "websocket_frame 50000->80 text:5:false",
            ),
            (
                websocket_message_event(),
                "websocket_message 50000->80 text:5:hello:1-2",
            ),
            (
                demo_event_with_kind(EventKind::OpaqueStream(OpaqueStream {
                    direction: Direction::Inbound,
                    fingerprint: vec![1, 2, 3],
                    reason: "unknown protocol".to_string(),
                })),
                "opaque_stream 50000->80 inbound:unknown protocol:1",
            ),
            (
                demo_event_with_kind(EventKind::Gap(Gap {
                    direction: Direction::Inbound,
                    expected_offset: 1,
                    next_offset: Some(2),
                    reason: "truncated".to_string(),
                })),
                "gap 50000->80 inbound:1:2:truncated",
            ),
            (
                demo_event_with_kind(EventKind::ProtocolError(ProtocolError {
                    direction: Direction::Inbound,
                    reason: "invalid frame".to_string(),
                })),
                "protocol_error 50000->80 inbound:invalid frame",
            ),
        ]
    }

    fn demo_event() -> EventEnvelope {
        demo_event_with_origin(replay_origin())
    }

    fn demo_event_with_origin(origin: CaptureOrigin) -> EventEnvelope {
        demo_event_with_kind_and_origin(
            EventKind::HttpRequestHeaders(http_headers(
                Direction::Outbound,
                Some("GET"),
                Some("/chat"),
                None,
                None,
                "host",
                "example.test",
            )),
            origin,
        )
    }

    fn demo_event_with_kind(kind: EventKind) -> EventEnvelope {
        demo_event_with_kind_and_origin(kind, replay_origin())
    }

    fn demo_event_with_kind_and_origin(kind: EventKind, origin: CaptureOrigin) -> EventEnvelope {
        EventEnvelope::from_flow(
            Timestamp {
                monotonic_ns: 1,
                wall_time_unix_ns: 1,
            },
            demo_flow(),
            origin,
            "test",
            kind,
        )
    }

    fn http_headers(
        direction: Direction,
        method: Option<&str>,
        target: Option<&str>,
        status: Option<u16>,
        reason: Option<&str>,
        header_name: &str,
        header_value: &str,
    ) -> HttpHeaders {
        HttpHeaders {
            direction,
            stream_sequence: 1,
            method: method.map(ToOwned::to_owned),
            target: target.map(ToOwned::to_owned),
            status,
            reason: reason.map(ToOwned::to_owned),
            version: "HTTP/1.1".to_string(),
            headers: vec![(header_name.to_string(), header_value.to_string())],
        }
    }

    fn websocket_handoff_event() -> EventEnvelope {
        demo_event_with_kind(EventKind::WebSocketHandoff(WebSocketHandoff {
            direction: Direction::Inbound,
            stream_sequence: 1,
            target: Some("/chat".to_string()),
            subprotocol: Some("chat".to_string()),
            extensions: vec!["permessage-deflate".to_string()],
        }))
    }

    fn websocket_frame_event() -> EventEnvelope {
        demo_event_with_kind(EventKind::WebSocketFrame(WebSocketFrame {
            direction: Direction::Inbound,
            stream_sequence: 1,
            frame_sequence: 1,
            fin: true,
            rsv1: false,
            rsv2: false,
            rsv3: false,
            opcode: WebSocketOpcode::Text,
            payload_len: 5,
            masked: false,
            payload_fingerprint: vec![1, 2, 3],
        }))
    }

    fn websocket_message_event() -> EventEnvelope {
        websocket_message_event_with_payload(WebSocketMessageOpcode::Text, b"hello".to_vec())
    }

    fn websocket_message_event_with_payload(
        opcode: WebSocketMessageOpcode,
        payload: Vec<u8>,
    ) -> EventEnvelope {
        let payload_len =
            u64::try_from(payload.len()).expect("test payload length should fit into u64");
        demo_event_with_kind(EventKind::WebSocketMessage(WebSocketMessage {
            direction: Direction::Inbound,
            stream_sequence: 1,
            message_sequence: 1,
            first_frame_sequence: 1,
            final_frame_sequence: 2,
            opcode,
            payload_len,
            payload: payload.into(),
            payload_fingerprint: vec![1, 2, 3],
        }))
    }

    fn replay_origin() -> CaptureOrigin {
        CaptureOrigin::from_source(CaptureSource::Replay)
    }

    fn demo_flow() -> FlowContext {
        let process = ProcessIdentity {
            pid: 1,
            tgid: 1,
            start_time_ticks: 1,
            boot_id: "boot".to_string(),
            exe_path: "/usr/bin/demo".to_string(),
            cmdline_hash: "hash".to_string(),
            uid: 1000,
            gid: 1000,
            cgroup: None,
            systemd_service: None,
            container_id: None,
            runtime_hint: None,
        };
        let local = AddressPort {
            address: "127.0.0.1".to_string(),
            port: 50_000,
        };
        let remote = AddressPort {
            address: "127.0.0.1".to_string(),
            port: 80,
        };
        FlowContext {
            id: FlowIdentity::stable(&process, &local, &remote, TransportProtocol::Tcp, 1, None),
            process: ProcessContext {
                identity: process,
                name: "demo".to_string(),
                cmdline: vec!["demo".to_string()],
            },
            local,
            remote,
            protocol: TransportProtocol::Tcp,
            start_monotonic_ns: 1,
            socket_cookie: None,
            attribution_confidence: 100,
        }
    }
}

pub const EBPF_EVENTS_MAP_NAME: &str = "SSSA_EVENTS";
pub const EBPF_UPROBE_SECTION_NAME: &str = "uprobe";
pub const EBPF_URETPROBE_SECTION_NAME: &str = "uretprobe";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EbpfMapSpec {
    pub name: &'static str,
    pub kind: EbpfMapKind,
    pub key_size: u32,
    pub value_size: u32,
    pub max_entries: u32,
    pub map_flags: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EbpfMapKind {
    Ringbuf,
    Hash,
    LruHash,
    PerCpuArray,
}

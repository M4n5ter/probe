mod client;
mod filter;
mod http;
mod rows;
mod state;
mod text;
mod websocket;

pub(crate) use state::{
    TrafficDetailLoadRequest, TrafficDetailLoadResult, TrafficState, TrafficStatusKind,
    load_traffic_detail,
};

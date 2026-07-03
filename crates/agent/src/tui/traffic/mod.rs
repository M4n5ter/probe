mod client;
mod filter;
mod http;
mod rows;
mod state;

pub(crate) use state::{
    TrafficDetailLoadRequest, TrafficDetailLoadResult, TrafficState, TrafficStatusKind,
    load_traffic_detail,
};

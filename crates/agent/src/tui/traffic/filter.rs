use probe_core::EventType;

use crate::event_type_groups;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum TrafficEventFilter {
    Application,
    Http,
    WebSocket,
    Security,
    Diagnostics,
    All,
}

impl TrafficEventFilter {
    pub(super) fn label(self) -> &'static str {
        match self {
            Self::Application => "Parsed",
            Self::Http => "HTTP",
            Self::WebSocket => "WebSocket",
            Self::Security => "Security",
            Self::Diagnostics => "Diagnostics",
            Self::All => "All",
        }
    }

    pub(super) fn event_type_filter(self) -> TrafficEventTypeFilter {
        match self {
            Self::Application => {
                TrafficEventTypeFilter::Only(event_type_groups::parsed_application())
            }
            Self::Http => TrafficEventTypeFilter::Only(event_type_groups::http()),
            Self::WebSocket => TrafficEventTypeFilter::Only(event_type_groups::websocket()),
            Self::Security => TrafficEventTypeFilter::Only(event_type_groups::security()),
            Self::Diagnostics => TrafficEventTypeFilter::Only(event_type_groups::diagnostics()),
            Self::All => TrafficEventTypeFilter::All,
        }
    }

    pub(super) fn next(self) -> Self {
        match self {
            Self::Application => Self::Http,
            Self::Http => Self::WebSocket,
            Self::WebSocket => Self::Security,
            Self::Security => Self::Diagnostics,
            Self::Diagnostics => Self::All,
            Self::All => Self::Application,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum TrafficEventTypeFilter {
    All,
    Only(&'static [EventType]),
}

impl TrafficEventTypeFilter {
    pub(super) fn to_admin_event_types(self) -> Vec<EventType> {
        match self {
            Self::All => Vec::new(),
            Self::Only(event_types) => event_types.to_vec(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn filter_event_type_groups_cover_common_traffic_views() {
        assert_eq!(
            TrafficEventFilter::Application.event_type_filter(),
            TrafficEventTypeFilter::Only(event_type_groups::parsed_application())
        );
        assert_eq!(
            TrafficEventFilter::Http.event_type_filter(),
            TrafficEventTypeFilter::Only(event_type_groups::http())
        );
        assert_eq!(
            TrafficEventFilter::WebSocket.event_type_filter(),
            TrafficEventTypeFilter::Only(event_type_groups::websocket())
        );
        assert_eq!(
            TrafficEventFilter::Security.event_type_filter(),
            TrafficEventTypeFilter::Only(event_type_groups::security())
        );
        assert_eq!(
            TrafficEventFilter::Diagnostics.event_type_filter(),
            TrafficEventTypeFilter::Only(event_type_groups::diagnostics())
        );
        assert_eq!(
            TrafficEventFilter::All.event_type_filter(),
            TrafficEventTypeFilter::All
        );
        assert!(
            TrafficEventFilter::All
                .event_type_filter()
                .to_admin_event_types()
                .is_empty()
        );
    }

    #[test]
    fn filter_labels_match_cycle_order() {
        let labels = [
            TrafficEventFilter::Application,
            TrafficEventFilter::Application.next(),
            TrafficEventFilter::Http.next(),
            TrafficEventFilter::WebSocket.next(),
            TrafficEventFilter::Security.next(),
            TrafficEventFilter::Diagnostics.next(),
        ]
        .into_iter()
        .map(TrafficEventFilter::label)
        .collect::<Vec<_>>();

        assert_eq!(
            labels,
            vec![
                "Parsed",
                "HTTP",
                "WebSocket",
                "Security",
                "Diagnostics",
                "All"
            ]
        );
        assert_eq!(
            TrafficEventFilter::All.next(),
            TrafficEventFilter::Application
        );
    }
}

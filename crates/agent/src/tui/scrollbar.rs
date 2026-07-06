pub(crate) fn drag_position_to_scroll(offset: usize, height: usize, max_scroll: usize) -> usize {
    if max_scroll == 0 {
        return 0;
    }
    let track = height.saturating_sub(1).max(1);
    offset.min(track).saturating_mul(max_scroll) / track
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn drag_position_maps_track_edges_to_scroll_edges() {
        assert_eq!(drag_position_to_scroll(0, 10, 90), 0);
        assert_eq!(drag_position_to_scroll(9, 10, 90), 90);
        assert_eq!(drag_position_to_scroll(usize::MAX, 10, 90), 90);
    }

    #[test]
    fn drag_position_handles_short_tracks_and_empty_scroll_range() {
        assert_eq!(drag_position_to_scroll(3, 0, 90), 90);
        assert_eq!(drag_position_to_scroll(3, 10, 0), 0);
    }
}

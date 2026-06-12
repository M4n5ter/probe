use bytes::Bytes;

use super::super::tcp_seq;
use super::budget::PendingCount;
use super::{BUFFER_LIMIT_GAP_REASON, MAX_PENDING_BYTES, MAX_PENDING_SEGMENTS};

#[derive(Debug, Default)]
pub(super) struct DirectionStreamAssembler {
    next_sequence: Option<u32>,
    next_offset: u64,
    pending: PendingSegments,
    closed_at: Option<u32>,
}

impl DirectionStreamAssembler {
    pub(super) fn ingest(&mut self, sequence: u32, payload: &[u8]) -> Vec<StreamPiece> {
        let Some(bytes) = self.accepted_payload(sequence, payload) else {
            return Vec::new();
        };
        let mut pieces = Vec::new();
        match self.next_sequence {
            None => {
                self.emit_available(sequence, bytes, &mut pieces);
            }
            Some(expected) if !tcp_seq::after(sequence, expected) => {
                self.emit_available(sequence, bytes, &mut pieces);
                self.drain_contiguous(&mut pieces);
            }
            Some(_) => {
                self.insert_pending(sequence, bytes);
                self.flush_until_within_limits(&mut pieces);
            }
        }
        pieces
    }

    pub(super) fn flush_pending(&mut self, reason: &'static str) -> Vec<StreamPiece> {
        let mut pieces = Vec::new();
        loop {
            let pending_before = self.pending.len();
            self.drain_contiguous(&mut pieces);
            if self.pending.is_empty() {
                break;
            }
            self.force_gap_to_next_pending(reason, &mut pieces);
            if self.pending.len() == pending_before && pending_before != 0 {
                break;
            }
        }
        pieces
    }

    pub(super) fn close_at(&mut self, sequence: u32, reason: &'static str) -> Vec<StreamPiece> {
        let close_sequence = self.closed_at.unwrap_or(sequence);
        self.closed_at = Some(close_sequence);
        self.pending.trim_to_close(close_sequence);
        let mut pieces = Vec::new();
        self.force_gap_until_sequence(close_sequence, reason, &mut pieces);
        pieces
    }

    pub(super) fn force_gap_for_buffer_limit(&mut self, reason: &'static str) -> Vec<StreamPiece> {
        let mut pieces = Vec::new();
        self.force_gap_to_next_pending(reason, &mut pieces);
        pieces
    }

    pub(super) fn pending_count(&self) -> PendingCount {
        self.pending.count()
    }

    fn accepted_payload(&self, sequence: u32, payload: &[u8]) -> Option<Bytes> {
        if payload.is_empty() {
            return None;
        }
        let allowed_len = self.allowed_payload_len(sequence, payload.len());
        (allowed_len != 0).then(|| Bytes::copy_from_slice(&payload[..allowed_len]))
    }

    fn force_gap_until_sequence(
        &mut self,
        limit: u32,
        reason: &'static str,
        pieces: &mut Vec<StreamPiece>,
    ) {
        loop {
            self.drain_contiguous(pieces);
            let Some(expected) = self.next_sequence else {
                return;
            };
            if !tcp_seq::after(limit, expected) {
                return;
            }
            let Some(segment) = self.pending.remove_between(expected, limit) else {
                break;
            };
            self.force_gap_to_pending(segment, expected, reason, pieces);
        }
        self.drain_contiguous(pieces);
        self.force_gap_to_sequence(limit, reason, pieces);
    }

    fn force_gap_to_sequence(
        &mut self,
        sequence: u32,
        reason: &'static str,
        pieces: &mut Vec<StreamPiece>,
    ) {
        if let Some(expected) = self.next_sequence
            && tcp_seq::after(sequence, expected)
        {
            let missing_bytes = u64::from(tcp_seq::distance(expected, sequence));
            let next_offset = self.next_offset.saturating_add(missing_bytes);
            pieces.push(StreamPiece::Gap {
                expected_offset: self.next_offset,
                next_offset: Some(next_offset),
                reason,
            });
            self.next_sequence = Some(sequence);
            self.next_offset = next_offset;
        }
    }

    fn allowed_payload_len(&self, sequence: u32, payload_len: usize) -> usize {
        let Some(closed_at) = self.closed_at else {
            return payload_len;
        };
        if !tcp_seq::before(sequence, closed_at) {
            return 0;
        }
        payload_len.min(tcp_seq::distance_usize(sequence, closed_at))
    }

    fn flush_until_within_limits(&mut self, pieces: &mut Vec<StreamPiece>) {
        while self.pending.exceeds_stream_limit() {
            let pending_before = self.pending.len();
            self.force_gap_to_next_pending(BUFFER_LIMIT_GAP_REASON, pieces);
            if self.pending.len() == pending_before {
                break;
            }
        }
    }

    fn insert_pending(&mut self, sequence: u32, bytes: Bytes) {
        self.pending.insert(sequence, bytes);
    }

    fn drain_contiguous(&mut self, pieces: &mut Vec<StreamPiece>) {
        let Some(mut expected) = self.next_sequence else {
            return;
        };
        loop {
            if self.pending.remove_duplicate(expected).is_some() {
                continue;
            }
            let Some(segment) = self.pending.remove_reaching(expected) else {
                break;
            };
            self.emit_available(segment.sequence, segment.bytes, pieces);
            let Some(next) = self.next_sequence else {
                break;
            };
            expected = next;
        }
    }

    fn force_gap_to_next_pending(&mut self, reason: &'static str, pieces: &mut Vec<StreamPiece>) {
        self.drain_contiguous(pieces);
        if self.pending.is_empty() {
            return;
        }
        let Some(expected) = self.next_sequence else {
            return;
        };
        let Some(segment) = self.pending.remove_after(expected) else {
            return;
        };
        self.force_gap_to_pending(segment, expected, reason, pieces);
    }

    fn force_gap_to_pending(
        &mut self,
        segment: PendingSegment,
        expected: u32,
        reason: &'static str,
        pieces: &mut Vec<StreamPiece>,
    ) {
        let missing_bytes = u64::from(tcp_seq::distance(expected, segment.sequence));
        let next_offset = self.next_offset.saturating_add(missing_bytes);
        pieces.push(StreamPiece::Gap {
            expected_offset: self.next_offset,
            next_offset: Some(next_offset),
            reason,
        });
        self.next_sequence = Some(segment.sequence);
        self.next_offset = next_offset;
        self.emit_available(segment.sequence, segment.bytes, pieces);
        self.drain_contiguous(pieces);
    }

    fn emit_available(&mut self, sequence: u32, bytes: Bytes, pieces: &mut Vec<StreamPiece>) {
        let expected = self.next_sequence.unwrap_or(sequence);
        let skip = if tcp_seq::before(sequence, expected) {
            tcp_seq::distance_usize(sequence, expected)
        } else {
            0
        };
        if skip >= bytes.len() {
            self.next_sequence = Some(expected);
            return;
        }
        let emitted = bytes.slice(skip..);
        let stream_offset = self.next_offset;
        let emitted_len = emitted.len();
        self.next_sequence = Some(tcp_seq::advance(expected, emitted_len));
        self.next_offset = self.next_offset.saturating_add(emitted_len as u64);
        pieces.push(StreamPiece::Bytes {
            stream_offset,
            bytes: emitted,
        });
    }
}

#[derive(Debug, Clone)]
struct PendingSegment {
    sequence: u32,
    bytes: Bytes,
}

#[derive(Debug, Default)]
struct PendingSegments {
    segments: Vec<PendingSegment>,
    bytes: usize,
}

impl PendingSegments {
    fn count(&self) -> PendingCount {
        PendingCount {
            segments: self.segments.len(),
            bytes: self.bytes,
        }
    }

    fn len(&self) -> usize {
        self.segments.len()
    }

    fn is_empty(&self) -> bool {
        self.segments.is_empty()
    }

    fn exceeds_stream_limit(&self) -> bool {
        self.segments.len() > MAX_PENDING_SEGMENTS || self.bytes > MAX_PENDING_BYTES
    }

    fn insert(&mut self, sequence: u32, bytes: Bytes) {
        if let Some(existing) = self
            .segments
            .iter_mut()
            .find(|segment| segment.sequence == sequence)
        {
            if bytes.len() > existing.bytes.len() {
                self.bytes = self
                    .bytes
                    .saturating_sub(existing.bytes.len())
                    .saturating_add(bytes.len());
                existing.bytes = bytes;
            }
            return;
        }
        self.bytes = self.bytes.saturating_add(bytes.len());
        self.segments.push(PendingSegment { sequence, bytes });
    }

    fn remove_duplicate(&mut self, expected: u32) -> Option<PendingSegment> {
        self.remove_by(|segment| segment_is_duplicate(segment, expected))
    }

    fn remove_reaching(&mut self, expected: u32) -> Option<PendingSegment> {
        self.remove_by(|segment| segment_reaches_expected(segment, expected))
    }

    fn remove_after(&mut self, expected: u32) -> Option<PendingSegment> {
        let index = self
            .segments
            .iter()
            .enumerate()
            .filter(|(_, segment)| tcp_seq::after(segment.sequence, expected))
            .min_by_key(|(_, segment)| tcp_seq::distance(expected, segment.sequence))
            .map(|(index, _)| index)?;
        Some(self.remove_index(index))
    }

    fn remove_between(&mut self, expected: u32, limit: u32) -> Option<PendingSegment> {
        let index = self
            .segments
            .iter()
            .enumerate()
            .filter(|(_, segment)| {
                tcp_seq::after(segment.sequence, expected)
                    && tcp_seq::before(segment.sequence, limit)
            })
            .min_by_key(|(_, segment)| tcp_seq::distance(expected, segment.sequence))
            .map(|(index, _)| index)?;
        Some(self.remove_index(index))
    }

    fn trim_to_close(&mut self, close_sequence: u32) {
        let mut retained = Vec::with_capacity(self.segments.len());
        let mut retained_bytes = 0;
        for mut segment in self.segments.drain(..) {
            if !tcp_seq::before(segment.sequence, close_sequence) {
                continue;
            }
            let allowed_len = segment
                .bytes
                .len()
                .min(tcp_seq::distance_usize(segment.sequence, close_sequence));
            if allowed_len == 0 {
                continue;
            }
            if allowed_len < segment.bytes.len() {
                segment.bytes = segment.bytes.slice(..allowed_len);
            }
            retained_bytes += segment.bytes.len();
            retained.push(segment);
        }
        self.segments = retained;
        self.bytes = retained_bytes;
    }

    fn remove_by(&mut self, predicate: impl Fn(&PendingSegment) -> bool) -> Option<PendingSegment> {
        let index = self.segments.iter().position(predicate)?;
        Some(self.remove_index(index))
    }

    fn remove_index(&mut self, index: usize) -> PendingSegment {
        let segment = self.segments.swap_remove(index);
        self.bytes = self.bytes.saturating_sub(segment.bytes.len());
        segment
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum StreamPiece {
    Bytes {
        stream_offset: u64,
        bytes: Bytes,
    },
    Gap {
        expected_offset: u64,
        next_offset: Option<u64>,
        reason: &'static str,
    },
}

fn segment_is_duplicate(segment: &PendingSegment, expected: u32) -> bool {
    !tcp_seq::after(segment.sequence, expected) && !tcp_seq::after(segment_end(segment), expected)
}

fn segment_reaches_expected(segment: &PendingSegment, expected: u32) -> bool {
    !tcp_seq::after(segment.sequence, expected) && tcp_seq::after(segment_end(segment), expected)
}

fn segment_end(segment: &PendingSegment) -> u32 {
    tcp_seq::advance(segment.sequence, segment.bytes.len())
}

#[cfg(test)]
mod tests {
    use super::super::FLOW_CLOSE_GAP_REASON;
    use super::*;

    #[test]
    fn contiguous_segments_advance_offsets() {
        let mut stream = DirectionStreamAssembler::default();

        let pieces = [
            stream.ingest(100, b"GET "),
            stream.ingest(104, b"/ HTTP/1.1\r\n\r\n"),
        ]
        .into_iter()
        .flatten()
        .collect::<Vec<_>>();

        assert_eq!(
            pieces,
            vec![
                bytes_piece(0, b"GET "),
                bytes_piece(4, b"/ HTTP/1.1\r\n\r\n"),
            ]
        );
    }

    #[test]
    fn duplicate_retransmission_emits_no_bytes() {
        let mut stream = DirectionStreamAssembler::default();

        assert_eq!(stream.ingest(100, b"GET "), vec![bytes_piece(0, b"GET ")]);
        assert!(stream.ingest(100, b"GET ").is_empty());
    }

    #[test]
    fn partial_retransmission_trims_emitted_prefix() {
        let mut stream = DirectionStreamAssembler::default();

        assert_eq!(stream.ingest(100, b"GET "), vec![bytes_piece(0, b"GET ")]);
        assert_eq!(stream.ingest(102, b"T /"), vec![bytes_piece(4, b"/")]);
    }

    #[test]
    fn out_of_order_segment_waits_for_missing_bytes() {
        let mut stream = DirectionStreamAssembler::default();

        assert_eq!(stream.ingest(100, b"GET "), vec![bytes_piece(0, b"GET ")]);
        assert!(stream.ingest(106, b"HTTP").is_empty());

        assert_eq!(
            stream.ingest(104, b"/ "),
            vec![bytes_piece(4, b"/ "), bytes_piece(6, b"HTTP")]
        );
    }

    #[test]
    fn sequence_wraparound_keeps_stream_offsets_monotonic() {
        let mut stream = DirectionStreamAssembler::default();

        assert_eq!(
            stream.ingest(u32::MAX - 1, b"ab"),
            vec![bytes_piece(0, b"ab")]
        );
        assert_eq!(stream.ingest(0, b"cd"), vec![bytes_piece(2, b"cd")]);

        let mut reordered = DirectionStreamAssembler::default();
        assert_eq!(
            reordered.ingest(u32::MAX - 1, b"a"),
            vec![bytes_piece(0, b"a")]
        );
        assert!(reordered.ingest(1, b"c").is_empty());
        assert_eq!(
            reordered.ingest(u32::MAX, b"bb"),
            vec![bytes_piece(1, b"bb"), bytes_piece(3, b"c")]
        );

        let mut closing = DirectionStreamAssembler::default();
        assert_eq!(
            closing.ingest(u32::MAX - 1, b"a"),
            vec![bytes_piece(0, b"a")]
        );
        assert_eq!(
            closing.close_at(1, FLOW_CLOSE_GAP_REASON),
            vec![StreamPiece::Gap {
                expected_offset: 1,
                next_offset: Some(3),
                reason: FLOW_CLOSE_GAP_REASON,
            }]
        );
    }

    #[test]
    fn flush_pending_emits_explicit_gap_before_unresolved_payload() {
        let mut stream = DirectionStreamAssembler::default();

        assert_eq!(stream.ingest(100, b"GET "), vec![bytes_piece(0, b"GET ")]);
        assert!(stream.ingest(108, b"HTTP").is_empty());

        assert_eq!(
            stream.flush_pending(FLOW_CLOSE_GAP_REASON),
            vec![
                StreamPiece::Gap {
                    expected_offset: 4,
                    next_offset: Some(8),
                    reason: FLOW_CLOSE_GAP_REASON,
                },
                bytes_piece(8, b"HTTP"),
            ]
        );
    }

    #[test]
    fn close_at_sequence_emits_tail_gap_without_pending_payload() {
        let mut stream = DirectionStreamAssembler::default();

        assert_eq!(stream.ingest(100, b"GET "), vec![bytes_piece(0, b"GET ")]);

        assert_eq!(
            stream.close_at(108, FLOW_CLOSE_GAP_REASON),
            vec![StreamPiece::Gap {
                expected_offset: 4,
                next_offset: Some(8),
                reason: FLOW_CLOSE_GAP_REASON,
            }]
        );
    }

    #[test]
    fn close_at_sequence_discards_pending_payload_after_close_boundary() {
        let mut stream = DirectionStreamAssembler::default();

        assert_eq!(stream.ingest(100, b"GET "), vec![bytes_piece(0, b"GET ")]);
        assert!(stream.ingest(120, b"BAD").is_empty());

        assert_eq!(
            stream.close_at(108, FLOW_CLOSE_GAP_REASON),
            vec![StreamPiece::Gap {
                expected_offset: 4,
                next_offset: Some(8),
                reason: FLOW_CLOSE_GAP_REASON,
            }]
        );
        assert_eq!(stream.pending_count(), PendingCount::default());
        assert!(stream.flush_pending(FLOW_CLOSE_GAP_REASON).is_empty());
        assert!(stream.ingest(120, b"BAD").is_empty());
    }

    #[test]
    fn close_at_sequence_trims_pending_payload_crossing_close_boundary() {
        let mut stream = DirectionStreamAssembler::default();

        assert_eq!(stream.ingest(100, b"GET "), vec![bytes_piece(0, b"GET ")]);
        assert!(stream.ingest(108, b"HTTPBAD").is_empty());

        assert_eq!(
            stream.close_at(112, FLOW_CLOSE_GAP_REASON),
            vec![
                StreamPiece::Gap {
                    expected_offset: 4,
                    next_offset: Some(8),
                    reason: FLOW_CLOSE_GAP_REASON,
                },
                bytes_piece(8, b"HTTP"),
            ]
        );
        assert_eq!(stream.pending_count(), PendingCount::default());
    }

    #[test]
    fn closed_direction_ignores_payload_starting_at_close_boundary() {
        let mut stream = DirectionStreamAssembler::default();

        assert_eq!(stream.ingest(100, b"GET "), vec![bytes_piece(0, b"GET ")]);
        assert!(stream.close_at(104, FLOW_CLOSE_GAP_REASON).is_empty());

        assert!(stream.ingest(104, b"BAD").is_empty());
        assert!(stream.ingest(120, b"BAD").is_empty());
    }

    #[test]
    fn flush_pending_emits_multiple_gaps_in_stream_order() {
        let mut stream = DirectionStreamAssembler::default();

        assert_eq!(stream.ingest(100, b"GET "), vec![bytes_piece(0, b"GET ")]);
        assert!(stream.ingest(108, b"AA").is_empty());
        assert!(stream.ingest(114, b"BB").is_empty());

        assert_eq!(
            stream.flush_pending(FLOW_CLOSE_GAP_REASON),
            vec![
                StreamPiece::Gap {
                    expected_offset: 4,
                    next_offset: Some(8),
                    reason: FLOW_CLOSE_GAP_REASON,
                },
                bytes_piece(8, b"AA"),
                StreamPiece::Gap {
                    expected_offset: 10,
                    next_offset: Some(14),
                    reason: FLOW_CLOSE_GAP_REASON,
                },
                bytes_piece(14, b"BB"),
            ]
        );
    }

    #[test]
    fn buffer_pressure_emits_gap_and_pending_payload() {
        let mut stream = DirectionStreamAssembler::default();

        assert_eq!(stream.ingest(100, b"GET "), vec![bytes_piece(0, b"GET ")]);
        for index in 0..MAX_PENDING_SEGMENTS {
            assert!(stream.ingest(200 + index as u32 * 10, b"x").is_empty());
        }

        assert_eq!(
            stream.ingest(900, b"z"),
            vec![
                StreamPiece::Gap {
                    expected_offset: 4,
                    next_offset: Some(100),
                    reason: BUFFER_LIMIT_GAP_REASON,
                },
                bytes_piece(100, b"x"),
            ]
        );
    }

    fn bytes_piece(stream_offset: u64, bytes: &[u8]) -> StreamPiece {
        StreamPiece::Bytes {
            stream_offset,
            bytes: Bytes::copy_from_slice(bytes),
        }
    }
}

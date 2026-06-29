use ebpf_abi::{EBPF_SOCKET_PAYLOAD_ALLOW_READ, EBPF_SOCKET_PAYLOAD_ALLOW_WRITE};
use probe_core::Direction;

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(super) struct PayloadDirections {
    mask: u8,
}

impl PayloadDirections {
    pub(super) fn empty() -> Self {
        Self { mask: 0 }
    }

    #[cfg(test)]
    pub(super) fn from_directions(directions: impl IntoIterator<Item = Direction>) -> Self {
        let mut payload_directions = Self::empty();
        for direction in directions {
            payload_directions.insert(direction);
        }
        payload_directions
    }

    pub(super) fn insert(&mut self, direction: Direction) {
        self.mask |= direction_bit(direction);
    }

    pub(super) fn allows(self, direction: Direction) -> bool {
        self.mask & direction_bit(direction) != 0
    }

    pub(super) fn directions(self) -> impl Iterator<Item = Direction> {
        [Direction::Inbound, Direction::Outbound]
            .into_iter()
            .filter(move |direction| self.allows(*direction))
    }

    pub(super) fn is_empty(self) -> bool {
        self.mask == 0
    }

    pub(super) fn to_abi_mask(self) -> u8 {
        self.mask
    }
}

fn direction_bit(direction: Direction) -> u8 {
    match direction {
        Direction::Inbound => EBPF_SOCKET_PAYLOAD_ALLOW_READ,
        Direction::Outbound => EBPF_SOCKET_PAYLOAD_ALLOW_WRITE,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn payload_directions_map_capture_directions_to_abi_bits() {
        let write_only = PayloadDirections::from_directions([Direction::Outbound]);
        assert!(write_only.allows(Direction::Outbound));
        assert!(!write_only.allows(Direction::Inbound));
        assert_eq!(write_only.to_abi_mask(), EBPF_SOCKET_PAYLOAD_ALLOW_WRITE);

        let read_only = PayloadDirections::from_directions([Direction::Inbound]);
        assert!(read_only.allows(Direction::Inbound));
        assert!(!read_only.allows(Direction::Outbound));
        assert_eq!(read_only.to_abi_mask(), EBPF_SOCKET_PAYLOAD_ALLOW_READ);

        let both = PayloadDirections::from_directions([Direction::Inbound, Direction::Outbound]);
        assert!(both.allows(Direction::Inbound));
        assert!(both.allows(Direction::Outbound));
        assert_eq!(
            both.to_abi_mask(),
            EBPF_SOCKET_PAYLOAD_ALLOW_READ | EBPF_SOCKET_PAYLOAD_ALLOW_WRITE
        );
    }
}

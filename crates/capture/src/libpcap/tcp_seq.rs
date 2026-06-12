pub(super) fn before(left: u32, right: u32) -> bool {
    (left.wrapping_sub(right) as i32) < 0
}

pub(super) fn after(left: u32, right: u32) -> bool {
    before(right, left)
}

pub(super) fn distance(from: u32, to: u32) -> u32 {
    to.wrapping_sub(from)
}

pub(super) fn distance_usize(from: u32, to: u32) -> usize {
    distance(from, to) as usize
}

pub(super) fn advance(sequence: u32, bytes: usize) -> u32 {
    sequence.wrapping_add(bytes as u32)
}

//! Layer-space allocation for one plan: proportional to the offered
//! shard RAM with zero-capacity slots skipped. The last contributing
//! slot takes the remainder so the union of ranges always covers
//! `[0, layers)` exactly.
//!
//! The proportional share uses 128-bit integer arithmetic with
//! round-half-up: every node computes the identical placement for the
//! same offers regardless of architecture or floating-point rounding,
//! which keeps the signed launch frames consistent across the network.

/// Split `layers` across capacity slots proportionally to `caps`.
/// Slots with zero capacity never absorb part of the layer space, and
/// a slot whose rounded share cannot hold a single layer is skipped.
pub(crate) fn split_layers(layers: u32, caps: &[u64]) -> Vec<(u32, u32)> {
    let total: u128 = caps.iter().map(|cap| *cap as u128).sum();
    let last_contributing = caps.iter().rposition(|cap| *cap > 0);
    let mut out = Vec::new();
    let mut from = 0u32;
    for (index, cap) in caps.iter().enumerate() {
        if from >= layers || *cap == 0 {
            continue;
        }
        let to = if Some(index) == last_contributing {
            layers
        } else {
            // Round-half-up share: (cap * layers + total / 2) / total.
            let share = (((*cap as u128) * layers as u128 + total / 2) / total) as u32;
            if share == 0 {
                continue;
            }
            from.saturating_add(share)
                .clamp(from.saturating_add(1), layers)
        };
        out.push((from, to));
        from = to;
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn equal_caps_split_evenly_and_cover_every_layer() {
        assert_eq!(split_layers(10, &[100, 100]), vec![(0, 5), (5, 10)]);
    }

    #[test]
    fn zero_capacity_slots_are_skipped() {
        assert_eq!(split_layers(9, &[100, 0, 100]), vec![(0, 5), (5, 9)]);
    }

    #[test]
    fn all_zero_pool_places_nothing() {
        assert!(split_layers(10, &[0, 0]).is_empty());
    }

    #[test]
    fn the_last_contributing_slot_takes_the_remainder() {
        assert_eq!(split_layers(7, &[3, 1]), vec![(0, 5), (5, 7)]);
    }

    #[test]
    fn one_slot_takes_everything() {
        assert_eq!(split_layers(80, &[4096]), vec![(0, 80)]);
    }
}

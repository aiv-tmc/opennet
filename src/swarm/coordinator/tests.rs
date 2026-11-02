//! Regression tests for layer placement: proportional shares, skipped
//! zero-capacity slots and exact coverage of the layer space.

use super::split_layers;

#[test]
fn proportional_split() {
    assert_eq!(split_layers(10, &[100, 50]), vec![(0, 7), (7, 10)]);
}

#[test]
fn single_shard_takes_all() {
    assert_eq!(split_layers(5, &[7]), vec![(0, 5)]);
}

#[test]
fn zero_capacity_slots_are_skipped() {
    assert_eq!(split_layers(4, &[0, 10, 0]), vec![(0, 4)]);
    assert_eq!(split_layers(10, &[50, 0, 50]), vec![(0, 5), (5, 10)]);
}

#[test]
fn all_zero_pool_places_nothing() {
    // With no capacity anywhere there is no placement at all; the
    // coordinator rejects the plan before launching.
    assert!(split_layers(3, &[0, 0, 0]).is_empty());
}

#[test]
fn ranges_cover_the_layer_space() {
    let ranges = split_layers(3, &[1, 1, 1]);
    assert_eq!(ranges.first().map(|range| range.0), Some(0));
    assert_eq!(ranges.last().map(|range| range.1), Some(3));
    for (from, to) in &ranges {
        assert!(from < to, "empty range in {ranges:?}");
    }
}

#[test]
fn huge_capacity_does_not_overflow() {
    // Shares are computed in 128-bit arithmetic: capacities near u64
    // maximum multiplied by the layer count must not wrap or panic.
    let ranges = split_layers(u32::MAX, &[u64::MAX, u64::MAX]);
    assert_eq!(ranges.first().map(|range| range.0), Some(0));
    assert_eq!(ranges.last().map(|range| range.1), Some(u32::MAX));
}

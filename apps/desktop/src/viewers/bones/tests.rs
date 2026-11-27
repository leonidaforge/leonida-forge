//! Hierarchy, collapse and filter tests for the bone panel. Synthetic bones.

use glam::{Quat, Vec3};

use super::*;
use lforge_scene::Bone;

fn bone(index: usize, parent: Option<usize>, name: Option<&str>, identifier: u32) -> Bone {
    Bone {
        name: name.map(str::to_string),
        index,
        parent,
        identifier: Some(identifier),
        identifier16: Some(index as u16),
        local_translation: Vec3::ZERO,
        local_rotation: Quat::IDENTITY,
        local_scale: Vec3::ONE,
        model_rotation: Quat::IDENTITY,
        model_position: Vec3::ZERO,
        inverse_bind: None,
    }
}

/// Root -> two children; child 1 has one child.
fn skeleton() -> Skeleton {
    Skeleton {
        bones: vec![
            bone(0, None, Some("Root"), 0xA0),
            bone(1, Some(0), Some("Left"), 0xA1),
            bone(2, Some(0), Some("Right"), 0xB2),
            bone(3, Some(2), Some("Tip"), 0xC3),
        ],
        roots: vec![0],
        max_depth: 3,
    }
}

#[test]
fn rows_follow_the_stored_order_with_their_depth() {
    let rows = BonePanel::new().rows(&skeleton(), "");
    let seen: Vec<(usize, usize)> = rows.iter().map(|row| (row.index, row.depth)).collect();
    assert_eq!(seen, vec![(0, 0), (1, 1), (2, 1), (3, 2)]);
    assert!(rows[0].has_children);
    assert!(!rows[3].has_children);
}

#[test]
fn collapsing_a_bone_hides_its_subtree_only() {
    let mut panel = BonePanel::new();
    panel.toggle(2);
    let rows = panel.rows(&skeleton(), "");
    let seen: Vec<usize> = rows.iter().map(|row| row.index).collect();
    assert_eq!(seen, vec![0, 1, 2]);
    assert!(rows[2].collapsed);
}

#[test]
fn a_filter_shows_a_match_and_its_ancestors() {
    let panel = BonePanel::new();
    let rows = panel.rows(&skeleton(), "tip");
    let seen: Vec<usize> = rows.iter().map(|row| row.index).collect();
    assert_eq!(seen, vec![0, 2, 3]);
}

#[test]
fn a_filter_matches_an_index_or_identifier() {
    let panel = BonePanel::new();
    let rows = panel.rows(&skeleton(), "2");
    let seen: Vec<usize> = rows.iter().map(|row| row.index).collect();
    assert!(seen.contains(&2));

    let rows = panel.rows(&skeleton(), "c3");
    assert!(rows.iter().any(|row| row.index == 3));
}

#[test]
fn filtering_ignores_a_stale_collapse() {
    let mut panel = BonePanel::new();
    panel.toggle(2);
    let rows = panel.rows(&skeleton(), "tip");
    assert!(rows.iter().any(|row| row.index == 3));
}

#[test]
fn a_selected_bone_reports_unavailable_values_as_unavailable() {
    let mut panel = BonePanel::new();
    panel.select(Some(3));
    let rows = panel.metadata(&skeleton(), &[]);
    let value = |key: &str| {
        rows.iter()
            .find(|(name, _)| name == key)
            .map(|(_, value)| value.clone())
            .expect("metadata row")
    };
    assert_eq!(value("Index"), "3");
    assert_eq!(value("Parent"), "2");
    assert_eq!(value("32-bit key"), "0x000000c3");
    assert_eq!(value("Inverse bind"), "unavailable");
    assert_eq!(value("Meshes"), "not established");
}

#[test]
fn two_bones_with_the_same_name_keep_distinct_selections() {
    let skeleton = Skeleton {
        bones: vec![
            bone(0, None, Some("Same"), 1),
            bone(1, Some(0), Some("Same"), 2),
        ],
        roots: vec![0],
        max_depth: 2,
    };
    let mut panel = BonePanel::new();
    panel.select(Some(1));
    assert_eq!(panel.selected(), Some(1));
    let rows = panel.metadata(&skeleton, &[]);
    assert_eq!(rows[0].1, "Same");
    assert_eq!(
        rows.iter()
            .find(|(key, _)| key == "Index")
            .map(|(_, value)| value.as_str()),
        Some("1")
    );
}

#[test]
fn a_large_skeleton_lists_in_one_ordered_pass() {
    let bones: Vec<Bone> = (0..2000)
        .map(|index| {
            bone(
                index,
                if index == 0 { None } else { Some(index - 1) },
                None,
                index as u32,
            )
        })
        .collect();
    let skeleton = Skeleton {
        bones,
        roots: vec![0],
        max_depth: 2000,
    };
    let rows = BonePanel::new().rows(&skeleton, "");
    assert_eq!(rows.len(), 2000);
    assert_eq!(rows[1999].depth, 1999);
    assert_eq!(rows[1999].label, "bone 1999");
}

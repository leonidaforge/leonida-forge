//! Bone hierarchy presentation shared by the model and dictionary viewers.
//!
//! The panel only reads a decoded [`lforge_scene::Skeleton`]; it never reads a
//! resource. Collapse state and the selection are indices into the skeleton's
//! bone array, so a selection stays unambiguous when two bones share a name.

use std::collections::BTreeSet;

use lforge_scene::{Bone, Skeleton};

/// One line of the hierarchy.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BoneRow {
    pub index: usize,
    pub depth: usize,
    pub has_children: bool,
    pub collapsed: bool,
    pub label: String,
    pub detail: String,
}

/// Collapse state and the selected bone of one viewer.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct BonePanel {
    collapsed: BTreeSet<usize>,
    selected: Option<usize>,
}

impl BonePanel {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn selected(&self) -> Option<usize> {
        self.selected
    }

    pub fn select(&mut self, index: Option<usize>) {
        self.selected = index;
    }

    pub fn toggle(&mut self, index: usize) {
        if !self.collapsed.remove(&index) {
            self.collapsed.insert(index);
        }
    }

    /// Forgets the selection and every collapsed row. A new member or a new
    /// model calls this so no bone from the previous resource survives.
    pub fn reset(&mut self) {
        self.collapsed.clear();
        self.selected = None;
    }

    /// The rows to show, in stored bone order.
    ///
    /// With an empty filter a collapsed bone hides its whole subtree. A filter
    /// matches a bone's name, its index or its stored identifier, and shows
    /// every match together with the ancestors that place it in the hierarchy
    /// and the descendants that belong to it. Filtering ignores collapse so a
    /// match is never hidden by a stale toggle.
    pub fn rows(&self, skeleton: &Skeleton, filter: &str) -> Vec<BoneRow> {
        let filter = filter.trim().to_ascii_lowercase();
        let count = skeleton.bones.len();
        let mut children = vec![0usize; count];
        for bone in &skeleton.bones {
            if let Some(parent) = bone.parent
                && let Some(entry) = children.get_mut(parent)
            {
                *entry += 1;
            }
        }
        let depth: Vec<usize> = skeleton
            .bones
            .iter()
            .map(|bone| {
                let mut depth = 0usize;
                let mut current = bone.parent;
                while let Some(parent) = current {
                    depth += 1;
                    if depth > count {
                        break;
                    }
                    current = skeleton.bones.get(parent).and_then(|bone| bone.parent);
                }
                depth
            })
            .collect();

        let visible: Vec<bool> = if filter.is_empty() {
            (0..count)
                .map(|index| {
                    !ancestors(index, skeleton).any(|parent| self.collapsed.contains(&parent))
                })
                .collect()
        } else {
            let matches: Vec<bool> = skeleton
                .bones
                .iter()
                .map(|bone| bone_matches(bone, &filter))
                .collect();
            (0..count)
                .map(|index| {
                    matches[index]
                        || ancestors(index, skeleton).any(|parent| matches[parent])
                        || descendants(index, skeleton).any(|child| matches[child])
                })
                .collect()
        };

        skeleton
            .bones
            .iter()
            .enumerate()
            .filter(|(index, _)| visible[*index])
            .map(|(index, bone)| BoneRow {
                index,
                depth: depth[index],
                has_children: children[index] > 0,
                collapsed: self.collapsed.contains(&index),
                label: bone.name.clone().unwrap_or_else(|| format!("bone {index}")),
                detail: format!(
                    "#{index} · parent {} · {}{}",
                    bone.parent
                        .map_or_else(|| "root".to_string(), |parent| parent.to_string()),
                    bone.identifier
                        .map_or_else(|| "no 32-bit key".to_string(), |key| format!("{key:#010x}")),
                    match bone.identifier16 {
                        Some(key) => format!(" · {key:#06x}"),
                        None => String::new(),
                    }
                ),
            })
            .collect()
    }

    /// The metadata rows of the selected bone, in display order. A value the
    /// resource does not establish is reported as unavailable.
    pub fn metadata(
        &self,
        skeleton: &Skeleton,
        associations: &[lforge_scene::PrimitiveBones],
    ) -> Vec<(String, String)> {
        let Some(bone) = self.selected.and_then(|index| skeleton.bones.get(index)) else {
            return Vec::new();
        };
        let vector = |value: &[f32]| {
            value
                .iter()
                .map(|value| format!("{value:.4}"))
                .collect::<Vec<_>>()
                .join(", ")
        };
        let rotation = [
            bone.local_rotation.x,
            bone.local_rotation.y,
            bone.local_rotation.z,
            bone.local_rotation.w,
        ];
        let position = bone.model_position.to_array();
        let local = bone.local_translation.to_array();
        let scale = bone.local_scale.to_array();
        let mut rows = vec![
            (
                "Name".to_string(),
                bone.name.clone().unwrap_or_else(|| "unavailable".into()),
            ),
            ("Index".to_string(), bone.index.to_string()),
            (
                "32-bit key".to_string(),
                bone.identifier
                    .map_or_else(|| "unavailable".to_string(), |key| format!("{key:#010x}")),
            ),
            (
                "16-bit key".to_string(),
                bone.identifier16
                    .map_or_else(|| "unavailable".to_string(), |key| format!("{key:#06x}")),
            ),
            (
                "Parent".to_string(),
                bone.parent
                    .map_or_else(|| "none (root)".to_string(), |parent| parent.to_string()),
            ),
            ("Local translation".to_string(), vector(&local)),
            ("Local rotation".to_string(), vector(&rotation)),
            ("Local scale".to_string(), vector(&scale)),
            ("Model position".to_string(), vector(&position)),
            (
                "Inverse bind".to_string(),
                if bone.inverse_bind.is_some() {
                    "validated".to_string()
                } else {
                    "unavailable".to_string()
                },
            ),
        ];
        let associated: Vec<String> = associations
            .iter()
            .filter(|association| association.bones.contains(&bone.index))
            .map(|association| {
                format!(
                    "mesh {} primitive {}",
                    association.mesh, association.primitive
                )
            })
            .collect();
        rows.push((
            "Meshes".to_string(),
            if associated.is_empty() {
                "not established".to_string()
            } else {
                associated.join(", ")
            },
        ));
        rows
    }
}

fn bone_matches(bone: &Bone, filter: &str) -> bool {
    if let Some(name) = &bone.name
        && name.to_ascii_lowercase().contains(filter)
    {
        return true;
    }
    if bone.index.to_string() == filter {
        return true;
    }
    if let Some(identifier) = bone.identifier {
        let hex = format!("{identifier:08x}");
        if hex.contains(filter) || format!("#{identifier}") == filter {
            return true;
        }
    }
    if let Some(identifier) = bone.identifier16 {
        let hex = format!("{identifier:04x}");
        if hex.contains(filter) {
            return true;
        }
    }
    false
}

fn ancestors(index: usize, skeleton: &Skeleton) -> impl Iterator<Item = usize> + '_ {
    let mut current = skeleton.bones.get(index).and_then(|bone| bone.parent);
    let mut steps = 0usize;
    std::iter::from_fn(move || {
        let parent = current?;
        steps += 1;
        if steps > skeleton.bones.len() {
            return None;
        }
        current = skeleton.bones.get(parent).and_then(|bone| bone.parent);
        Some(parent)
    })
}

fn descendants(index: usize, skeleton: &Skeleton) -> impl Iterator<Item = usize> + '_ {
    let mut stack = vec![index];
    let mut found = Vec::new();
    let mut steps = 0usize;
    while let Some(current) = stack.pop() {
        for (child, bone) in skeleton.bones.iter().enumerate() {
            if bone.parent == Some(current) {
                steps += 1;
                if steps > skeleton.bones.len() {
                    break;
                }
                found.push(child);
                stack.push(child);
            }
        }
    }
    found.into_iter()
}

#[cfg(test)]
mod tests;

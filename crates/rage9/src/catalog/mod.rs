//! Structured catalog metadata from the XML documents GTA VI stores in RPF9
//! rows.
//!
//! The extractor reads a decoded document and reports *observations*: one
//! named item per source element, with the field values the document stores and
//! the XML path they came from. It assigns no unit to a number unless the
//! element name states one, and it never fills a missing field. Normalising,
//! merging and assigning catalog identities belong to the exporter.
//!
//! A root is recognised by its element name. The names below are the document
//! roots the research observed in readable `common.rpf` rows; an unlisted root
//! is reported as unrecognised, not guessed.

use std::collections::BTreeMap;

use roxmltree::{Document, Node};
use serde::Serialize;

#[cfg(test)]
mod tests;

/// The catalog categories a record can belong to.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Category {
    Peds,
    Weapons,
    Vehicles,
    Clothing,
}

impl Category {
    pub fn name(self) -> &'static str {
        match self {
            Category::Peds => "peds",
            Category::Weapons => "weapons",
            Category::Vehicles => "vehicles",
            Category::Clothing => "clothing",
        }
    }
}

/// A value the document stores. Serialised as the JSON value itself.
#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(untagged)]
pub enum Value {
    Text(String),
    Number(f64),
    Boolean(bool),
    TextList(Vec<String>),
    NumberList(Vec<f64>),
}

/// One field with its unit and how it was read.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct Field {
    pub value: Value,
    /// `None` when the document states no unit. Never a guessed unit.
    pub unit: Option<String>,
    /// `source_number`, `source_boolean`, `source_text`, `meters`, or
    /// `source_text_non_finite`.
    pub semantics: String,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Observation {
    pub category: Category,
    pub entity_type: String,
    pub internal_name: String,
    /// Only set when the document stores a separate display name. An internal
    /// identifier is not promoted to a display name here.
    pub display_name: Option<String>,
    pub fields: BTreeMap<String, Field>,
    pub metadata: BTreeMap<String, Value>,
    /// The element path inside the document, built from tag names and the
    /// `key` attributes that identify an item.
    pub source_path: String,
}

impl Observation {
    fn new(
        category: Category,
        entity_type: &str,
        internal_name: impl Into<String>,
        source_path: String,
    ) -> Self {
        Self {
            category,
            entity_type: entity_type.to_string(),
            internal_name: internal_name.into(),
            display_name: None,
            fields: BTreeMap::new(),
            metadata: BTreeMap::new(),
            source_path,
        }
    }

    fn number(&mut self, key: impl Into<String>, value: f64, unit: Option<&str>) {
        let finite = value.is_finite();
        self.fields.insert(
            key.into(),
            Field {
                value: if finite {
                    Value::Number(value)
                } else {
                    Value::Text(if value.is_sign_negative() {
                        "-inf".to_string()
                    } else {
                        "inf".to_string()
                    })
                },
                unit: unit.map(str::to_string),
                semantics: if finite {
                    if unit.is_some() {
                        "meters"
                    } else {
                        "source_number"
                    }
                } else {
                    "source_text_non_finite"
                }
                .to_string(),
            },
        );
    }

    fn text(&mut self, key: impl Into<String>, value: impl Into<String>) {
        self.fields.insert(
            key.into(),
            Field {
                value: Value::Text(value.into()),
                unit: None,
                semantics: "source_text".to_string(),
            },
        );
    }

    fn boolean(&mut self, key: impl Into<String>, value: bool) {
        self.fields.insert(
            key.into(),
            Field {
                value: Value::Boolean(value),
                unit: None,
                semantics: "source_boolean".to_string(),
            },
        );
    }

    fn text_list(&mut self, key: impl Into<String>, values: Vec<String>) {
        if values.is_empty() {
            return;
        }
        self.fields.insert(
            key.into(),
            Field {
                value: Value::TextList(values),
                unit: None,
                semantics: "source_text".to_string(),
            },
        );
    }

    fn number_list(&mut self, key: impl Into<String>, values: Vec<f64>, unit: Option<&str>) {
        if values.is_empty() {
            return;
        }
        self.fields.insert(
            key.into(),
            Field {
                value: Value::NumberList(values),
                unit: unit.map(str::to_string),
                semantics: if unit.is_some() {
                    "meters"
                } else {
                    "source_number"
                }
                .to_string(),
            },
        );
    }

    fn meta_text(&mut self, key: impl Into<String>, value: impl Into<String>) {
        self.metadata.insert(key.into(), Value::Text(value.into()));
    }
}

/// The result of reading one document.
#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DocumentExtraction {
    pub root: String,
    pub recognized: bool,
    pub observations: Vec<Observation>,
    pub issues: Vec<String>,
}

/// Roots the extractor knows.
pub const RECOGNIZED_ROOTS: [&str; 10] = [
    "CVehiclePerformanceMaps",
    "CVehicleBaseRatingsAndEstimatesMap",
    "CVehicleBoneOffsetsArray",
    "CVehicleDistantLightData",
    "CVehiclePoints",
    "CPedVariationBodyTypeManager",
    "CPedComponentSetManager",
    "CPedScheduleInfoManager",
    "CPedFormationInfoManager",
    "CPedInventoryLoadOutManager",
];

/// Reads a UTF-8 XML document. A UTF-8 BOM is accepted.
pub fn extract_document(bytes: &[u8]) -> Result<DocumentExtraction, String> {
    let bytes = bytes.strip_prefix(b"\xEF\xBB\xBF").unwrap_or(bytes);
    let text = std::str::from_utf8(bytes)
        .map_err(|err| format!("the document is not valid UTF-8: {err}"))?;
    let document =
        Document::parse(text).map_err(|err| format!("the XML is not well formed: {err}"))?;
    let root = document.root_element();
    let root_name = root.tag_name().name().to_string();
    let mut observations = Vec::new();

    match root_name.as_str() {
        "CVehiclePerformanceMaps" => vehicle_performance_maps(root, &mut observations),
        "CVehicleBaseRatingsAndEstimatesMap" => vehicle_ratings(root, &mut observations),
        "CVehicleBoneOffsetsArray" => vehicle_bone_offsets(root, &mut observations),
        "CVehicleDistantLightData" => vehicle_distant_lights(root, &mut observations),
        "CVehiclePoints" => vehicle_points(root, &mut observations),
        "CPedVariationBodyTypeManager" => ped_body_types(root, &mut observations),
        "CPedComponentSetManager" => ped_component_sets(root, &mut observations),
        "CPedScheduleInfoManager" => ped_schedules(root, &mut observations),
        "CPedFormationInfoManager" => ped_formations(root, &mut observations),
        "CPedInventoryLoadOutManager" => weapon_loadouts(root, &mut observations),
        _ => {}
    }

    // Weapon identifiers and ammunition types also occur inside documents whose
    // root describes damage, combat or animation. They are read from the
    // explicit `WeaponTypes`, `WeaponGroups` and `AmmoTypes` elements only.
    weapon_identifiers(root, &mut observations);

    let recognized = RECOGNIZED_ROOTS.contains(&root_name.as_str()) || !observations.is_empty();
    dedupe(&mut observations, &mut Vec::new());
    Ok(DocumentExtraction {
        root: root_name,
        recognized,
        observations,
        issues: Vec::new(),
    })
}

fn element_children<'a, 'input>(node: Node<'a, 'input>) -> impl Iterator<Item = Node<'a, 'input>> {
    node.children().filter(|child| child.is_element())
}

fn child<'a, 'input>(node: Node<'a, 'input>, name: &str) -> Option<Node<'a, 'input>> {
    element_children(node).find(|child| child.tag_name().name() == name)
}

fn text(node: Node<'_, '_>) -> Option<String> {
    let value = node.text().unwrap_or("").trim();
    (!value.is_empty()).then(|| value.to_string())
}

fn child_text(node: Node<'_, '_>, name: &str) -> Option<String> {
    child(node, name).and_then(text)
}

fn attribute_f64(node: Node<'_, '_>) -> Option<f64> {
    node.attribute("value")
        .and_then(|value| value.trim().parse().ok())
}

fn item_path(parent: &str, tag: &str, key: Option<&str>) -> String {
    match key {
        Some(key) => format!("{parent}/{tag}[@key='{key}']"),
        None => format!("{parent}/{tag}"),
    }
}

fn vehicle_performance_maps(root: Node<'_, '_>, out: &mut Vec<Observation>) {
    let Some(map) = child(root, "Map") else {
        return;
    };
    for item in element_children(map).filter(|node| node.tag_name().name() == "Item") {
        let Some(key) = item
            .attribute("key")
            .map(str::trim)
            .filter(|key| !key.is_empty())
        else {
            continue;
        };
        let path = item_path("/CVehiclePerformanceMaps/Map", "Item", Some(key));
        let mut observation = Observation::new(Category::Vehicles, "vehicle", key, path);
        for field in element_children(item) {
            if let Some(value) = attribute_f64(field) {
                observation.number(field.tag_name().name(), value, None);
            }
        }
        out.push(observation);
    }
}

fn vehicle_ratings(root: Node<'_, '_>, out: &mut Vec<Observation>) {
    let Some(map) = child(root, "Map") else {
        return;
    };
    for item in element_children(map).filter(|node| node.tag_name().name() == "Item") {
        let Some(key) = item
            .attribute("key")
            .map(str::trim)
            .filter(|key| !key.is_empty())
        else {
            continue;
        };
        let path = item_path("/CVehicleBaseRatingsAndEstimatesMap/Map", "Item", Some(key));
        let mut observation = Observation::new(Category::Vehicles, "vehicle", key, path);
        for group in element_children(item) {
            let group_name = group.tag_name().name();
            let grouped = matches!(
                group_name,
                "estimatesRoad" | "estimatesOffroad" | "ratingsRoad" | "ratingsOffroad"
            );
            if !grouped {
                if let Some(value) = attribute_f64(group) {
                    observation.number(group_name, value, None);
                }
                continue;
            }
            for field in element_children(group) {
                if let Some(value) = attribute_f64(field) {
                    observation.number(
                        format!("{group_name}.{}", field.tag_name().name()),
                        value,
                        None,
                    );
                }
            }
        }
        out.push(observation);
    }
}

fn vehicle_bone_offsets(root: Node<'_, '_>, out: &mut Vec<Observation>) {
    let Some(offsets) = child(root, "boneOffsets") else {
        return;
    };
    for (index, item) in element_children(offsets)
        .filter(|node| node.tag_name().name() == "Item")
        .enumerate()
    {
        let Some(vehicle) = child_text(item, "vehicleName") else {
            continue;
        };
        let path = format!("/CVehicleBoneOffsetsArray/boneOffsets/Item[{index}]");
        let mut observation = Observation::new(Category::Vehicles, "vehicle", vehicle, path);
        if let Some(name) = child_text(item, "name") {
            observation.meta_text("boneSetName", name);
        }
        if let Some(record) = child(item, "offsets") {
            for field in element_children(record) {
                let tag = field.tag_name().name();
                match tag {
                    "numEntries" | "bitsPerIndex" => {
                        if let Some(value) = attribute_f64(field) {
                            observation.number(tag, value, None);
                        }
                    }
                    "packedIndices" => {
                        observation.metadata.insert(
                            "packedIndices".to_string(),
                            Value::TextList(
                                field
                                    .text()
                                    .unwrap_or("")
                                    .split_whitespace()
                                    .filter(|part| !part.is_empty())
                                    .map(str::to_string)
                                    .collect(),
                            ),
                        );
                    }
                    "palette" => {
                        let values = field
                            .text()
                            .unwrap_or("")
                            .split_whitespace()
                            .filter_map(|part| part.parse::<f64>().ok())
                            .collect::<Vec<_>>();
                        observation.number_list("palette", values, None);
                    }
                    _ => {}
                }
            }
        }
        if let Some(bones) = child(item, "attachBones") {
            let values = element_children(bones)
                .filter(|node| node.tag_name().name() == "Item")
                .filter_map(text)
                .collect::<Vec<_>>();
            observation.text_list("attachBones", values);
        }
        out.push(observation);
    }
}

fn vehicle_distant_lights(root: Node<'_, '_>, out: &mut Vec<Observation>) {
    let Some(recipe) = child(root, "recipeLights") else {
        return;
    };
    for (index, item) in element_children(recipe)
        .filter(|node| node.tag_name().name() == "Item")
        .enumerate()
    {
        let Some(vehicle) = child_text(item, "vehicleModelName") else {
            continue;
        };
        let path = format!("/CVehicleDistantLightData/recipeLights/Item[{index}]");
        let mut observation = Observation::new(Category::Vehicles, "vehicle", vehicle, path);
        if let Some(recipes) = child(item, "secondaryRecipes") {
            let values = element_children(recipes)
                .filter(|node| node.tag_name().name() == "Item")
                .filter_map(text)
                .collect::<Vec<_>>();
            observation.text_list("secondaryRecipes", values);
        }
        out.push(observation);
    }
}

fn vehicle_points(root: Node<'_, '_>, out: &mut Vec<Observation>) {
    let Some(name) = child_text(root, "DefinitionName").or_else(|| child_text(root, "ModelName"))
    else {
        return;
    };
    let path = "/CVehiclePoints".to_string();
    let mut observation = Observation::new(Category::Vehicles, "vehicle", name.clone(), path);
    if let Some(model) = child_text(root, "ModelName") {
        observation.text("modelName", model);
    }
    if let Some(definition) = child_text(root, "DefinitionName") {
        observation.text("definitionName", definition);
    }
    for field in element_children(root) {
        let tag = field.tag_name().name();
        if matches!(tag, "ModelName" | "DefinitionName" | "Points" | "Props") {
            continue;
        }
        if let Some(value) = attribute_f64(field) {
            observation.number(tag, value, None);
        } else if let Some(value) = text(field) {
            observation.text(tag, value);
        }
    }
    out.push(observation);
}

fn number_list_content(node: Node<'_, '_>) -> Vec<f64> {
    node.text()
        .unwrap_or("")
        .split_whitespace()
        .filter_map(|part| part.parse::<f64>().ok())
        .collect()
}

fn ped_body_types(root: Node<'_, '_>, out: &mut Vec<Observation>) {
    if let Some(presets) = child(root, "HeightPresets") {
        for item in element_children(presets).filter(|node| node.tag_name().name() == "Item") {
            let Some(key) = item
                .attribute("key")
                .map(str::trim)
                .filter(|key| !key.is_empty())
            else {
                continue;
            };
            let mut observation = Observation::new(
                Category::Peds,
                "ped_height_preset",
                key,
                item_path(
                    "/CPedVariationBodyTypeManager/HeightPresets",
                    "Item",
                    Some(key),
                ),
            );
            if let Some(values) = child(item, "HeightsInMeters") {
                observation.number_list("heightsMeters", number_list_content(values), Some("m"));
            }
            out.push(observation);
        }
    }
    if let Some(profiles) = child(root, "ScaleProfiles") {
        for item in element_children(profiles).filter(|node| node.tag_name().name() == "Item") {
            let Some(key) = item
                .attribute("key")
                .map(str::trim)
                .filter(|key| !key.is_empty())
            else {
                continue;
            };
            let mut observation = Observation::new(
                Category::Peds,
                "ped_scale_profile",
                key,
                item_path(
                    "/CPedVariationBodyTypeManager/ScaleProfiles",
                    "Item",
                    Some(key),
                ),
            );
            if let Some(height) = child(item, "DefaultHeightMeters").and_then(attribute_f64) {
                observation.number("defaultHeightMeters", height, Some("m"));
            }
            if let Some(presets) = child_text(item, "HeightPresets") {
                observation.text("heightPresets", presets);
            }
            out.push(observation);
        }
    }
    if let Some(shapes) = child(root, "BodyShapePresets") {
        for item in element_children(shapes).filter(|node| node.tag_name().name() == "Item") {
            let Some(key) = item
                .attribute("key")
                .map(str::trim)
                .filter(|key| !key.is_empty())
            else {
                continue;
            };
            let mut observation = Observation::new(
                Category::Peds,
                "ped_body_shape",
                key,
                item_path(
                    "/CPedVariationBodyTypeManager/BodyShapePresets",
                    "Item",
                    Some(key),
                ),
            );
            if let Some(expressions) = child(item, "Expressions") {
                for expression in
                    element_children(expressions).filter(|node| node.tag_name().name() == "Item")
                {
                    let Some(id) = child_text(expression, "Id") else {
                        continue;
                    };
                    if let Some(values) = child(expression, "Values") {
                        observation.number_list(
                            format!("expression.{}", id.to_lowercase()),
                            number_list_content(values),
                            None,
                        );
                    }
                }
            }
            out.push(observation);
        }
    }
    let mut defaults = Observation::new(
        Category::Peds,
        "ped_variation_defaults",
        "CPedVariationBodyTypeManager",
        "/CPedVariationBodyTypeManager".to_string(),
    );
    for key in [
        "DefaultHumanHeightPresets",
        "DefaultHumanMaleScaleProfile",
        "DefaultHumanFemaleScaleProfile",
    ] {
        if let Some(value) = child_text(root, key) {
            defaults.text(key, value);
        }
    }
    if !defaults.fields.is_empty() {
        out.push(defaults);
    }
}

fn ped_component_sets(root: Node<'_, '_>, out: &mut Vec<Observation>) {
    let Some(infos) = child(root, "Infos") else {
        return;
    };
    for (index, item) in element_children(infos)
        .filter(|node| node.tag_name().name() == "Item")
        .enumerate()
    {
        if item.attribute("type") != Some("CPedComponentSetInfo") {
            continue;
        }
        let Some(name) = child_text(item, "Name") else {
            continue;
        };
        let mut observation = Observation::new(
            Category::Peds,
            "ped_component_set",
            name,
            format!("/CPedComponentSetManager/Infos/Item[{index}]"),
        );
        for field in element_children(item) {
            let tag = field.tag_name().name();
            if tag == "Name" || tag == "EntityComponentsInfo" {
                continue;
            }
            if let Some(value) = field.attribute("value") {
                match value {
                    "true" => observation.boolean(tag, true),
                    "false" => observation.boolean(tag, false),
                    _ => {
                        if let Ok(number) = value.parse::<f64>() {
                            observation.number(tag, number, None);
                        }
                    }
                }
            }
        }
        if let Some(components) = child(item, "EntityComponentsInfo") {
            let mut names = Vec::new();
            for component in
                element_children(components).filter(|node| node.tag_name().name() == "Item")
            {
                let Some(kind) = child_text(component, "Type") else {
                    continue;
                };
                names.push(kind.clone());
                for bound in ["MinDistance", "MaxDistance"] {
                    if let Some(value) = child(component, bound).and_then(attribute_f64) {
                        observation.number(format!("component.{kind}.{bound}"), value, None);
                    }
                }
            }
            observation.text_list("components", names);
        }
        out.push(observation);
    }
}

fn ped_schedules(root: Node<'_, '_>, out: &mut Vec<Observation>) {
    let Some(schedules) = child(root, "Schedules") else {
        return;
    };
    for (index, item) in element_children(schedules)
        .filter(|node| node.tag_name().name() == "Item")
        .enumerate()
    {
        let Some(name) = child_text(item, "Name") else {
            continue;
        };
        let mut observation = Observation::new(
            Category::Peds,
            "ped_schedule",
            name,
            format!("/CPedScheduleInfoManager/Schedules/Item[{index}]"),
        );
        if let Some(pack) = child_text(item, "Pack") {
            observation.text("pack", pack);
        }
        out.push(observation);
    }
}

fn ped_formations(root: Node<'_, '_>, out: &mut Vec<Observation>) {
    let Some(infos) = child(root, "aPedFormationInfos") else {
        return;
    };
    for (index, item) in element_children(infos)
        .filter(|node| node.tag_name().name() == "Item")
        .enumerate()
    {
        let Some(name) = child_text(item, "Name") else {
            continue;
        };
        let mut observation = Observation::new(
            Category::Peds,
            "ped_formation",
            name,
            format!("/CPedFormationInfoManager/aPedFormationInfos/Item[{index}]"),
        );
        for field in element_children(item) {
            let tag = field.tag_name().name();
            if tag == "Name" {
                continue;
            }
            if let Some(value) = field.attribute("value") {
                match value {
                    "true" => observation.boolean(tag, true),
                    "false" => observation.boolean(tag, false),
                    _ => {
                        if let Ok(number) = value.parse::<f64>() {
                            observation.number(tag, number, None);
                        }
                    }
                }
            }
        }
        out.push(observation);
    }
}

fn weapon_loadouts(root: Node<'_, '_>, out: &mut Vec<Observation>) {
    let Some(loadouts) = child(root, "LoadOuts") else {
        return;
    };
    for (index, loadout) in element_children(loadouts)
        .filter(|node| node.tag_name().name() == "Item")
        .enumerate()
    {
        let Some(loadout_name) = child_text(loadout, "Name") else {
            continue;
        };
        for (kind, tag, entity_type) in [
            ("weapon_preset", "WeaponPreset", "weapon_preset"),
            ("weapon_recipe", "WeaponRecipe", "weapon_recipe"),
            ("weapon_spec", "WeaponSpec", "weapon_spec"),
        ] {
            for value in loadout.descendants().filter_map(|node| {
                (node.is_element() && node.tag_name().name() == tag)
                    .then(|| text(node))
                    .flatten()
            }) {
                let mut observation = Observation::new(
                    Category::Weapons,
                    entity_type,
                    value,
                    format!(
                        "/CPedInventoryLoadOutManager/LoadOuts/Item[{index}]/descendant::{tag}"
                    ),
                );
                observation.text("loadout", loadout_name.clone());
                observation.meta_text("referenceKind", kind);
                out.push(observation);
            }
        }
    }
}

fn weapon_identifiers(root: Node<'_, '_>, out: &mut Vec<Observation>) {
    for node in root.descendants() {
        if !node.is_element() {
            continue;
        }
        let tag = node.tag_name().name();
        match tag {
            "WeaponTypes" | "WeaponGroups" | "AmmoTypes" => {
                let (entity_type, prefix) = match tag {
                    "WeaponTypes" => ("weapon_type", "WEAPON_"),
                    "WeaponGroups" => ("weapon_group", "GROUP_"),
                    _ => ("ammo_type", "AMMO_"),
                };
                for item in element_children(node)
                    .filter(|child| child.tag_name().name() == "Item")
                    .filter_map(text)
                {
                    if !item.starts_with(prefix) {
                        continue;
                    }
                    let mut observation = Observation::new(
                        Category::Weapons,
                        entity_type,
                        item,
                        format!("/{}/descendant::{}", root.tag_name().name(), tag),
                    );
                    observation.meta_text("sourceElement", tag);
                    out.push(observation);
                }
            }
            "WeaponName" | "WeaponToCheck" => {
                if let Some(value) = text(node)
                    && value.starts_with("WEAPON_")
                {
                    let mut observation = Observation::new(
                        Category::Weapons,
                        "weapon_type",
                        value,
                        format!("/{}/descendant::{}", root.tag_name().name(), tag),
                    );
                    observation.meta_text("sourceElement", tag);
                    out.push(observation);
                }
            }
            _ => {}
        }
    }
}

/// Collapses observations with the same category, entity type and name inside
/// one document. Field values that disagree are kept as separate observations,
/// so the exporter can report a conflict instead of picking one.
fn dedupe(observations: &mut Vec<Observation>, _issues: &mut Vec<String>) {
    let mut seen: BTreeMap<(String, String, String), usize> = BTreeMap::new();
    let mut keep = Vec::with_capacity(observations.len());
    for observation in observations.drain(..) {
        let key = (
            observation.category.name().to_string(),
            observation.entity_type.clone(),
            observation.internal_name.clone(),
        );
        if let Some(&index) = seen.get(&key) {
            let existing: &mut Observation = &mut keep[index];
            if existing.fields == observation.fields {
                // Same item reached through another path: merge metadata only.
                for (name, value) in observation.metadata {
                    existing.metadata.entry(name).or_insert(value);
                }
                continue;
            }
        }
        seen.insert(key, keep.len());
        keep.push(observation);
    }
    *observations = keep;
}

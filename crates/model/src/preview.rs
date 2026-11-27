//! Presentation policy for a vehicle preview.
//!
//! The decoder reports what the asset declares. This module decides how a
//! vehicle body is presented when the asset cannot answer: which shader hashes
//! are paint, glass, a lamp or a tyre, what a painted panel is coloured with,
//! and which texture stores a body is resolved against.
//!
//! The colour is a presentation choice, not a factory colour. It is derived
//! from the model name so a repeated render keeps the same colour.
//!
//! The module holds no paths and no I/O beyond reading caller-supplied files.

use std::path::{Path, PathBuf};
use std::sync::atomic::AtomicBool;

use lforge_scene::{AlphaMode, Scene};
use lforge_texture::StoreSet;

/// A vehicle surface class, keyed by the shader hash the body declares.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Surface {
    Paint,
    Glass,
    Emissive,
    Tyre,
    Default,
}

/// The policy version. It is part of the preview cache identity, so a change to
/// any constant or default here invalidates cached images.
pub const POLICY_VERSION: u32 = 2;

/// The lowest display luminance a body colour is lifted to.
///
/// A preview has a transparent background and the catalog page is dark, so a
/// factory near-black paint would render as an invisible silhouette. The lift
/// keeps the hue and changes only the brightness.
const MINIMUM_PAINT_LUMINANCE: f32 = 0.075;

/// Reads the shader hash out of a material name such as `shader 4aa38282`.
pub fn shader_hash(name: &str) -> Option<u32> {
    let hex = name.strip_prefix("shader ")?;
    u32::from_str_radix(hex, 16).ok()
}

/// The class of a shader hash. The hashes are the ones the vehicle preview
/// reference lists; an unknown hash is trim, which keeps its texture.
pub fn surface(hash: Option<u32>) -> Surface {
    match hash {
        Some(
            0x4AA3_8282 | 0x03B2_7476 | 0x4D2B_05E7 | 0xC5CD_BDD2 | 0xF9FB_7331 | 0xEDE8_5B0B
            | 0xE029_BF8E | 0xC0CB_80D2,
        ) => Surface::Paint,
        Some(0xFA9C_C069 | 0xBD71_BDBF | 0x7C98_D207) => Surface::Glass,
        Some(0x5A69_3BBE | 0x2964_8098 | 0x59C1_D684 | 0xF119_F925 | 0xE515_A6E7) => {
            Surface::Emissive
        }
        Some(0x99AD_6FC9) => Surface::Tyre,
        _ => Surface::Default,
    }
}

/// The class of a material, from its name.
pub fn material_surface(name: &str) -> Surface {
    surface(shader_hash(name))
}

/// Base colour per class. `paint` is the body colour.
pub fn class_color(surface: Surface, paint: [f32; 4]) -> [f32; 4] {
    match surface {
        Surface::Paint => paint,
        Surface::Glass => [0.12, 0.14, 0.17, 0.55],
        Surface::Emissive => [0.92, 0.90, 0.82, 1.0],
        Surface::Tyre => [0.07, 0.07, 0.08, 1.0],
        Surface::Default => [0.34, 0.35, 0.37, 1.0],
    }
}

/// Metalness, roughness and emissive weight per class.
pub fn class_shading(surface: Surface) -> (f32, f32, f32) {
    match surface {
        Surface::Paint => (0.45, 0.24, 0.0),
        Surface::Glass => (0.0, 0.05, 0.0),
        Surface::Emissive => (0.0, 0.2, 1.8),
        Surface::Tyre => (0.0, 0.92, 0.0),
        Surface::Default => (0.05, 0.55, 0.0),
    }
}

/// Applies the class policy to a decoded body.
///
/// A textured material keeps its texture as the base colour. A material with no
/// diffuse texture gets its class colour, and the checker fallback is cleared:
/// a painted panel is not a damaged asset.
///
/// Returns the painted and textured material counts.
pub fn prepare_materials(scene: &mut Scene, paint: [f32; 4]) -> (usize, usize) {
    let mut painted = 0;
    let mut textured = 0;
    for material in &mut scene.materials {
        let surface = material_surface(&material.name);
        material.missing_texture = false;
        // Glass, lamps and rubber keep their class response whether or not they
        // carry a texture; only paint is replaced by the body colour.
        let shading = class_shading(surface);
        material.metallic = shading.0;
        material.roughness = shading.1;
        material.emissive = shading.2;
        if matches!(surface, Surface::Glass) {
            material.alpha_mode = AlphaMode::Blend;
        }
        if material.diffuse.is_some() {
            material.base_color = [1.0, 1.0, 1.0, 1.0];
            textured += 1;
            continue;
        }
        material.base_color = class_color(surface, paint);
        material.bumpiness = 0.0;
        painted += 1;
    }
    (painted, textured)
}

/// A stable paint for a model name, so repeat renders keep their colour.
pub fn paint_for(name: &str) -> [f32; 4] {
    const PALETTE: [[f32; 4]; 8] = [
        [0.42, 0.09, 0.10, 1.0],
        [0.08, 0.13, 0.28, 1.0],
        [0.55, 0.57, 0.60, 1.0],
        [0.08, 0.20, 0.12, 1.0],
        [0.62, 0.52, 0.34, 1.0],
        [0.05, 0.05, 0.06, 1.0],
        [0.62, 0.25, 0.06, 1.0],
        [0.05, 0.28, 0.30, 1.0],
    ];
    let hash = fnv1a(name);
    PALETTE[(hash % PALETTE.len() as u64) as usize]
}

/// The paint for a model: a colour from the supplied list, else the palette,
/// lifted enough to stay visible on a dark page.
pub fn paint_color(name: &str, colors: &[[f32; 4]]) -> [f32; 4] {
    lift_paint(color_for(name, colors).unwrap_or_else(|| paint_for(name)))
}

/// Raises a colour's luminance to [`MINIMUM_PAINT_LUMINANCE`], keeping its hue.
pub fn lift_paint(color: [f32; 4]) -> [f32; 4] {
    let luminance = 0.2126 * color[0] + 0.7152 * color[1] + 0.0722 * color[2];
    if luminance >= MINIMUM_PAINT_LUMINANCE || luminance <= f32::EPSILON {
        return color;
    }
    let scale = MINIMUM_PAINT_LUMINANCE / luminance;
    [
        (color[0] * scale).min(1.0),
        (color[1] * scale).min(1.0),
        (color[2] * scale).min(1.0),
        color[3],
    ]
}

fn fnv1a(text: &str) -> u64 {
    let mut hash = 0xcbf2_9ce4_8422_2325u64;
    for byte in text.bytes() {
        hash ^= u64::from(byte);
        hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
    }
    hash
}

/// One entry of the public vehicle dump, limited to the fields the preview uses.
#[derive(Debug, Clone, PartialEq)]
pub struct VehicleInfo {
    pub wheel_type: String,
    pub wheel_scale: Option<f32>,
    pub wheel_scale_rear: Option<f32>,
    pub vehicle_type: String,
}

/// Looks a model up in a `vehicles.json` shaped array, by exact name.
pub fn load_vehicle_info(path: &Path, model: &str) -> Option<VehicleInfo> {
    let text = std::fs::read_to_string(path).ok()?;
    let value: serde_json::Value = serde_json::from_str(&text).ok()?;
    let entry = value.as_array()?.iter().find(|entry| {
        entry
            .get("Name")
            .and_then(serde_json::Value::as_str)
            .is_some_and(|name| name.eq_ignore_ascii_case(model))
    })?;
    Some(VehicleInfo {
        wheel_type: entry
            .get("WheelType")
            .and_then(serde_json::Value::as_str)
            .unwrap_or("VWT_SPORT")
            .to_string(),
        wheel_scale: entry
            .get("WheelScale")
            .and_then(serde_json::Value::as_f64)
            .map(|value| value as f32),
        wheel_scale_rear: entry
            .get("WheelScaleRear")
            .and_then(serde_json::Value::as_f64)
            .map(|value| value as f32),
        vehicle_type: entry
            .get("Type")
            .and_then(serde_json::Value::as_str)
            .unwrap_or("VEHICLE_TYPE_CAR")
            .to_string(),
    })
}

/// The wheel kit family for a vehicle, or `None` when it has no wheels.
pub fn wheel_family(info: Option<&VehicleInfo>) -> Option<&'static str> {
    let Some(info) = info else {
        return Some("sport");
    };
    if info.vehicle_type.contains("BOAT")
        || info.vehicle_type.contains("PLANE")
        || info.vehicle_type.contains("HELI")
        || info.vehicle_type.contains("TRAIN")
        || info.vehicle_type.contains("SUBMARINE")
    {
        return None;
    }
    if info.vehicle_type.contains("BICYCLE") {
        return Some("bicycle");
    }
    if info.vehicle_type.contains("TRUCK") || info.vehicle_type.contains("INDUSTRIAL") {
        return Some("truck");
    }
    Some(match info.wheel_type.as_str() {
        "VWT_MUSCLE" => "muscle",
        "VWT_SUV" => "suv",
        "VWT_BIKE" => "bike",
        "VWT_HIEND" => "hiend",
        "VWT_LOWRIDER" => "lowrider",
        "VWT_TUNER" => "tuner",
        "VWT_OFFROAD" => "offroad",
        _ => "sport",
    })
}

/// Reads body colours from a `vehicleColors.json` shaped array.
///
/// Entries that are not opaque or are near-black are skipped: a black body
/// would hide the shading the preview exists to show.
pub fn load_colors(path: &Path) -> Vec<[f32; 4]> {
    let Ok(text) = std::fs::read_to_string(path) else {
        return Vec::new();
    };
    parse_colors(&text)
}

/// [`load_colors`] over text, for callers that already hold the file.
pub fn parse_colors(text: &str) -> Vec<[f32; 4]> {
    let Ok(value) = serde_json::from_str::<serde_json::Value>(text) else {
        return Vec::new();
    };
    let mut colors = Vec::new();
    for entry in value.as_array().into_iter().flatten() {
        let Some(raw) = entry.get("Colour").and_then(serde_json::Value::as_str) else {
            continue;
        };
        let hex = raw.trim_start_matches('#');
        if hex.len() != 8 {
            continue;
        }
        let Ok(argb) = u32::from_str_radix(hex, 16) else {
            continue;
        };
        if argb >> 24 != 0xFF {
            continue;
        }
        let rgb = [(argb >> 16) as u8, (argb >> 8) as u8, argb as u8];
        if rgb.iter().all(|channel| *channel < 8) {
            continue;
        }
        colors.push([
            srgb_to_linear(rgb[0]),
            srgb_to_linear(rgb[1]),
            srgb_to_linear(rgb[2]),
            1.0,
        ]);
    }
    colors
}

fn srgb_to_linear(channel: u8) -> f32 {
    let value = f32::from(channel) / 255.0;
    if value <= 0.04045 {
        value / 12.92
    } else {
        ((value + 0.055) / 1.055).powf(2.4)
    }
}

/// The colour a model takes from a list, by name. `None` when the list is empty.
pub fn color_for(name: &str, colors: &[[f32; 4]]) -> Option<[f32; 4]> {
    if colors.is_empty() {
        return None;
    }
    let hash = fnv1a(name);
    Some(colors[(hash % colors.len() as u64) as usize])
}

/// The rim and tyre files of a kit family, when both exist.
pub fn kit_paths(root: &Path, family: &str) -> Option<(PathBuf, PathBuf)> {
    let rim = root.join(family).join("rim.bin");
    let tyre = root.join(family).join("tyre.bin");
    (rim.is_file() && tyre.is_file()).then_some((rim, tyre))
}

/// Every texture store the caller supplied, searched in order.
///
/// A body takes its glass and lamp textures from the vehicle texture store,
/// while a painted panel references a key no single root holds, so a caller may
/// give several roots.
pub struct Stores(Vec<StoreSet>);

impl Stores {
    /// Scans each root. A root that cannot be scanned is an error: a silently
    /// empty store would render every body untextured.
    pub fn scan(roots: &[PathBuf]) -> Result<Option<Self>, String> {
        let mut sets = Vec::with_capacity(roots.len());
        for root in roots {
            sets.push(
                StoreSet::scan(root)
                    .map_err(|err| format!("could not scan {}: {err}", root.display()))?,
            );
        }
        Ok((!sets.is_empty()).then_some(Self(sets)))
    }

    /// How many roots the set holds.
    pub fn root_count(&self) -> usize {
        self.0.len()
    }
}

impl crate::TextureProvider for Stores {
    fn resolve(&self, reference: &crate::TextureReference) -> crate::TextureResolution {
        let mut hits = Vec::new();
        for (sets, set) in self.0.iter().enumerate() {
            for (store_index, index) in set.find(reference.key64) {
                hits.push((sets, store_index, index));
            }
        }
        match hits.as_slice() {
            [] => crate::TextureResolution::Missing,
            [(sets, store_index, index)] => {
                let (sets, store_index, index) = (*sets, *store_index, *index);
                let store = match self.0[sets].open(store_index) {
                    Ok(store) => store,
                    Err(err) => return crate::TextureResolution::Failed(err.to_string()),
                };
                match store.level(index, 0, &AtomicBool::new(false)) {
                    Ok(level) => crate::TextureResolution::Resolved(crate::ResolvedTexture {
                        level,
                        source: format!("{sets}/{store_index}#{index}"),
                    }),
                    Err(err) => crate::TextureResolution::Failed(err.to_string()),
                }
            }
            _ => crate::TextureResolution::Ambiguous(
                hits.iter()
                    .map(|(sets, store, index)| format!("{sets}/{store}#{index}"))
                    .collect(),
            ),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn paint_materials_are_classified_by_hash() {
        assert_eq!(material_surface("shader 4aa38282"), Surface::Paint);
        assert_eq!(material_surface("shader fa9cc069"), Surface::Glass);
        assert_eq!(material_surface("shader 5a693bbe"), Surface::Emissive);
        assert_eq!(material_surface("shader 99ad6fc9"), Surface::Tyre);
        assert_eq!(material_surface("shader 00000000"), Surface::Default);
        assert_eq!(material_surface("not a shader"), Surface::Default);
    }

    #[test]
    fn the_paint_is_stable_for_a_name() {
        let first = paint_for("akane");
        assert_eq!(first, paint_for("akane"));
        // Two names can share a palette entry, so the claim is that the palette
        // is used, not that every pair differs.
        let names = ["akane", "blista2", "cheetah2", "sultan", "fcr", "taco"];
        let distinct: std::collections::BTreeSet<[u32; 4]> = names
            .iter()
            .map(|name| paint_for(name).map(|channel| (channel * 1e6) as u32))
            .collect();
        assert!(distinct.len() > 1);
    }

    #[test]
    fn a_dump_colour_is_taken_from_the_list_and_kept_in_range() {
        let text =
            r##"[{"Name":"black","Colour":"#FF000000"},{"Name":"red","Colour":"#FFFF0000"}]"##;
        let colors = parse_colors(text);
        assert_eq!(colors.len(), 1, "a near-black entry is skipped");
        let color = paint_color("akane", &colors);
        assert!(color[0] > 0.9 && color[1] < 0.1 && color[2] < 0.1);
        assert!((color[3] - 1.0).abs() < f32::EPSILON);
    }

    #[test]
    fn an_empty_colour_list_falls_back_to_the_palette() {
        assert_eq!(paint_color("akane", &[]), lift_paint(paint_for("akane")));
    }

    #[test]
    fn a_near_black_paint_is_lifted_and_a_bright_one_is_not() {
        let dark = lift_paint([0.01, 0.01, 0.012, 1.0]);
        let luminance = 0.2126 * dark[0] + 0.7152 * dark[1] + 0.0722 * dark[2];
        assert!(luminance >= MINIMUM_PAINT_LUMINANCE - 1e-6);
        assert!(dark[0] < dark[2], "the blue cast is kept");
        let bright = [0.5, 0.5, 0.5, 1.0];
        assert_eq!(lift_paint(bright), bright);
    }

    #[test]
    fn wheel_families_follow_the_vehicle_type_first() {
        let boat = VehicleInfo {
            wheel_type: "VWT_SPORT".into(),
            wheel_scale: None,
            wheel_scale_rear: None,
            vehicle_type: "VEHICLE_TYPE_BOAT".into(),
        };
        assert_eq!(wheel_family(Some(&boat)), None);
        let bike = VehicleInfo {
            wheel_type: "VWT_BIKE".into(),
            wheel_scale: None,
            wheel_scale_rear: None,
            vehicle_type: "VEHICLE_TYPE_BIKE".into(),
        };
        assert_eq!(wheel_family(Some(&bike)), Some("bike"));
        assert_eq!(wheel_family(None), Some("sport"));
    }

    #[test]
    fn a_textured_material_keeps_its_texture_and_a_bare_one_takes_the_class_colour() {
        let mut scene = Scene::default();
        let mut textured = lforge_scene::Material {
            name: "shader 4d2b05e7".into(),
            ..Default::default()
        };
        textured.diffuse = Some(0);
        let mut bare = lforge_scene::Material {
            name: "shader 4aa38282".into(),
            ..Default::default()
        };
        bare.missing_texture = true;
        scene.materials.push(textured);
        scene.materials.push(bare);
        let (painted, textured_count) = prepare_materials(&mut scene, [0.5, 0.1, 0.1, 1.0]);
        assert_eq!((painted, textured_count), (1, 1));
        assert_eq!(scene.materials[0].base_color, [1.0, 1.0, 1.0, 1.0]);
        assert_eq!(scene.materials[1].base_color, [0.5, 0.1, 0.1, 1.0]);
        assert!(!scene.materials[1].missing_texture);
        assert!((scene.materials[1].metallic - 0.45).abs() < f32::EPSILON);
    }
}

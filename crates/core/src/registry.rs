//! The engine's native type registry, recovered statically from the retail
//! executable.
//!
//! The engine maps a table-of-contents type id to a file extension through a
//! static table of string pointers indexed by type id, with three variants of
//! every extension. The path resolver uses [`Variant::Path`].
//!
//! Two id ranges are registered: 0 to 18 and 64 to 115. Every other id resolves
//! to no extension, which the engine prints as `???`.
//!
//! Recovered from build `e95020b2` of the retail executable:
//!
//! - accessor `0x4EBBC30`: `0xFF` and a `0xFFFF` variant return nothing, ids
//!   below 19 index the table at `0x62FCD30` with a stride of 19 pointers, and
//!   ids above fall through to the provider registered for `0x40..0x73`, which
//!   indexes the table at `0x618D9E0` with a stride of 52 pointers;
//! - extension to id `0x56EE50` compares against the path variant of the first
//!   table in id order and answers `0xFFFF` when nothing matches.
//!
//! Evidence: RPF9-F144.

/// Which of the engine's three extension variants a name uses.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Variant {
    /// Row 0: the variant the path resolver and the reverse lookup use.
    Path,
    /// Row 1: the same ids with the `i…` forms.
    Alternate,
    /// Row 2: the same ids with the `#…` forms.
    Hash,
}

impl Variant {
    pub fn name(self) -> &'static str {
        match self {
            Variant::Path => "path",
            Variant::Alternate => "alternate",
            Variant::Hash => "hash",
        }
    }
}

/// A native extension the engine associates with a type id.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NativeExtension {
    pub type_id: u8,
    /// The extension without a dot.
    pub extension: &'static str,
    pub variant: Variant,
}

/// Extensions for type ids 0 to 18, one row per variant.
const LOW: [[&str; 19]; 3] = [
    [
        "rpf", "zmf", "zdr", "zft", "zdd", "ztd", "zbn", "zbd", "zpd", "zbs", "zsd", "zmt", "zsc",
        "zcs", "zdatb", "zbdr", "zbdd", "zbft", "zvert",
    ],
    [
        "rpf", "imf", "idr", "ift", "idd", "itd", "ibn", "ibd", "ipd", "ibs", "isd", "imt", "isc",
        "ics", "idatb", "ibdr", "ibdd", "ibft", "ivert",
    ],
    [
        "rpf", "#mf", "#dr", "#ft", "#dd", "#td", "#bn", "#bd", "#pd", "#bs", "#sd", "#mt", "#sc",
        "#cs", "#datb", "#bdr", "#bdd", "#bft", "#vert",
    ],
];

/// Extensions for type ids 64 to 115, one row per variant.
const HIGH: [[&str; 52]; 3] = [
    [
        "mrf", "cut", "gfx", "zcd", "zld", "zpmd", "zpm", "zed", "zpt", "zmap", "ztyp", "zch",
        "zldb", "zjd", "zad", "znv", "znvs", "zpl", "znd", "zvr", "zwr", "znh", "zfd", "zas",
        "zsm", "zscript", "zascript", "zsma", "iasf", "zfc", "zlfc", "zcg", "zasd", "rdb", "zfbs",
        "zcps", "zsp", "ztsl", "zmmd", "zfid", "zmsk", "zhdat", "znmd", "zsmm", "zascd", "zrd",
        "zsmam", "zldbmt", "znmd", "zkit", "zcgc", "zcov",
    ],
    [
        "mrf", "cut", "gfx", "icd", "ild", "ipmd", "ipm", "ied", "ipt", "imap", "ityp", "ich",
        "ildb", "ijd", "iad", "inv", "invs", "ipl", "ind", "ivr", "iwr", "inh", "ifd", "ias",
        "ism", "iscript", "iascript", "isma", "iasf", "ifc", "ilfc", "icg", "iasd", "rdb", "ifbs",
        "icps", "isp", "itsl", "immd", "ifid", "imsk", "ihdat", "inmd", "ismm", "iascd", "ird",
        "ismam", "ildbmt", "inmd", "ikit", "icgc", "icov",
    ],
    [
        "mrf", "cut", "gfx", "#cd", "#ld", "#pmd", "#pm", "#ed", "#pt", "#map", "#typ", "#ch",
        "#ldb", "#jd", "#ad", "#nv", "#nvs", "#pl", "#nd", "#vr", "#wr", "#nh", "#fd", "#as",
        "#sm", "#script", "#ascript", "#sma", "iasf", "#fc", "#lfc", "#cg", "#asd", "rdb", "#fbs",
        "#cps", "#sp", "#tsl", "#mmd", "#fid", "#msk", "#hdat", "#nmd", "#smm", "#ascd", "#rd",
        "#smam", "#ldbmt", "#nmd", "#kit", "#cgc", "#cov",
    ],
];

/// The lowest type id the second table covers.
const HIGH_START: u8 = 64;
/// The id the accessor answers with no extension, whatever the table holds.
const NO_EXTENSION: u8 = 0xFF;

/// The native extension of `type_id` in the path variant.
pub fn native_extension(type_id: u8) -> Option<NativeExtension> {
    extension(type_id, Variant::Path)
}

/// The native extension of `type_id` in `variant`.
pub fn extension(type_id: u8, variant: Variant) -> Option<NativeExtension> {
    if type_id == NO_EXTENSION {
        return None;
    }
    let row = match variant {
        Variant::Path => 0,
        Variant::Alternate => 1,
        Variant::Hash => 2,
    };
    let index = usize::from(type_id);
    let extension = match LOW[row].get(index) {
        Some(extension) => *extension,
        None => {
            let high = index.checked_sub(usize::from(HIGH_START))?;
            *HIGH[row].get(high)?
        }
    };
    Some(NativeExtension {
        type_id,
        extension,
        variant,
    })
}

/// Whether the engine registers an extension for `type_id` at all.
pub fn is_registered(type_id: u8) -> bool {
    native_extension(type_id).is_some()
}

/// Where the extension of a resolved file name came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NameSource {
    /// The resolved name already carried an extension. It is kept as it is.
    Original,
    /// The name had none, so the type's declared extension was appended.
    Declared,
    /// The name had none and the type declares none: the name stays as it is.
    None,
}

impl NameSource {
    pub fn name(self) -> &'static str {
        match self {
            NameSource::Original => "original",
            NameSource::Declared => "declared",
            NameSource::None => "none",
        }
    }
}

/// A resolved entry name with the extension the application shows.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedFileName {
    pub text: String,
    /// The extension shown, without a dot.
    pub extension: Option<&'static str>,
    pub source: NameSource,
}

/// The name to show for a resolved entry, with its extension resolved.
///
/// One rule for the Explorer and for the command line, so a name shown in one
/// is the name shown in the other:
///
/// - a name that already carries an extension keeps it, because the archive's
///   own name is the better evidence about how the engine spells it;
/// - a name without one takes the extension the engine's type registry
///   declares for the row's type;
/// - a type that declares no extension — an unregistered id, or 255 — gets
///   none. Nothing is invented.
///
/// The extension is a naming fact about the loader's type table. It says
/// nothing about whether the payload is valid, and a caller must keep it apart
/// from anything it verified itself.
pub fn file_name(name: &str, type_id: Option<u8>) -> ResolvedFileName {
    let declared = type_id.and_then(native_extension);
    let basename = name.rsplit(['/', '\\']).next().unwrap_or(name);
    let has_extension = match basename.rsplit_once('.') {
        Some((stem, extension)) => !stem.is_empty() && !extension.is_empty(),
        None => false,
    };
    if has_extension {
        return ResolvedFileName {
            text: name.to_string(),
            extension: None,
            source: NameSource::Original,
        };
    }
    match declared {
        Some(native) => ResolvedFileName {
            text: format!("{name}.{}", native.extension),
            extension: Some(native.extension),
            source: NameSource::Declared,
        },
        None => ResolvedFileName {
            text: name.to_string(),
            extension: None,
            source: NameSource::None,
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_archive_type_is_rpf_in_every_variant() {
        for variant in [Variant::Path, Variant::Alternate, Variant::Hash] {
            assert_eq!(extension(0, variant).unwrap().extension, "rpf");
        }
    }

    #[test]
    fn the_observed_texture_dictionary_type_is_ztd() {
        let extension = native_extension(5).expect("a texture dictionary extension");
        assert_eq!(extension.extension, "ztd");
        assert_eq!(extension.variant, Variant::Path);
    }

    #[test]
    fn the_observed_graphics_type_is_gfx() {
        assert_eq!(native_extension(66).unwrap().extension, "gfx");
    }

    #[test]
    fn the_second_table_covers_64_to_115() {
        assert_eq!(native_extension(64).unwrap().extension, "mrf");
        assert_eq!(native_extension(115).unwrap().extension, "zcov");
        assert_eq!(native_extension(63), None);
        assert_eq!(native_extension(116), None);
    }

    #[test]
    fn unregistered_ids_have_no_extension() {
        for type_id in [19u8, 20, 63, 116, 200, 254] {
            assert_eq!(native_extension(type_id), None, "type {type_id}");
        }
        assert_eq!(native_extension(NO_EXTENSION), None);
    }

    #[test]
    fn a_resolved_name_keeps_its_own_extension() {
        let name = file_name("packs/inner.rpf", Some(0));
        assert_eq!(name.text, "packs/inner.rpf");
        assert_eq!(name.source, NameSource::Original);
        // A dotted stem is not an extension the type may replace.
        let dotted = file_name("packs/v1.2/inner", Some(6));
        assert_eq!(dotted.text, "packs/v1.2/inner.zbn");
        assert_eq!(dotted.source, NameSource::Declared);
        let hidden = file_name(".gitignore", Some(6));
        assert_eq!(hidden.text, ".gitignore.zbn");
    }

    #[test]
    fn a_name_without_an_extension_takes_the_declared_one() {
        let name = file_name("packs/01_ai", Some(6));
        assert_eq!(name.text, "packs/01_ai.zbn");
        assert_eq!(name.extension, Some("zbn"));
        assert_eq!(name.source, NameSource::Declared);
        // An unobserved but registered type still declares its extension.
        assert_eq!(file_name("x", Some(112)).text, "x.znmd");
    }

    #[test]
    fn a_type_that_declares_nothing_gets_no_extension() {
        for type_id in [Some(255u8), Some(19), None] {
            let name = file_name("Unnamed Entries/Row 00042", type_id);
            assert_eq!(name.text, "Unnamed Entries/Row 00042");
            assert_eq!(name.extension, None, "{type_id:?}");
            assert_eq!(name.source, NameSource::None);
        }
    }

    #[test]
    fn every_registered_id_has_all_three_variants() {
        for type_id in (0..=18u8).chain(64..=115) {
            for variant in [Variant::Path, Variant::Alternate, Variant::Hash] {
                assert!(
                    extension(type_id, variant).is_some(),
                    "type {type_id} variant {}",
                    variant.name()
                );
            }
        }
    }

    #[test]
    fn variants_differ_only_where_the_engine_says_so() {
        // Extensions the engine stores once are the same in every variant.
        for type_id in [0u8, 64, 65, 66, 92, 97] {
            let path = native_extension(type_id).unwrap().extension;
            assert_eq!(
                extension(type_id, Variant::Alternate).unwrap().extension,
                path
            );
            assert_eq!(extension(type_id, Variant::Hash).unwrap().extension, path);
        }
        // The others differ between variants.
        assert_eq!(native_extension(5).unwrap().extension, "ztd");
        assert_eq!(extension(5, Variant::Hash).unwrap().extension, "#td");
    }
}

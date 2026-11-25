//! Tests on invented paths and synthetic decoded metadata.

use super::*;
use crate::rpf::metadata::keys;
use crate::rpf::metadata::tests::{Build, Column, record_a};

fn long(len: usize) -> Vec<u8> {
    let mut path = b"synthetic/".to_vec();
    path.resize(255, b'x');
    path.extend_from_slice(&b"yz"[..len - 255]);
    path
}

#[test]
fn folds_ascii_letters_and_backslashes_only() {
    for byte in 0..=255u8 {
        let expected = match byte {
            b'A'..=b'Z' => byte.to_ascii_lowercase(),
            b'\\' => b'/',
            _ => byte,
        };
        assert_eq!(fold(byte), expected, "{byte:#04x}");
    }
}

#[test]
fn hash64_vectors() {
    let cases: [(&[u8], u64); 12] = [
        (b"", 0),
        (b"alpha/beta/gamma", 0x7489_FBD9_4F2A_4C86),
        (b"ALPHA/BETA/GAMMA", 0x7489_FBD9_4F2A_4C86),
        (b"Alpha/Beta/Gamma", 0x7489_FBD9_4F2A_4C86),
        (b"alpha\\beta\\gamma", 0x7489_FBD9_4F2A_4C86),
        (b"Alpha\\beta/Gamma", 0x7489_FBD9_4F2A_4C86),
        (b"widget", 0x08E2_9CA2_FA83_C05A),
        (b"zone_a/sector_07/props/crate_small", 0xE6FF_B49A_3FF8_C68D),
        (b"ui/menu.v2.layout", 0x7825_5B90_7998_6159),
        (b"abcdefghijklmnop", 0xC4CA_3CA3_224C_B723),
        (b"abcdefghijklmnopq", 0x7564_747F_88BD_A657),
        (b"caf\xC3\xA9/item", 0xC580_3A91_8B18_D3ED),
    ];
    for (input, expected) in cases {
        assert_eq!(hash64(input), expected, "{}", input.escape_ascii());
    }
    // The published MurmurHash3 x64-128 value of "hello".
    assert_eq!(hash64(b"hello"), 0xCBD8_A7B3_41BD_9B02);
}

/// Vectors generated with the independent `mmh3` 5.3.1 package for
/// MurmurHash3_x64_128, seed 0, x64 architecture, first 64-bit word. Below 256
/// bytes the engine's low-byte length mixing equals the standard length, so
/// these check the block loop, tail, endianness and finalizer independently of
/// this implementation.
#[test]
fn hash64_matches_an_independent_implementation_below_256_bytes() {
    let cases: [(&[u8], u64); 11] = [
        (b"", 0x0000_0000_0000_0000),
        (b"hello", 0xCBD8_A7B3_41BD_9B02),
        (b"a", 0x8555_5565_F659_7889),
        (b"abc", 0xB496_3F3F_3FAD_7867),
        (b"alpha/beta/gamma", 0x7489_FBD9_4F2A_4C86),
        (b"widget", 0x08E2_9CA2_FA83_C05A),
        (b"ui/menu.v2.layout", 0x7825_5B90_7998_6159),
        (b"caf\xC3\xA9/item", 0xC580_3A91_8B18_D3ED),
        (b"sub/dir/item.name", 0x3FC6_02FC_F22D_7472),
        (b"dev:/synthetic/Packs/", 0x4F70_72CD_AD2C_FF1E),
        (&[b'x'; 100], 0x0404_E502_8859_6AE2),
    ];
    for (input, expected) in cases {
        assert_eq!(hash64(input), expected, "{}", input.escape_ascii());
    }
    // The last length where the engine's low-byte rule equals full-length
    // mixing also matches `mmh3`.
    assert_eq!(hash64(&long(255)), 0x7C9B_5EB2_48E0_7F31);
}

/// The engine-only length rule from 256 bytes on has no independent reference
/// implementation. These values follow RPF9-F56 and guard against regressions;
/// they are not external evidence.
#[test]
fn hash64_mixes_only_the_low_length_byte() {
    // Standard MurmurHash3 gives 0xC168A72B90FD64CC and 0xF73B45F99E163F09.
    assert_eq!(hash64(&long(256)), 0x7515_B6DF_B512_9164);
    assert_eq!(hash64(&long(257)), 0x018C_14B2_CF45_0E79);
}

#[test]
fn joaat_vectors() {
    let cases: [(&[u8], u32); 15] = [
        (b"", 0),
        (b"alpha/beta/gamma", 0x28E1_C03D),
        (b"ALPHA/BETA/GAMMA", 0x28E1_C03D),
        (b"Alpha\\beta/Gamma", 0x28E1_C03D),
        (b"widget", 0xF9E6_713D),
        (b"zone_a/sector_07/props/crate_small", 0x78AE_2FB1),
        (b"ui/menu.v2.layout", 0x17B3_A067),
        (b"abcdefghijklmnop", 0xAB9B_22BF),
        (b"abcdefghijklmnopq", 0x4599_DA44),
        (b"caf\xC3\xA9/item", 0xB53D_3A5D),
        // The published one-at-a-time value of "a".
        (b"a", 0xCA2E_9442),
        (b"\"alpha/beta\"tail", 0x7543_8640),
        (b"\"alpha/beta", 0x7543_8640),
        (b"alpha\"beta", 0x3ACF_4CC5),
        (b"\"", 0),
    ];
    for (input, expected) in cases {
        assert_eq!(joaat(input), expected, "{}", input.escape_ascii());
    }
    assert_eq!(joaat(b"alpha/beta"), 0x7543_8640);
    assert_eq!(joaat(&long(255)), 0x8BCF_F836);
    assert_eq!(joaat(&long(256)), 0xB3C4_A22E);
    assert_eq!(joaat(&long(257)), 0x6AAD_0AFF);
    assert_eq!(joaat(b"alpha/beta\0ignored"), joaat(b"alpha/beta"));
}

const ARCHIVE: &[u8] = b"dev:/synthetic/Packs/sample.rpf";

fn prefix() -> MountPrefix {
    MountPrefix::from_archive_path(ARCHIVE).unwrap()
}

#[test]
fn derives_mount_prefixes() {
    assert_eq!(
        prefix(),
        MountPrefix {
            len: 21,
            hash: 0x4F70_72CD_AD2C_FF1E
        }
    );
    let backslash = MountPrefix::from_archive_path(b"dev:\\synthetic\\Packs\\sample.rpf");
    assert_eq!(backslash, Some(prefix()));
    assert_eq!(
        MountPrefix::from_archive_path(b"sample.rpf"),
        Some(MountPrefix::EMPTY)
    );
    let memory = MountPrefix::from_archive_path(b"memory:blob:dir/sample.rpf").unwrap();
    assert_eq!(memory.len, b"memory:blob:".len());
    assert_eq!(memory.hash, hash64(b"memory:blob:"));
    assert_eq!(MountPrefix::from_archive_path(b"memory:blob"), None);
    assert_eq!(MountPrefix::from_archive_path(b"dev:/a\0/b.rpf"), None);

    let mut path = vec![b'd'; 300];
    path.extend_from_slice(b"/sample.rpf");
    let long = MountPrefix::from_archive_path(&path).unwrap();
    assert_eq!(long.len, MAX_PREFIX_LEN);
    assert_eq!(long.hash, hash64(&path[..MAX_PREFIX_LEN]));
}

fn resolve(types: &Types, path: &[u8]) -> Result<Address, Unresolved> {
    types.resolve(&prefix(), &Candidate::Path(path))
}

#[test]
fn resolves_the_documented_example() {
    let address = resolve(
        &Types::default(),
        b"dev:/synthetic/Packs/Sub\\Dir/Item.Name.rpf",
    )
    .unwrap();
    assert_eq!(address.key, Key::Hash64(0x3FC6_02FC_F22D_7472));
    assert_eq!(address.type_id, RPF_TYPE);
    assert_eq!(address.stem, b"Sub\\Dir/Item.Name");
    // Case and separators do not matter in the prefix or the stem.
    let folded = resolve(
        &Types::default(),
        b"DEV:\\SYNTHETIC\\packs\\sub/dir\\ITEM.NAME.rpf",
    )
    .unwrap();
    assert_eq!(folded.key, address.key);
}

#[test]
fn extensions_are_case_sensitive_and_never_guessed() {
    let types = Types::default();
    let path = b"dev:/synthetic/Packs/item.RPF";
    assert_eq!(
        resolve(&types, path),
        Err(Unresolved::UnknownExtension(b"RPF".to_vec()))
    );
    assert_eq!(
        resolve(&types, b"dev:/synthetic/Packs/item.ydr"),
        Err(Unresolved::UnknownExtension(b"ydr".to_vec()))
    );
    // The last `.` splits even inside a directory name.
    assert_eq!(
        resolve(&types, b"dev:/synthetic/Packs/dir.v2/item"),
        Err(Unresolved::UnknownExtension(b"v2/item".to_vec()))
    );
}

#[test]
fn caller_mappings_select_type_and_class() {
    let mut types = Types::default();
    types.insert_extension(b"ydr", 7);
    let path = b"dev:/synthetic/Packs/props/Crate.ydr";
    assert_eq!(resolve(&types, path), Err(Unresolved::UnknownClass(7)));
    types.insert_class(7, Class::Key32);
    let address = resolve(&types, path).unwrap();
    assert_eq!(address.key, Key::Key32(joaat(b"props/crate")));
    assert_eq!(address.type_id, 7);
    types.insert_class(7, Class::Hash64);
    assert_eq!(
        resolve(&types, path).unwrap().key,
        Key::Hash64(hash64(b"props/crate"))
    );
}

#[test]
fn untyped_paths_hash_the_whole_rest() {
    let mut types = Types::default();
    let address = resolve(&types, b"dev:/synthetic/Packs/notes/readme").unwrap();
    assert_eq!(address.key, Key::Key32(joaat(b"notes/readme")));
    assert_eq!(address.type_id, NO_TYPE);
    types.insert_extension(b"txt", NO_TYPE);
    let address = resolve(&types, b"dev:/synthetic/Packs/notes/readme.txt").unwrap();
    assert_eq!(address.key, Key::Key32(joaat(b"notes/readme.txt")));
    assert_eq!(address.stem, b"notes/readme.txt");
    // Setting a class for NO_TYPE does not change the resolver's rule.
    types.insert_class(NO_TYPE, Class::Hash64);
    assert_eq!(types.class(NO_TYPE), Some(Class::Key32));
}

#[test]
fn established_types_keep_their_class_and_confirmed_extension() {
    let types = Types::default();
    assert_eq!(types.class(RPF_TYPE), Some(Class::Hash64));
    for type_id in KEY32_TYPES {
        assert_eq!(types.class(type_id), Some(Class::Key32), "type {type_id}");
    }
    // The class is established for these observed types; their extensions are
    // not, so none is invented.
    assert_eq!(types.extension(RPF_TYPE), Some(&b"rpf"[..]));
    for type_id in KEY32_TYPES {
        assert_eq!(types.extension(type_id), None);
    }
    assert_eq!(types.class(NO_TYPE), Some(Class::Key32));
    assert_eq!(types.extension(NO_TYPE), None);
}

#[test]
fn relative_paths_are_checked_component_by_component() {
    assert_eq!(
        relative_path("packs/props/crate.ydr"),
        Some(vec!["packs", "props", "crate.ydr"])
    );
    assert_eq!(
        relative_path(r"packs\props\crate.ydr"),
        Some(vec!["packs", "props", "crate.ydr"])
    );
    for path in [
        "",
        "/absolute",
        "\\absolute",
        "a//b",
        "a/./b",
        "a/../b",
        "a\\..\\b",
        "c:drive",
        "a/<b>",
        "a/|b",
        "a/?b",
        "a/*b",
    ] {
        assert_eq!(relative_path(path), None, "{path}");
    }
}

#[test]
fn rejects_paths_outside_the_prefix() {
    let types = Types::default();
    for path in [
        &b"dev:/synthetic/Pack"[..],
        b"dev:/synthetic/Other/item.rpf",
        b"dev:/synthetic/Packs\0/item.rpf",
    ] {
        assert!(resolve(&types, path).is_err(), "{}", path.escape_ascii());
    }
    assert_eq!(
        resolve(&types, b"dev:/synthetic/Other/item.rpf"),
        Err(Unresolved::OutsidePrefix)
    );
    assert_eq!(
        resolve(&types, b"dev:/synthetic/Packs/a\0.rpf"),
        Err(Unresolved::Nul)
    );
}

struct Spec {
    type_id: u8,
    hash: Option<u64>,
    key: Option<u32>,
}

fn row(type_id: u8, hash: Option<u64>, key: Option<u32>) -> Spec {
    Spec { type_id, hash, key }
}

fn metadata(rows: &[Spec]) -> Metadata {
    let hashes: Vec<[u8; 8]> = rows
        .iter()
        .map(|r| r.hash.unwrap_or(0).to_le_bytes())
        .collect();
    let names: Vec<[u8; 4]> = rows
        .iter()
        .map(|r| r.key.unwrap_or(0).to_le_bytes())
        .collect();
    let locations: Vec<Vec<u8>> = rows
        .iter()
        .enumerate()
        .map(|(n, r)| record_a(1, n as u32, 0x10, r.type_id, 0))
        .collect();
    fn slices<T: AsRef<[u8]>>(values: &[T]) -> Vec<&[u8]> {
        values.iter().map(AsRef::as_ref).collect()
    }
    let present = |has: fn(&Spec) -> bool| {
        rows.iter()
            .enumerate()
            .map(|(n, r)| has(r).then_some(n as u32))
            .collect::<Vec<_>>()
    };
    let all: Vec<Option<u32>> = (0..rows.len() as u32).map(Some).collect();
    let columns = [
        Column::new(
            keys::NAME_HASH,
            8,
            &slices(&hashes),
            &present(|r| r.hash.is_some()),
        ),
        Column::new(
            keys::NAME_KEY,
            4,
            &slices(&names),
            &present(|r| r.key.is_some()),
        ),
        Column::new(keys::LOCATION_A, 16, &slices(&locations), &all),
    ];
    Build::default().metadata(&columns)
}

#[test]
fn reads_the_name_key_column() {
    let metadata = metadata(&[row(9, None, Some(0x1234_5678)), row(0, Some(1), None)]);
    assert_eq!(metadata.name_key(0).unwrap(), Some(0x1234_5678));
    assert_eq!(metadata.name_key(1).unwrap(), None);
}

#[test]
fn matches_candidates_to_rows() {
    let item = hash64(b"sub/dir/item.name");
    let metadata = metadata(&[
        row(RPF_TYPE, Some(item), None),
        row(RPF_TYPE, Some(hash64(b"unnamed")), None),
        row(7, None, Some(joaat(b"textures/sky"))),
        row(NO_TYPE, None, Some(joaat(b"readme"))),
        row(RPF_TYPE, Some(item), None),
        row(7, Some(item), None),
    ]);
    let mut types = Types::default();
    types.insert_extension(b"ytd", 7);
    types.insert_class(7, Class::Key32);
    let candidates = [
        Candidate::Path(b"dev:/synthetic/Packs/Sub/Dir/Item.Name.rpf"),
        Candidate::Path(b"dev:/synthetic/Packs/textures/sky.ytd"),
        Candidate::Path(b"dev:/synthetic/Packs/readme"),
        Candidate::Path(b"dev:/synthetic/Packs/SUB\\DIR\\ITEM.NAME.rpf"),
        Candidate::Path(b"dev:/synthetic/Packs/Sub/Dir/Item.Name.rpf"),
        Candidate::Stem {
            stem: b"\"readme\"suffix",
            type_id: NO_TYPE,
        },
        Candidate::Path(b"dev:/synthetic/Packs/missing.rpf"),
        Candidate::Path(b"dev:/synthetic/Packs/model.ydr"),
        Candidate::Stem {
            stem: b"sub/dir/item.name",
            type_id: 7,
        },
    ];
    let matches = match_candidates(&metadata, &prefix(), &types, &candidates).unwrap();

    let rows = |n: usize| matches.candidates[n].as_ref().unwrap().rows.clone();
    // Two rows share key and type: both are reported, in row order.
    assert_eq!(rows(0), [0, 4]);
    assert_eq!(rows(1), [2]);
    assert_eq!(rows(2), [3]);
    assert_eq!(rows(5), [3]);
    assert!(rows(6).is_empty());
    assert_eq!(
        matches.candidates[7],
        Err(Unresolved::UnknownExtension(b"ydr".to_vec()))
    );
    // Same stem hash, but the type's class reads the 32-bit key.
    assert!(rows(8).is_empty());

    let row = |n: usize| &matches.rows[n];
    // Duplicates and spellings that fold to the same stem are kept and are
    // not ambiguous.
    assert_eq!(row(0).candidates, [0, 3, 4]);
    assert!(!row(0).ambiguous);
    // Different stems with the same key are.
    assert_eq!(row(3).candidates, [2, 5]);
    assert!(row(3).ambiguous);
    // Unmatched rows keep their identity.
    assert_eq!(matches.rows.len(), 6);
    assert_eq!(
        *row(1),
        Row {
            index: 1,
            type_id: RPF_TYPE,
            name_hash: Some(hash64(b"unnamed")),
            name_key: None,
            candidates: Vec::new(),
            ambiguous: false,
        }
    );
    assert!(row(5).candidates.is_empty());
}

#[test]
fn nested_archives_use_their_own_directory() {
    // The parent row of the nested archive.
    let parent = metadata(&[row(RPF_TYPE, Some(hash64(b"sub/dir/item.name")), None)]);
    let nested_path: &[u8] = b"dev:/synthetic/Packs/Sub/Dir/Item.Name.rpf";
    let found = match_candidates(
        &parent,
        &prefix(),
        &Types::default(),
        &[Candidate::Path(nested_path)],
    )
    .unwrap();
    assert_eq!(found.rows[0].candidates, [0]);

    // Its entries are addressed under the directory of its path, not under
    // its file name.
    let nested = metadata(&[row(RPF_TYPE, Some(hash64(b"inner")), None)]);
    let nested_prefix = MountPrefix::from_archive_path(nested_path).unwrap();
    assert_eq!(nested_prefix.len, b"dev:/synthetic/Packs/Sub/Dir/".len());
    let candidates = [
        Candidate::Path(b"dev:/synthetic/Packs/Sub/Dir/inner.rpf"),
        Candidate::Path(b"dev:/synthetic/Packs/Sub/Dir/Item.Name/inner.rpf"),
        Candidate::Path(b"dev:/synthetic/Packs/inner.rpf"),
    ];
    let matches =
        match_candidates(&nested, &nested_prefix, &Types::default(), &candidates).unwrap();
    assert_eq!(matches.rows[0].candidates, [0]);
    assert!(matches.candidates[1].as_ref().unwrap().rows.is_empty());
    assert_eq!(matches.candidates[2], Err(Unresolved::OutsidePrefix));
}

#[test]
fn validates_explicit_mount_prefixes() {
    let mount = MountPrefix::mounted(b"platform:/mnt/").unwrap();
    assert_eq!(mount.len, 14);
    assert_eq!(mount.hash, hash64(b"platform:/mnt/"));
    assert_eq!(MountPrefix::mounted(b"PLATFORM:\\MNT\\"), Some(mount));
    let mut longest = vec![b'p'; MAX_MOUNT_PREFIX_LEN - 1];
    longest.push(b'/');
    assert!(MountPrefix::mounted(&longest).is_some());
    let mut too_long = vec![b'p'; MAX_MOUNT_PREFIX_LEN];
    too_long.push(b'\\');
    for prefix in [
        &b""[..],
        b"platform:/mnt",
        b"default",
        b"plat\0form:/",
        &too_long,
    ] {
        assert_eq!(
            MountPrefix::mounted(prefix),
            None,
            "{}",
            prefix.escape_ascii()
        );
    }
}

#[test]
fn the_effective_prefix_selects_the_paths() {
    let metadata = metadata(&[row(RPF_TYPE, Some(hash64(b"props/item")), None)]);
    let candidates = [
        Candidate::Path(b"dev:/synthetic/Packs/props/item.rpf"),
        Candidate::Path(b"platform:/mnt/props/item.rpf"),
        Candidate::Path(b"Platform:\\Mnt\\Props\\Item.rpf"),
    ];
    let match_with = |prefix: &MountPrefix| {
        match_candidates(&metadata, prefix, &Types::default(), &candidates).unwrap()
    };

    // The same archive, unmounted: the default from its path applies.
    let default = match_with(&prefix());
    assert_eq!(default.rows[0].candidates, [0]);
    assert_eq!(default.candidates[1], Err(Unresolved::OutsidePrefix));

    // Mounted: the mount prefix replaces the default.
    let mounted = match_with(&MountPrefix::mounted(b"platform:/mnt/").unwrap());
    assert_eq!(mounted.rows[0].candidates, [1, 2]);
    assert!(!mounted.rows[0].ambiguous);
    assert_eq!(mounted.candidates[0], Err(Unresolved::OutsidePrefix));
}

#[test]
fn nested_archives_can_be_mounted() {
    let nested = metadata(&[row(RPF_TYPE, Some(hash64(b"inner")), None)]);
    let mount = MountPrefix::mounted(b"nested:/").unwrap();
    let candidates = [
        Candidate::Path(b"nested:/inner.rpf"),
        Candidate::Path(b"nested:/Item.Name/inner.rpf"),
        Candidate::Path(b"dev:/synthetic/Packs/Sub/Dir/inner.rpf"),
    ];
    let matches = match_candidates(&nested, &mount, &Types::default(), &candidates).unwrap();
    assert_eq!(matches.rows[0].candidates, [0]);
    assert!(matches.candidates[1].as_ref().unwrap().rows.is_empty());
    assert_eq!(matches.candidates[2], Err(Unresolved::OutsidePrefix));
}

#[test]
fn without_an_archive_path_candidates_are_relative() {
    let metadata = metadata(&[row(RPF_TYPE, Some(hash64(b"pack/item")), None)]);
    let candidates = [
        Candidate::Path(b"pack/item.rpf"),
        Candidate::Stem {
            stem: b"Pack\\Item",
            type_id: RPF_TYPE,
        },
    ];
    let matches = match_candidates(
        &metadata,
        &MountPrefix::EMPTY,
        &Types::default(),
        &candidates,
    )
    .unwrap();
    assert_eq!(matches.rows[0].candidates, [0, 1]);
    assert!(!matches.rows[0].ambiguous);
}

#[test]
fn reports_malformed_rows() {
    let columns = [Column::new(keys::NAME_HASH, 8, &[&[0; 8]], &[Some(0)])];
    let metadata = Build::default().metadata(&columns);
    let result = match_candidates(&metadata, &MountPrefix::EMPTY, &Types::default(), &[]);
    assert!(matches!(result, Err(Error::Invalid(_))));
}

use super::*;

fn extract(xml: &str) -> DocumentExtraction {
    extract_document(xml.as_bytes()).expect("document parses")
}

#[test]
fn reads_performance_fields_without_assigning_a_unit() {
    let document = extract(
        r#"<?xml version="1.0" encoding="UTF-8"?>
        <CVehiclePerformanceMaps>
          <Map>
            <Item key="TestCar">
              <topSpeed value="27.500000" />
              <accelZeroSixty value="2.833000" />
            </Item>
          </Map>
        </CVehiclePerformanceMaps>"#,
    );
    assert!(document.recognized);
    assert_eq!(document.root, "CVehiclePerformanceMaps");
    assert_eq!(document.observations.len(), 1);
    let observation = &document.observations[0];
    assert_eq!(observation.category, Category::Vehicles);
    assert_eq!(observation.entity_type, "vehicle");
    assert_eq!(observation.internal_name, "TestCar");
    assert_eq!(observation.display_name, None);
    let speed = &observation.fields["topSpeed"];
    assert_eq!(speed.value, Value::Number(27.5));
    assert_eq!(speed.unit, None);
    assert_eq!(speed.semantics, "source_number");
    assert_eq!(
        observation.source_path,
        "/CVehiclePerformanceMaps/Map/Item[@key='TestCar']"
    );
}

#[test]
fn reads_recorded_heights_in_metres() {
    let document = extract(
        r#"<CPedVariationBodyTypeManager>
          <HeightPresets>
            <Item key="HUMAN">
              <HeightsInMeters content="float_array">1.52 1.82</HeightsInMeters>
            </Item>
          </HeightPresets>
          <ScaleProfiles>
            <Item key="MALE">
              <HeightPresets>HUMAN</HeightPresets>
              <DefaultHeightMeters value="1.82" />
            </Item>
          </ScaleProfiles>
        </CPedVariationBodyTypeManager>"#,
    );
    assert_eq!(document.observations.len(), 2);
    let preset = &document.observations[0];
    assert_eq!(preset.entity_type, "ped_height_preset");
    assert_eq!(
        preset.fields["heightsMeters"].value,
        Value::NumberList(vec![1.52, 1.82])
    );
    assert_eq!(preset.fields["heightsMeters"].unit.as_deref(), Some("m"));
    let profile = &document.observations[1];
    assert_eq!(
        profile.fields["defaultHeightMeters"].unit.as_deref(),
        Some("m")
    );
}

#[test]
fn reads_weapon_groups_ammunition_and_names_from_a_damage_document() {
    let document = extract(
        r#"<CDamageDataManager>
          <DamageModifiers>
            <Item>
              <Condition>
                <WeaponTypes><Item>WEAPON_PISTOL</Item><Item>NOT_A_WEAPON</Item></WeaponTypes>
                <WeaponGroups><Item>GROUP_PISTOL</Item></WeaponGroups>
                <AmmoTypes><Item>AMMO_PISTOL</Item></AmmoTypes>
              </Condition>
            </Item>
          </DamageModifiers>
        </CDamageDataManager>"#,
    );
    assert!(document.recognized);
    let names = document
        .observations
        .iter()
        .map(|observation| {
            (
                observation.entity_type.as_str(),
                observation.internal_name.as_str(),
            )
        })
        .collect::<Vec<_>>();
    assert_eq!(
        names,
        vec![
            ("weapon_type", "WEAPON_PISTOL"),
            ("weapon_group", "GROUP_PISTOL"),
            ("ammo_type", "AMMO_PISTOL"),
        ]
    );
    assert_eq!(document.observations[0].category, Category::Weapons);
}

#[test]
fn a_repeated_identifier_from_two_paths_is_one_observation() {
    let document = extract(
        r#"<CDamageDataManager>
          <A><WeaponTypes><Item>WEAPON_PISTOL</Item></WeaponTypes></A>
          <B><WeaponTypes><Item>WEAPON_PISTOL</Item></WeaponTypes></B>
        </CDamageDataManager>"#,
    );
    assert_eq!(document.observations.len(), 1);
    assert_eq!(document.observations[0].internal_name, "WEAPON_PISTOL");
}

#[test]
fn a_missing_field_stays_missing() {
    let document = extract(
        r#"<CVehicleBaseRatingsAndEstimatesMap><Map><Item key="Car"><fStrengthRating value="0.5" /></Item></Map></CVehicleBaseRatingsAndEstimatesMap>"#,
    );
    let observation = &document.observations[0];
    assert!(!observation.fields.contains_key("ratingsRoad.fSpeedRating"));
    assert_eq!(
        observation.fields["fStrengthRating"].value,
        Value::Number(0.5)
    );
}

#[test]
fn a_non_finite_value_is_reported_as_text_not_a_number() {
    let document = extract(
        r#"<CVehicleBaseRatingsAndEstimatesMap><Map><Item key="Car"><fAccelerationTime value="inf" /></Item></Map></CVehicleBaseRatingsAndEstimatesMap>"#,
    );
    let field = &document.observations[0].fields["fAccelerationTime"];
    assert_eq!(field.value, Value::Text("inf".to_string()));
    assert_eq!(field.semantics, "source_text_non_finite");
}

#[test]
fn an_unrecognised_root_is_not_guessed() {
    let document =
        extract("<CVehicleDistantLightData><distantLights /></CVehicleDistantLightData>");
    assert!(document.recognized);
    assert!(document.observations.is_empty());
    let document = extract("<SomethingElse><Item>value</Item></SomethingElse>");
    assert!(!document.recognized);
}

#[test]
fn a_utf8_bom_is_accepted_and_malformed_xml_is_rejected() {
    let mut bytes = b"\xEF\xBB\xBF".to_vec();
    bytes.extend_from_slice(
        b"<CVehicleDistantLightData><recipeLights /></CVehicleDistantLightData>",
    );
    let document = extract_document(&bytes).expect("BOM is accepted");
    assert_eq!(document.root, "CVehicleDistantLightData");
    assert!(extract_document(b"<CVehicleDistantLightData>").is_err());
}

#[test]
fn base_ratings_are_grouped_by_their_element() {
    let document = extract(
        r#"<CVehicleBaseRatingsAndEstimatesMap><Map><Item key="Car">
          <ratingsRoad><fSpeedRating value="11.2" /></ratingsRoad>
          <fStrengthRating value="0.55" />
        </Item></Map></CVehicleBaseRatingsAndEstimatesMap>"#,
    );
    let observation = &document.observations[0];
    assert_eq!(
        observation.fields["ratingsRoad.fSpeedRating"].value,
        Value::Number(11.2)
    );
    assert_eq!(
        observation.fields["fStrengthRating"].value,
        Value::Number(0.55)
    );
}

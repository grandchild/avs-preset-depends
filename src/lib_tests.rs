use super::*;

static TEST_RESOURCE_SPECS_DATA: [(CompID, ResourceSpec); 1] = [(
    CompID::Builtin(0),
    ResourceSpec {
        name: "Offset 0, Length 1",
        offset: FieldOffset::Constant(0),
        ftype: FieldType::NtStr(1),
        rtype: ResourceType::Image,
        empty_significance: EmptyIs::Error,
        treat_as_empty: None,
    },
)];

#[test]
#[ignore]
fn test_get_depends() {}

#[test]
#[ignore]
fn test_scan_dirs_and_preset_files() {}

#[test]
#[ignore]
fn test_scan_preset_file() {}

#[test]
fn test_scan_components_simple() {
    let resource_specs = HashMap::from(TEST_RESOURCE_SPECS_DATA);
    //          |ID:0   |len:1    |str
    let buf = b"\0\0\0\0\x01\0\0\0A\0".to_vec();
    let results =
        scan_components(&buf, 0, buf.len(), &"".to_string(), &resource_specs).unwrap();
    for Resource {
        string,
        rtype,
        available: _,
    } in results
    {
        assert_eq!(string, "A",);
        assert_eq!(rtype, ResourceType::Image);
    }
}

#[test]
fn test_scan_components_offset() {
    let resource_specs = HashMap::from(TEST_RESOURCE_SPECS_DATA);
    //          |ID:0   |len:1    |str
    let buf = b"\0\0\0\0\x01\0\0\0A\0".to_vec();
    let results =
        scan_components(&buf, 0, buf.len(), &"".to_string(), &resource_specs).unwrap();
    for Resource {
        string,
        rtype,
        available: _,
    } in results
    {
        assert_eq!(string, "A");
        assert_eq!(rtype, ResourceType::Image);
    }
}

#[test]
fn get_component_len_and_id_zero_zero() -> Result<(), String> {
    let buf = b"\0\0\0\0\0\0\0\0";
    let (len, id) = get_component_len_and_id(&buf.to_vec(), 0)?;
    assert_eq!(len, 0, "length not 0");
    assert_eq!(id, CompID::Builtin(0), "id not Bultin(0)");
    Ok(())
}
#[test]
fn get_component_len_and_id_empty() {
    let empty = get_component_len_and_id(&b"".to_vec(), 0);
    assert_eq!(empty, Err("Preset ended prematurely"), "empty buf");
}
#[test]
fn get_component_len_and_id_builtin_7_bytes() {
    let seven = get_component_len_and_id(&b"\0\0\0\0\0\0\0".to_vec(), 0);
    assert_eq!(seven, Err("Preset ended prematurely"), "builtin 7 bytes");
}
#[test]
fn get_component_len_and_id_ape_8_bytes() {
    let ape_id_but_too_short = b"\0\x40\0\0\0\0\0\0";
    let ape_id_8 = get_component_len_and_id(&ape_id_but_too_short.to_vec(), 0);
    assert_eq!(ape_id_8, Err("Preset ended prematurely"), "APE 8 bytes");
}
#[test]
fn get_component_len_and_id_ape_39_bytes() {
    #[rustfmt::skip]
    let ape_id_one_byte_short = [
        // Effect id
        0, 0x40, 0, 0,
        // APE id
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        // Size 
        0, 0, 0, // <- one byte short
    ];
    let ape_id_39 = get_component_len_and_id(&ape_id_one_byte_short.to_vec(), 0);
    assert_eq!(ape_id_39, Err("Preset ended prematurely"), "APE 39 bytes");
}

#[test]
fn test_i32_from_u8arr_values() {
    let cases = [
        (b"\0\0\0\0", 0i32),
        (b"\x01\0\0\0", 1i32),
        (b"\xff\xff\xff\xff", -1i32),
        (b"\xff\xff\xff\x7f", i32::MAX),
        (b"\0\0\0\x80", i32::MIN),
    ];
    for (input, expected) in cases {
        let result = i32_from_u8arr(input, 0);
        assert_eq!(result, expected, "case {input:?}");
    }
}

#[test]
fn test_i32_from_u8arr_offset() {
    let input = b"\0\0\0\0\x80\0\0\0\0";
    let expected = [0, -0x80_00_00_00, 0x80_00_00, 0x80_00, 0x80];
    for offset in 0..=4 {
        let result = i32_from_u8arr(input, offset);
        assert_eq!(result, expected[offset], "offset: {offset}");
    }
}

#[test]
fn test_usize32_from_u8arr_values() {
    let cases = [
        (b"\0\0\0\0", 0usize),
        (b"\x01\0\0\0", 1usize),
        (b"\xff\xff\xff\xff", u32::MAX as usize),
    ];
    for (input, expected) in cases {
        let result = usize32_from_u8arr(input, 0);
        assert_eq!(result, expected, "case {input:?}");
    }
}

#[test]
fn test_usize32_from_u8arr_offset() {
    let input = b"\0\0\0\0\x80\0\0\0\0";
    let expected = [0, 0x80_00_00_00, 0x80_00_00, 0x80_00, 0x80];
    for offset in 0..=4 {
        let result = usize32_from_u8arr(input, offset);
        assert_eq!(result, expected[offset], "offset: {offset}");
    }
}

#[test]
#[ignore]
fn test_string_from_u8vec_ntstr1252() {}

#[test]
#[ignore]
fn test_string_from_u8vec_sizestr1252() {}

#[test]
#[ignore]
fn test_get_globalvars_filename_offset() {}

#[test]
#[ignore]
fn test_win1252_decode() {}

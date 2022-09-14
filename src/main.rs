use std::collections::HashMap;
use std::collections::HashSet;
use std::env;
use std::fs::metadata;
use std::fs::read_dir;
use std::fs::File;
use std::io::Read;
use std::os::unix::ffi::OsStrExt;
use std::path::Path;

use encoding_rs::WINDOWS_1252;

mod iterable_enum;
use iterable_enum::IterableEnum;
use iterable_enum_derive::IterableEnum;

static AVS_HEADER_01: &[u8] = b"Nullsoft AVS Preset 0.1\x1a";
static AVS_HEADER_02: &[u8] = b"Nullsoft AVS Preset 0.2\x1a";
static AVS_HEADER_LEN: usize = AVS_HEADER_02.len();
const AVS_APE_SEPARATOR: i32 = 0x4000;
const AVS_APE_ID_LEN: usize = 32;
static AVS_EL28_HEADER: &[u8] = b"\0@\0\0AVS 2.8+ Effect List Config\0\0\0\0\0";
static AVS_EL28_HEADER_LEN: usize = AVS_EL28_HEADER.len();
const SIZE_INT32: usize = (i32::BITS / 8) as usize;
const WIN32_MAX_PATH: usize = 260;

#[derive(Eq, Hash, PartialEq, Clone, Copy)]
enum CompID {
    Builtin(i32),
    Ape([u8; AVS_APE_ID_LEN]),
}
#[derive(Clone, Copy)]
enum FieldType {
    NtStr(/*max_len*/ usize),
    // SizeStr,
    Function(fn(&Vec<u8>, usize) -> String),
}
#[derive(Eq, Hash, PartialEq, Clone, Copy, IterableEnum)]
enum ResourceType {
    Image,
    Video,
    Ape,
    Font,
    Dll,
    GenericFile,
}
#[derive(Clone, Copy)]
enum Empty {
    IsDefault,
    IsCommon,
    IsRare,
    IsError,
}
#[derive(Clone, Copy)]
struct ResourceSpec {
    name: &'static str,
    offset: usize,
    ftype: FieldType,
    rtype: ResourceType,
    empty_significance: Empty,
}
#[derive(Eq, Hash, PartialEq, Clone)]
struct Resource {
    string: String,
    rtype: ResourceType,
}

// static mut RESOURCE_SPECS: &HashMap<CompID, ResourceSpec>;
static RESOURCE_SPECS_DATA: [(CompID, ResourceSpec); 9] = [
    (
        CompID::Builtin(10),
        ResourceSpec {
            name: "SVP",
            offset: 0,
            ftype: FieldType::NtStr(WIN32_MAX_PATH),
            rtype: ResourceType::Dll,
            empty_significance: Empty::IsRare,
        },
    ),
    (
        CompID::Builtin(28),
        ResourceSpec {
            name: "Text",
            offset: 132,
            ftype: FieldType::NtStr(32),
            rtype: ResourceType::Font,
            empty_significance: Empty::IsDefault,
        },
    ),
    (
        CompID::Builtin(32),
        ResourceSpec {
            name: "AVI",
            offset: 12,
            ftype: FieldType::NtStr(WIN32_MAX_PATH),
            rtype: ResourceType::Video,
            empty_significance: Empty::IsError,
        },
    ),
    (
        CompID::Builtin(34),
        ResourceSpec {
            name: "Picture",
            offset: 20,
            ftype: FieldType::NtStr(WIN32_MAX_PATH),
            rtype: ResourceType::Image,
            empty_significance: Empty::IsError,
        },
    ),
    (
        CompID::Ape(*b"Texer\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0"),
        ResourceSpec {
            name: "Texer",
            offset: 16,
            ftype: FieldType::NtStr(WIN32_MAX_PATH),
            rtype: ResourceType::Image,
            empty_significance: Empty::IsDefault,
        },
    ),
    (
        CompID::Ape(*b"Acko.net: Texer II\0\0\0\0\0\0\0\0\0\0\0\0\0\0"),
        ResourceSpec {
            name: "Texer II",
            offset: 4,
            ftype: FieldType::NtStr(WIN32_MAX_PATH),
            rtype: ResourceType::Image,
            empty_significance: Empty::IsDefault,
        },
    ),
    (
        CompID::Ape(*b"VFX AVI PLAYER\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0"),
        ResourceSpec {
            name: "AVI Player",
            offset: 0,
            ftype: FieldType::NtStr(256),
            rtype: ResourceType::Video,
            empty_significance: Empty::IsError,
        },
    ),
    (
        CompID::Ape(*b"Jheriko: Global\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0"),
        ResourceSpec {
            name: "Global Variables",
            offset: 0xBAD0FF5E7,
            ftype: FieldType::Function(get_global_vars_file_name),
            rtype: ResourceType::GenericFile,
            empty_significance: Empty::IsCommon,
        },
    ),
    (
        CompID::Ape(*b"Picture II\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0"),
        ResourceSpec {
            name: "Picture II",
            offset: 0,
            ftype: FieldType::NtStr(WIN32_MAX_PATH),
            rtype: ResourceType::Image,
            empty_significance: Empty::IsError,
        },
    ),
];

fn main() {
    let resource_specs = HashMap::from(RESOURCE_SPECS_DATA);
    let args: Vec<String> = env::args().collect();
    for arg in &args[1..] {
        let resources = &scan_dirs_and_preset_files(Path::new(&arg), &resource_specs);
        println!("{arg}:");
        for t in ResourceType::items() {
            let mut section_header_printed = false;
            for Resource { string, rtype } in resources {
                if rtype == &t {
                    if !section_header_printed {
                        println!("  {t}s:");
                        section_header_printed = true;
                    }
                    if needs_quote_for_yaml(&string) {
                        let escaped_string = string.escape_default();
                        println!("    - \"{escaped_string}\"");
                    } else {
                        println!("    - {string}");
                    }
                }
            }
        }
    }
}

fn scan_dirs_and_preset_files(
    file_path: &Path,
    resource_specs: &HashMap<CompID, ResourceSpec>,
) -> HashSet<Resource> {
    if file_path.is_dir() {
        let mut resources: HashSet<Resource> = HashSet::new();
        let dir_listing = match read_dir(file_path) {
            Err(why) => {
                eprintln!("Cannot list directory {file_path:?} ({why})");
                return resources;
            }
            Ok(listing) => listing,
        };
        for entry in dir_listing {
            match entry {
                Err(ref why) => {
                    eprintln!("Cannot read file entry {entry:?} ({why})");
                    continue;
                }
                Ok(entry) => {
                    resources =
                        &resources | &scan_dirs_and_preset_files(&entry.path(), resource_specs);
                }
            }
        }
        return resources;
    } else {
        let file_path_str = match file_path.to_str() {
            None => {
                let bytes = file_path.as_os_str().as_bytes();
                let (cow, _, has_errors) = WINDOWS_1252.decode(&bytes);
                if has_errors {
                    eprintln!(
                        "Path is neither UTF-8- nor Windows1252-/latin1-encoded {file_path:?}"
                    );
                    return HashSet::new();
                }
                cow.to_string()
            }
            Some(string) => string.to_string(),
        };
        if file_path_str.ends_with(".avs") {
            return scan_preset_file(file_path, &file_path_str, resource_specs);
        }
        return HashSet::new();
    }
}

fn scan_preset_file(
    file_path: &Path,
    file_path_str: &String,
    resource_specs: &HashMap<CompID, ResourceSpec>,
) -> HashSet<Resource> {
    let empty = HashSet::new();
    let mut preset_file = match File::open(file_path) {
        Err(why) => {
            eprintln!("Cannot open file {file_path_str:?} ({why})");
            return empty;
        }
        Ok(file) => file,
    };
    let preset_len = match metadata(file_path) {
        Err(why) => {
            eprintln!("Cannot read properties for file {file_path_str:?} ({why})");
            return empty;
        }
        Ok(file_metadata) => file_metadata.len() as usize,
    };
    let mut preset_bytes: Vec<u8> = Vec::with_capacity(preset_len);
    match preset_file.read_to_end(&mut preset_bytes) {
        Err(why) => {
            eprintln!("Cannot read from file {file_path_str:?} ({why})");
            return empty;
        }
        Ok(_n) => (),
    }
    if preset_len < AVS_HEADER_LEN {
        eprintln!("File too short '{file_path_str}'");
        return empty;
    }
    let header = &preset_bytes[0..AVS_HEADER_LEN];
    let mut pos: usize = AVS_HEADER_LEN;
    if header != AVS_HEADER_02 && header != AVS_HEADER_01 {
        eprintln!("Header wrong in '{file_path_str}'");
        return empty;
    }
    pos += 1; // "Clear Every Frame"
    scan_components(
        &preset_bytes,
        pos,
        preset_len,
        file_path_str,
        resource_specs,
    )
}

fn scan_components(
    buf: &Vec<u8>,
    mut pos: usize,
    max_pos: usize,
    file_path_str: &String,
    resource_specs: &HashMap<CompID, ResourceSpec>,
) -> HashSet<Resource> {
    let mut resources = HashSet::new();
    while pos < max_pos {
        let (len, id) = match get_component_len_and_id(&buf, pos) {
            Err(_why) => break,
            Ok((len, id)) => (len, id),
        };
        match id {
            CompID::Builtin(_) => pos += SIZE_INT32 * 2,
            CompID::Ape(id) => {
                pos += SIZE_INT32 * 2 + AVS_APE_ID_LEN;
                let string = string_from_u8vec_ntstr1252(&Vec::from(id), 0, AVS_APE_ID_LEN);
                if string.len() > 2 {
                    // TODO: Check what's up with empty APE IDs!
                    resources.insert(Resource {
                        string,
                        rtype: ResourceType::Ape,
                    });
                }
            }
        };
        match resource_specs.get(&id) {
            Some(spec) => {
                let string = match spec.ftype {
                    FieldType::NtStr(max_len) => {
                        string_from_u8vec_ntstr1252(buf, pos + spec.offset, max_len)
                    }
                    // FieldType::SizeStr => string_from_u8vec_sizestr1252(buf, pos + spec.offset),
                    FieldType::Function(f) => f(buf, pos),
                };
                if string.is_empty() {
                    if let Empty::IsError | Empty::IsRare = spec.empty_significance {
                        eprintln!(
                            "{} {} is empty in '{file_path_str}' @0x{pos:x}",
                            spec.name, spec.rtype,
                        )
                    }
                }
                if !string.is_empty() {
                    resources.insert(Resource {
                        string,
                        rtype: spec.rtype,
                    });
                }
            }
            None => match id {
                CompID::Builtin(-2) => {
                    let mut offset = pos;
                    offset += (buf[offset + 4] as usize) + 1; // config
                    if buf.len() > offset + AVS_EL28_HEADER_LEN {
                        let el_header = &buf[offset..offset + AVS_EL28_HEADER_LEN];
                        if el_header == AVS_EL28_HEADER {
                            offset += AVS_EL28_HEADER_LEN;
                            let code_size = usize32_from_u8arr(buf, offset);
                            offset += code_size; // code size
                            offset += SIZE_INT32;
                        }
                    }
                    resources = &resources
                        | &scan_components(buf, offset, pos + len, file_path_str, resource_specs);
                }
                _ => {}
            },
        }
        pos += len;
    }
    resources
}

fn get_component_len_and_id(
    buf: &Vec<u8>,
    mut pos: usize,
) -> Result<(usize, CompID), &'static str> {
    if pos + SIZE_INT32 >= buf.len() {
        return Err("Preset ended prematurely");
    }
    let component_code = i32_from_u8arr(buf, pos);
    pos += SIZE_INT32;
    let id = match component_code {
        AVS_APE_SEPARATOR.. => CompID::Ape(*u8arr_fixed_slice::<AVS_APE_ID_LEN>(buf, pos)),
        _ => CompID::Builtin(component_code),
    };
    if component_code >= AVS_APE_SEPARATOR {
        pos += AVS_APE_ID_LEN;
    }
    let component_len: usize = usize32_from_u8arr(buf, pos);
    Ok((component_len, id))
}

fn i32_from_u8arr(arr: &Vec<u8>, pos: usize) -> i32 {
    i32::from_le_bytes(arr[pos..pos + SIZE_INT32].try_into().unwrap())
}
fn usize32_from_u8arr(arr: &Vec<u8>, pos: usize) -> usize {
    u32::from_le_bytes(arr[pos..pos + SIZE_INT32].try_into().unwrap()) as usize
}
fn u8arr_fixed_slice<const LENGTH: usize>(arr: &Vec<u8>, pos: usize) -> &[u8; LENGTH] {
    arr[pos..pos + LENGTH].try_into().unwrap()
}
fn string_from_u8vec_ntstr1252(arr: &Vec<u8>, start: usize, max_len: usize) -> String {
    let mut end: usize = start;
    loop {
        match arr[end] {
            1.. => end += 1,
            0 => break,
        }
        if end - start > max_len {
            break;
        }
    }
    let (cow, _, _) = WINDOWS_1252.decode(&arr[start..end]);
    cow.to_string()
}
// fn string_from_u8vec_sizestr1252(arr: &Vec<u8>, pos: usize) -> String {
//     let str_size = usize32_from_u8arr(arr, pos);
//     let (cow, _, _) = WINDOWS_1252.decode(&arr[pos + SIZE_INT32..pos + SIZE_INT32 + str_size]);
//     cow.to_string()
//     // String::from_utf8_lossy(&arr[pos + SIZE_INT32..pos + SIZE_INT32 + str_size]).to_string()
// }

fn get_global_vars_file_name(buf: &Vec<u8>, pos: usize) -> String {
    let mut file_str_start = pos + 4 + 24;
    // Init, Frame, Beat
    for _ in 0..3 {
        loop {
            match buf[file_str_start] {
                1.. => file_str_start += 1,
                0 => {
                    file_str_start += 1;
                    break;
                }
            }
        }
    }
    string_from_u8vec_ntstr1252(buf, file_str_start, WIN32_MAX_PATH)
}

fn needs_quote_for_yaml(string: &str) -> bool {
    if string.is_empty() {
        return true;
    }
    let mut is_number = true;
    let mut no_number_separator_yet = true;
    for c in string.chars() {
        match c {
            '0'..='9' => (),
            '.' | 'e' if no_number_separator_yet => no_number_separator_yet = false,
            'x' if string.starts_with("0x") && no_number_separator_yet => {
                no_number_separator_yet = false
            }
            _ => {
                is_number = false;
                break;
            }
        }
    }
    let special_start_chars = [
        '.', '&', '*', '?', '|', '-', '<', '>', '=', '!', '%', '@', '`', '{', '[', '\'', ' ', '#',
    ];
    is_number
        || string.starts_with(special_start_chars)
        || string.contains(": ")
        || string.contains(|c: char| match c {
            '\0'..='\x1f' => true,
            _ => false,
        })
        || string.ends_with([' ', ':'])
        || ["yes", "no", "true", "false", "on", "off", "null", "~"]
            .contains(&string.to_lowercase().as_str())
}

impl std::fmt::Debug for FieldType {
    fn fmt(&self, fmt: &mut std::fmt::Formatter) -> std::fmt::Result {
        match &self {
            FieldType::NtStr(max_len) => write!(fmt, "FieldType::NtStr (max: {max_len})"),
            // FieldType::SizeStr => write!(fmt, "FieldType::SizeStr"),
            FieldType::Function(_) => write!(fmt, "FieldType::Function"),
        }
    }
}

impl std::fmt::Debug for CompID {
    fn fmt(&self, fmt: &mut std::fmt::Formatter) -> std::fmt::Result {
        match &self {
            CompID::Builtin(id) => write!(fmt, "Builtin {}/0x{:02x}", id, id),
            CompID::Ape(id) => write!(
                fmt,
                "APE '{}'",
                string_from_u8vec_ntstr1252(&id.to_vec(), 0, AVS_APE_ID_LEN)
            ),
        }
    }
}

impl std::fmt::Display for ResourceType {
    fn fmt(&self, fmt: &mut std::fmt::Formatter) -> std::fmt::Result {
        match &self {
            ResourceType::Image => write!(fmt, "Image"),
            ResourceType::Video => write!(fmt, "Video"),
            ResourceType::Ape => write!(fmt, "APE"),
            ResourceType::Font => write!(fmt, "Font"),
            ResourceType::Dll => write!(fmt, "DLL"),
            ResourceType::GenericFile => write!(fmt, "File"),
        }
    }
}

impl std::fmt::Display for Resource {
    fn fmt(&self, fmt: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(fmt, "{} {}", self.rtype, self.string)
    }
}

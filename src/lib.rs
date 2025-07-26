/*!
Scan Winamp AVS presets for any files they might need.

Scan individual files or whole directories.

Usage examples:

    use preset_depends::get_depends;
    use preset_depends::Resource;

    let paths = vec!["/my/presets/preset.avs".to_owned()];
    let resources_for_paths = get_depends(&paths, None);
    for (_path, resources) in resources_for_paths {
        for Resource{string, ..} in resources {
            println!("{string}");
        }
    }

or

    use preset_depends::get_depends;
    use preset_depends::Resource;
    let paths = vec![
        "/my/presets/".to_owned(),
        "/my_other/presets/".to_owned()
    ];
    let winamp_dir = "/path/to/Winamp/Plugins/avs/".to_owned();
    let resources_for_paths = get_depends(&paths, Some(&winamp_dir));
    // etc. See above.

`get_depends()` returns a map from each of the `paths` given to the resources needed by
the presets found within.
*/
#![warn(clippy::missing_docs_in_private_items)]

use std::collections::BTreeSet;
use std::collections::HashMap;
use std::fs::metadata;
use std::fs::read_dir;
use std::fs::File;
use std::io::Read;
use std::path::Path;

#[cfg(target_family = "unix")]
use std::os::unix::ffi::OsStrExt;

#[cfg(test)]
mod lib_tests;

/// Ancient AVS preset file magic.
const AVS_HEADER_01: &[u8] = b"Nullsoft AVS Preset 0.1\x1a";

/// Latest AVS preset file magic.
const AVS_HEADER_02: &[u8] = b"Nullsoft AVS Preset 0.2\x1a";

/// Length of the AVS preset file magic.
const AVS_HEADER_LEN: usize = AVS_HEADER_02.len();

/// Builtin IDs must be lower than this. To mark a section as an APE section the ID must
/// be equal to or larger that this.
///
/// The APE ID _string_ starts after this ID.
const AVS_APE_SEPARATOR: i32 = 0x00004000;

/// The maximum length of an APE ID string.
///
/// Actual IDs are all shorter, and the rest is filled with zero.
const AVS_APE_ID_LEN: usize = 32;

/// Effect List "APE" Header.
///
/// Modern Effect Lists contain this "APE" as a first member which is then merged into
/// the Effect List itself.
const AVS_EL28_HEADER: &[u8] = b"\0@\0\0AVS 2.8+ Effect List Config\0\0\0\0\0";

/// Length of the Effect List "APE" Header.
const AVS_EL28_HEADER_LEN: usize = AVS_EL28_HEADER.len();

/// Length of a i32 in bytes.
const SIZE_INT32: usize = (i32::BITS / 8) as usize;

/// Maximum length of path strings in old Windows versions. `"C:\"` + 256 path chars +
/// `'\0'`.
const WIN32_MAX_PATH: usize = 260;

/// The ID of an effect. Either an int32 for builtin effects or a string for plugin
/// ("APE") effects.
#[derive(Hash, Eq, PartialEq, Clone, Copy)]
enum CompID {
    /// Builtin IDs range from 0 to ~45, with two special values: -2 for Effect List
    /// (the only component which can have child components) and -1 for an unknown
    /// effect. Builtin IDs must not be higher than [AVS_APE_SEPARATOR].
    Builtin(i32),
    /// The string field for APEs in a preset file is always 32 chars, with unneeded
    /// trailing chars filled with zero.
    Ape([u8; AVS_APE_ID_LEN]),
}

/// The data shape of the resource field in the effect.
#[derive(Clone, Copy)]
enum FieldType {
    /// All currently implemented resources are null-terminated strings with a maximum
    /// string length
    NtStr(/*max_len*/ usize),
    /// Some AVS effects use size-prefixed strings but none of the effects scanned for
    /// here do that, but future changes might use it.
    #[allow(dead_code)]
    SizeStr,
}

/// The offset into the effect save data where the resource string starts. Usually a
/// static offset from the start, but some effects are more complicated.
#[derive(Clone, Copy)]
enum FieldOffset {
    /// A static offset into the buffer, relative to the effect's starting position.
    Constant(usize),
    /// A resource might be at a non-constant offset. Then a function can be given to
    /// retrieve its offset with more flexibility.
    Function(fn(&[u8], usize) -> usize),
}

/// The type of the resource pointed to.
#[derive(Hash, Eq, PartialEq, Ord, PartialOrd, Clone, Copy, Debug)]
// #[derive(Debug)] needed by unit tests
pub enum ResourceType {
    /// An image file.
    Image,
    /// A video file.
    Video,
    /// A plugin-effect (APE) identifier. This is not the `.ape` filename.
    Ape,
    /// A font name.
    Font,
    /// A Sonique Visualization Plugin effect DLL.
    Dll,
    /// Any other file (currently only GlobalVariables' code includes).
    GenericFile,
}

/// The significance of an empty resource field.
#[derive(Clone, Copy)]
enum EmptyIs {
    /// An empty resource will use the baked-in default resource (e.g. _TexerII_ image).
    Default,
    /// Setting a resource is optional and not having one is common.
    Common,
    /// An effect will do nothing without a resource, but it happens often enough.
    /// (Currently this just behaves the same as `Error` and is only a hint.)
    Rare,
    /// An effect will do nothing without a resource. Print the offending preset and
    /// file position to stderr.
    Error,
}

/// Name of the effect and where to find its resource.
#[derive(Clone, Copy)]
struct ResourceSpec {
    /// The effects display name.
    name: &'static str,
    /// The offset into the effect's save data where the resource string starts.
    offset: FieldOffset,
    /// The shape of the resource string.
    ftype: FieldType,
    /// The type of the retrieved resource.
    rtype: ResourceType,
    /// What does not finding a resource mean?
    empty_significance: EmptyIs,
    /// A value to disregard and treat as empty.
    treat_as_empty: Option<&'static str>,
}

/// The availability of a resource on-disk.
#[derive(Hash, Eq, PartialEq, Ord, PartialOrd, Clone, Copy, Debug)]
pub enum ResourceAvailable {
    /// The resource hasn't been searched for yet, or it won't be.
    Undetermined,
    /// Resource is available as a file.
    Yes,
    /// Resource file is not present in given Winamp dir.
    No,
    /// Resource is not a file. (Currently this always implies [ResourceType::Font]).
    NotApplicable,
}

/// The value and type of a resource.
#[derive(Hash, Eq, PartialEq, Clone, Ord, PartialOrd)]
pub struct Resource {
    /// The type of the resource pointed to.
    pub rtype: ResourceType,
    /// The filename, font name or ID of a resource.
    pub string: String,
    /// The availability on-disk, if applicable
    pub available: ResourceAvailable,
}

/// An APE plugin binary file on disk with its ASCII strings.
struct ApeBinary {
    /// The path to the APE file.
    filename: String,
    /// Strings of at least a minimum length found in the binary.
    strings: Vec<String>,
}

/// A resource file on disk
struct ResourceFile {
    /// The lowercase filename for comparison
    filename: String,
    /// The full original path, relative to the given Winamp directory.
    path: String,
}

/// A list of selected AVS effects with resources, keyed by their `CompID`s.
///
/// This list of tuples will be turned into a [HashMap] at the beginning of
/// [get_depends], because they can't be statically initialized in Rust (yet?).
const RESOURCE_SPECS_DATA: [(CompID, ResourceSpec); 9] = [
    (
        CompID::Builtin(10),
        ResourceSpec {
            name: "SVP",
            offset: FieldOffset::Constant(0),
            ftype: FieldType::NtStr(WIN32_MAX_PATH),
            rtype: ResourceType::Dll,
            empty_significance: EmptyIs::Rare,
            treat_as_empty: None,
        },
    ),
    (
        CompID::Builtin(28),
        ResourceSpec {
            name: "Text",
            offset: FieldOffset::Constant(132),
            ftype: FieldType::NtStr(32),
            rtype: ResourceType::Font,
            empty_significance: EmptyIs::Default,
            treat_as_empty: None,
        },
    ),
    (
        CompID::Builtin(32),
        ResourceSpec {
            name: "AVI",
            offset: FieldOffset::Constant(12),
            ftype: FieldType::NtStr(WIN32_MAX_PATH),
            rtype: ResourceType::Video,
            empty_significance: EmptyIs::Error,
            treat_as_empty: None,
        },
    ),
    (
        CompID::Builtin(34),
        ResourceSpec {
            name: "Picture",
            offset: FieldOffset::Constant(20),
            ftype: FieldType::NtStr(WIN32_MAX_PATH),
            rtype: ResourceType::Image,
            empty_significance: EmptyIs::Error,
            treat_as_empty: None,
        },
    ),
    (
        CompID::Ape(*b"Texer\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0"),
        ResourceSpec {
            name: "Texer",
            offset: FieldOffset::Constant(16),
            ftype: FieldType::NtStr(WIN32_MAX_PATH),
            rtype: ResourceType::Image,
            empty_significance: EmptyIs::Default,
            treat_as_empty: None,
        },
    ),
    (
        CompID::Ape(*b"Acko.net: Texer II\0\0\0\0\0\0\0\0\0\0\0\0\0\0"),
        ResourceSpec {
            name: "Texer II",
            offset: FieldOffset::Constant(4),
            ftype: FieldType::NtStr(WIN32_MAX_PATH),
            rtype: ResourceType::Image,
            empty_significance: EmptyIs::Default,
            // A few rare presets have, through some bug, saved a literal
            // '(default image)' as image filename.
            treat_as_empty: Some("(default image)"),
        },
    ),
    (
        CompID::Ape(*b"VFX AVI PLAYER\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0"),
        ResourceSpec {
            name: "AVI Player",
            offset: FieldOffset::Constant(0),
            ftype: FieldType::NtStr(256),
            rtype: ResourceType::Video,
            empty_significance: EmptyIs::Error,
            treat_as_empty: None,
        },
    ),
    (
        CompID::Ape(*b"Jheriko: Global\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0"),
        ResourceSpec {
            name: "Global Variables",
            offset: FieldOffset::Function(get_globalvars_filename_offset),
            ftype: FieldType::NtStr(WIN32_MAX_PATH),
            rtype: ResourceType::GenericFile,
            empty_significance: EmptyIs::Common,
            treat_as_empty: None,
        },
    ),
    (
        CompID::Ape(*b"Picture II\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0"),
        ResourceSpec {
            name: "Picture II",
            offset: FieldOffset::Constant(0),
            ftype: FieldType::NtStr(WIN32_MAX_PATH),
            rtype: ResourceType::Image,
            empty_significance: EmptyIs::Error,
            treat_as_empty: None,
        },
    ),
];

/// A list of APE ID strings for plugins that used to be external at some point but are
/// now builtin to AVS proper.
const KNOWN_BUILTIN_APES: [&str; 18] = [
    "AVS 2.8+ Effect List Config",
    "Nullsoft MIRROR v1",
    "Nullsoft Picture Rendering v1",
    "Winamp AVIAPE v1",
    "Winamp Brightness APE v1",
    "Winamp Bump v1",
    "Winamp ClearScreen APE v1",
    "Winamp Grain APE v1",
    "Winamp Interf APE v1",
    "Winamp Interleave APE v1",
    "Winamp Mosaic v1",
    "Winamp Starfield v1",
    "Winamp Text v1",
    "Channel Shift",
    "Color Reduction",
    "Multiplier",
    "Holden04: Video Delay",
    "Holden05: Multi Delay",
];

/// Scan the given `paths` and return all resources for any AVS preset file found in
/// each path. A path may be a preset file or a directory.
///
/// If additionally a `winamp_dir` path is given, then all the files in it will be
/// scanned. Any resource that is a file (i.e. not fonts) will be searched for in the
/// list and if found, the complete path is reported instead of just the filename.
pub fn get_depends<'a>(
    paths: &'a Vec<String>,
    winamp_dir: Option<&String>,
) -> HashMap<&'a String, BTreeSet<Resource>> {
    let resource_specs = HashMap::from(RESOURCE_SPECS_DATA);
    let (resource_files, ape_files) = match winamp_dir {
        Some(ref winamp_dir) => {
            let winamp_dir_path = Path::new(winamp_dir);
            (
                find_resource_files(winamp_dir_path),
                find_ape_files(winamp_dir_path),
            )
        }
        None => (Vec::new(), Vec::new()),
    };
    let mut depends: HashMap<&String, BTreeSet<Resource>> = HashMap::new();
    for path in paths {
        match scan_dirs_and_preset_files(Path::new(&path), &resource_specs) {
            Ok(resources) => {
                if !resource_files.is_empty() || !ape_files.is_empty() {
                    // intermediate move to vector, you can't edit values in a set.
                    let mut vec_resources: Vec<_> = resources.into_iter().collect();
                    resolve_resource_filenames(
                        &mut vec_resources,
                        &resource_files,
                        &ape_files,
                    );
                    // now back to a set because we want the resources sorted.
                    depends.insert(path, vec_resources.into_iter().collect());
                } else {
                    depends.insert(path, resources);
                }
            }
            Err(why) => eprintln!("{why}"),
        }
    }
    depends
}

/// Check if the given path is an AVS file or a directory, collect resources therein
/// (in case of directories recursively) and return them.
///
/// In case of any permission errors return the empty set.
fn scan_dirs_and_preset_files(
    file_path: &Path,
    resource_specs: &HashMap<CompID, ResourceSpec>,
) -> Result<BTreeSet<Resource>, String> {
    if file_path.is_dir() {
        let mut resources: BTreeSet<Resource> = BTreeSet::new();
        let dir_listing = match read_dir(file_path) {
            Err(why) => {
                return Err(format!("Cannot list directory {file_path:?} ({why})"));
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
                    match scan_dirs_and_preset_files(&entry.path(), resource_specs) {
                        Ok(new_resources) => resources = &resources | &new_resources,
                        Err(why) => eprintln!("{why}"),
                    }
                }
            }
        }
        Ok(resources)
    } else {
        let file_path_str = decode_path_str(file_path);
        if file_path_str.ends_with(".avs") {
            return scan_preset_file(file_path, &file_path_str, resource_specs);
        }
        Ok(BTreeSet::new())
    }
}

/// Read a binary file and return it as a list of `u8` bytes.
fn read_binary_file(
    file_path: &Path,
    file_path_str: &String,
) -> Result<Vec<u8>, String> {
    let mut preset_file = match File::open(file_path) {
        Err(why) => {
            return Err(format!("Cannot open file {file_path_str:?} ({why})"));
        }
        Ok(file) => file,
    };
    let preset_len = match metadata(file_path) {
        Err(why) => {
            return Err(format!(
                "Cannot read properties for file {file_path_str:?} ({why})"
            ));
        }
        Ok(file_metadata) => file_metadata.len() as usize,
    };
    let mut preset_bytes: Vec<u8> = Vec::with_capacity(preset_len);
    match preset_file.read_to_end(&mut preset_bytes) {
        Err(why) => {
            return Err(format!("Cannot read from file {file_path_str:?} ({why})"));
        }
        Ok(_n) => (),
    }
    Ok(preset_bytes)
}

/// Return a set of all resources referenced in the preset.
///
/// If the preset file is inaccessible or invalid return the empty set.
fn scan_preset_file(
    file_path: &Path,
    file_path_str: &String,
    resource_specs: &HashMap<CompID, ResourceSpec>,
) -> Result<BTreeSet<Resource>, String> {
    let preset_bytes = read_binary_file(file_path, file_path_str)?;
    if preset_bytes.len() < AVS_HEADER_LEN {
        return Err(format!("File too short '{file_path_str}'"));
    }
    let header = &preset_bytes[0..AVS_HEADER_LEN];
    let mut pos: usize = AVS_HEADER_LEN;
    if header != AVS_HEADER_02 && header != AVS_HEADER_01 {
        return Err(format!("Header wrong in '{file_path_str}'"));
    }
    pos += 1; // "Clear Every Frame"
    scan_components(
        &preset_bytes,
        pos,
        preset_bytes.len(),
        file_path_str,
        resource_specs,
    )
}

/// Recursively walk the preset tree and find any effects that have resources.
///
/// Return any resources found, or an empty set.
fn scan_components(
    buf: &Vec<u8>,
    mut pos: usize,
    max_pos: usize,
    file_path_str: &String,
    resource_specs: &HashMap<CompID, ResourceSpec>,
) -> Result<BTreeSet<Resource>, String> {
    let mut resources = BTreeSet::new();
    while pos < max_pos {
        let (len, id) = match get_component_len_and_id(buf, pos) {
            Err(_why) => break,
            Ok((len, id)) => (len, id),
        };
        match id {
            CompID::Builtin(_) => pos += SIZE_INT32 * 2,
            CompID::Ape(id) => {
                pos += SIZE_INT32 * 2 + AVS_APE_ID_LEN;
                let string =
                    string_from_u8vec_ntstr1252(&Vec::from(id), 0, AVS_APE_ID_LEN);
                if string.len() > 2 && !KNOWN_BUILTIN_APES.contains(&string.as_str()) {
                    resources.insert(Resource {
                        string,
                        rtype: ResourceType::Ape,
                        available: ResourceAvailable::Undetermined,
                    });
                } else {
                    // TODO: Check what's up with empty APE IDs!
                }
            }
        };
        match resource_specs.get(&id) {
            Some(spec) => {
                let offset = match spec.offset {
                    FieldOffset::Constant(offset) => offset,
                    FieldOffset::Function(offset_func) => offset_func(buf, pos),
                };
                let string = match spec.ftype {
                    FieldType::NtStr(max_len) => {
                        string_from_u8vec_ntstr1252(buf, pos + offset, max_len)
                    }
                    FieldType::SizeStr => {
                        string_from_u8vec_sizestr1252(buf, pos + offset)
                    }
                };
                if string.is_empty() {
                    if let EmptyIs::Error | EmptyIs::Rare = spec.empty_significance {
                        eprintln!(
                            "{} {} is empty in '{file_path_str}' @0x{pos:x}",
                            spec.name, spec.rtype,
                        )
                    }
                }
                if !string.is_empty() && Some(string.as_str()) != spec.treat_as_empty {
                    resources.insert(Resource {
                        string,
                        rtype: spec.rtype,
                        available: ResourceAvailable::Undetermined,
                    });
                }
            }
            None => {
                if let CompID::Builtin(-2) = id {
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
                    match scan_components(
                        buf,
                        offset,
                        pos + len,
                        file_path_str,
                        resource_specs,
                    ) {
                        Ok(new_resources) => resources = &resources | &new_resources,
                        Err(why) => eprintln!("{why}"),
                    }
                }
            }
        }
        pos += len;
    }
    Ok(resources)
}

/// Decode the byte array at `pos` as an AVS effect ID and its serialized length.
///
/// Every effect starts with its ID (an i32, either the builtin effect's ID or some
/// arbitrary number > [AVS_APE_SEPARATOR]). In APE effect sections the APE ID string
/// follows (see [CompID] for details). Next comes the length of the effect's section
/// in the preset file (an i32 again).
///
/// The distinction between builtin effect and APE is done by comparison with
/// [AVS_APE_SEPARATOR]. If the `ID >= AVS_APE_SEPARATOR` then the data starting after
/// this integer is evaluated as ASCII string, which is the APE ID.
///
/// The exact value of the first ID in an APE section is actually a stack pointer from
/// within AVS and because the x86 stack grows from the top of the process's memory
/// range downwards, realistically values are always well above [AVS_APE_SEPARATOR].
fn get_component_len_and_id(
    buf: &Vec<u8>,
    mut pos: usize,
) -> Result<(usize, CompID), &'static str> {
    if pos + SIZE_INT32 * 2 > buf.len() {
        return Err("Preset ended prematurely");
    }
    let component_code = i32_from_u8arr(buf, pos);
    pos += SIZE_INT32;
    let id = match component_code {
        AVS_APE_SEPARATOR.. => {
            if pos + SIZE_INT32 + AVS_APE_ID_LEN > buf.len() {
                println!("{}, {}", pos + AVS_APE_ID_LEN, buf.len());
                return Err("Preset ended prematurely");
            }
            CompID::Ape(*u8arr_fixed_slice::<AVS_APE_ID_LEN>(buf, pos))
        }
        _ => CompID::Builtin(component_code),
    };
    if component_code >= AVS_APE_SEPARATOR {
        pos += AVS_APE_ID_LEN;
    }
    let component_len: usize = usize32_from_u8arr(buf, pos);
    Ok((component_len, id))
}

/// List all files within `path` as a tuple of their filename and complete path strings.
/// This is a breadth-first traversal, i.e. files closer to the root path will be listed
/// first.
fn find_resource_files(path: &Path) -> Vec<ResourceFile> {
    match find_resource_files_checked(path) {
        Ok(files) => files,
        Err(why) => {
            eprintln!("{why}");
            Vec::new()
        }
    }
}

/// List all files within `path`. [Result]-typed version of [find_resource_files].
fn find_resource_files_checked(path: &Path) -> Result<Vec<ResourceFile>, String> {
    if path.is_dir() {
        let dir_listing = match read_dir(path) {
            Err(why) => {
                return Err(format!("Cannot list directory {path:?} ({why})"));
            }
            Ok(listing) => listing,
        };
        let mut files: Vec<ResourceFile> = Vec::new();
        for entry in dir_listing {
            let file_or_dir = match entry {
                Err(ref why) => {
                    eprintln!("Cannot read file entry {entry:?} ({why})");
                    continue;
                }
                Ok(entry) => entry,
            };
            match find_resource_files_checked(&file_or_dir.path()) {
                Ok(mut nested_files) => files.append(&mut nested_files),
                Err(why) => eprintln!("{why}"),
            }
        }
        Ok(files)
    } else {
        match decode_path_filename_str(path) {
            Some(filename) => Ok(vec![ResourceFile {
                filename: filename.to_lowercase(),
                path: decode_path_str(path),
            }]),
            None => Err(format!("Path '{path:?}' has no filename part.")),
        }
    }
}

/// Find all .ape files within `winamp_dir` and collect their contained ASCII strings.
fn find_ape_files(winamp_dir: &Path) -> Vec<ApeBinary> {
    let mut ape_files: Vec<ApeBinary> = Vec::new();
    let dir_listing = match read_dir(winamp_dir) {
        Err(why) => {
            eprintln!("Cannot list directory {winamp_dir:?} ({why})");
            return ape_files;
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
                if !entry.path().is_dir() {
                    let file_path_str = decode_path_str(&entry.path());
                    if file_path_str.ends_with(".ape") {
                        ape_files.push(ApeBinary {
                            filename: file_path_str.clone(),
                            strings: collect_ape_file_c_strings(
                                &entry.path(),
                                file_path_str,
                            ),
                        });
                    }
                }
            }
        }
    }
    ape_files
}

/// Go through a binary .ape file and return a list of byte strings of least length 6
/// (including null) that decode to only printable ASCII characters.
fn collect_ape_file_c_strings(file_path: &Path, file_path_str: String) -> Vec<String> {
    let mut strings: Vec<String> = Vec::new();
    let ape_file_bytes = match read_binary_file(file_path, &file_path_str) {
        Err(why) => {
            eprintln!("{}", why);
            return strings;
        }
        Ok(bytes) => bytes,
    };
    let mut cur_string = String::new();
    for byte in ape_file_bytes {
        match byte {
            0x20..=0x7e => {
                cur_string.push(byte as char);
            }
            _ => {
                // "Texer\0" is the shortest known APE ID string
                if cur_string.len() > 6 && cur_string.len() < AVS_APE_ID_LEN {
                    strings.push(cur_string);
                }
                cur_string = String::new();
            }
        }
    }
    strings
}

/// Search for matching files in the given `winamp_dir` or, for APE effects, for
/// matching APE plugin files from APE ID strings.
fn resolve_resource_filenames(
    resources: &mut Vec<Resource>,
    resource_files: &Vec<ResourceFile>,
    ape_files: &Vec<ApeBinary>,
) {
    for resource in resources {
        match resource.rtype {
            ResourceType::Image
            | ResourceType::Video
            | ResourceType::Dll
            | ResourceType::GenericFile => {
                if let Some(resource_filename) =
                    find_resource_file_match(&resource.string, resource_files)
                {
                    resource.string = resource_filename;
                    resource.available = ResourceAvailable::Yes;
                } else {
                    resource.available = ResourceAvailable::No;
                }
            }
            ResourceType::Ape => {
                if let Some(ape_file) = find_ape_file_match(&resource.string, ape_files)
                {
                    resource.string = ape_file.filename.clone();
                    resource.available = ResourceAvailable::Yes;
                } else {
                    resource.available = ResourceAvailable::No;
                }
            }
            ResourceType::Font => (),
        }
    }
}

/// Search for a resource file in the given directory, recursively.
fn find_resource_file_match(
    search: &str,
    resource_files: &Vec<ResourceFile>,
) -> Option<String> {
    let lower_search = search.to_lowercase();
    for ResourceFile { filename, path } in resource_files {
        if *filename == lower_search {
            return Some(path.clone());
        }
    }
    None
}

/// Search for an APE ID string in all APE files' strings and return the reference to
/// the first matching one, if any.
fn find_ape_file_match<'a>(
    ape_id_str: &String,
    ape_files: &'a Vec<ApeBinary>,
) -> Option<&'a ApeBinary> {
    for ape_file in ape_files {
        for string in ape_file.strings.iter() {
            if string.starts_with(ape_id_str) {
                return Some(ape_file);
            }
        }
    }
    None
}

/// Decode 4 bytes of the byte array starting at `pos` as a signed 32bit integer.
fn i32_from_u8arr(arr: &[u8], pos: usize) -> i32 {
    i32::from_le_bytes(arr[pos..pos + SIZE_INT32].try_into().unwrap())
}
/// Decode 4 bytes of the byte array starting at `pos` as an unsigned 32-bit integer.
///
/// Cast to usize is safe, because currently Rust has no target platforms of less than
/// 32bit width.
fn usize32_from_u8arr(arr: &[u8], pos: usize) -> usize {
    u32::from_le_bytes(arr[pos..pos + SIZE_INT32].try_into().unwrap()) as usize
}
/// Turn a slice of a byte array into a fixed-size array.
///
/// Needed to type-correctly compare a section of the preset file contents with the
/// static fixed-size APE ID strings.
fn u8arr_fixed_slice<const LENGTH: usize>(arr: &[u8], pos: usize) -> &[u8; LENGTH] {
    arr[pos..pos + LENGTH].try_into().unwrap()
}
/// Decode the byte array starting at `pos` as a null-terminated string.
fn string_from_u8vec_ntstr1252(arr: &[u8], start: usize, max_len: usize) -> String {
    let mut end: usize = start;
    while let 1.. = arr[end] {
        end += 1;
        if end - start > max_len {
            break;
        }
    }
    win1252_decode(&arr[start..end])
}
/// Decode the byte array starting at `pos` as a size-prefixed string.
#[allow(dead_code)]
fn string_from_u8vec_sizestr1252(arr: &[u8], pos: usize) -> String {
    let str_size = usize32_from_u8arr(arr, pos);
    win1252_decode(&arr[pos + SIZE_INT32..pos + SIZE_INT32 + str_size])
}

/// Return the offset for the code include filename for the GlobalVariables APE effect.
///
/// The offset depends on the size of the preceding code fields, so scan through Init,
/// Frame and Beat code strings first, and return the resulting offset from the start
/// of the save section.
fn get_globalvars_filename_offset(buf: &[u8], pos: usize) -> usize {
    let mut file_str_start: usize = pos + 4 + 24;
    for _ in ["Init", "Frame", "Beat"] {
        while let 1.. = buf[file_str_start] {
            file_str_start += 1;
        }
        file_str_start += 1;
    }
    file_str_start - pos
}

/// Decode a path string as UTF-8 or, if that fails, as Win1252 (which cannot fail, it
/// can only be wrong).
#[cfg(target_family = "unix")]
fn decode_path_str(path: &Path) -> String {
    match path.to_str() {
        None => win1252_decode(path.as_os_str().as_bytes()),
        Some(string) => string.to_string(),
    }
}

/// Decode a path's file_name as UTF-8 or, if that fails, as Win1252 (which cannot fail,
/// it can only be wrong).
#[cfg(target_family = "unix")]
fn decode_path_filename_str(path: &Path) -> Option<String> {
    path.file_name().map(|file_name| match file_name.to_str() {
        None => win1252_decode(file_name.as_bytes()),
        Some(string) => string.to_string(),
    })
}

/// Decode a path string as UTF-8. On Windows this cannot fail, i.e. all paths are UTF-8
/// or UTF-16? Unsure.
#[cfg(target_family = "windows")]
fn decode_path_str(path: &Path) -> String {
    path.to_str()
        .expect("This path should be valid UTF-8!")
        .to_string()
}

/// Decode a path's file_name as UTF-8. On Windows this cannot fail, i.e. all paths are
/// UTF-8 or UTF-16? Unsure.
#[cfg(target_family = "windows")]
fn decode_path_filename_str(path: &Path) -> Option<String> {
    path.file_name().map(|file_name| {
        file_name
            .to_str()
            .expect("This filename should be valid UTF-8!")
            .to_string()
    })
}

/// Decode a byte array into a [String] assuming a Windows1252 encoding.
fn win1252_decode(bytes: &[u8]) -> String {
    let mut decoded = String::with_capacity(bytes.len());
    for b in bytes {
        decoded.push(char::from_u32(WINDOWS_1252_CP[*b as usize]).unwrap());
    }
    decoded
}

/// Translation table from Windows1252 encoding to UTF-8 codepoints.
static WINDOWS_1252_CP: [u32; 256] = [
    0x0000, 0x0001, 0x0002, 0x0003, 0x0004, 0x0005, 0x0006, 0x0007, 0x0008, 0x0009,
    0x000A, 0x000B, 0x000C, 0x000D, 0x000E, 0x000F, 0x0010, 0x0011, 0x0012, 0x0013,
    0x0014, 0x0015, 0x0016, 0x0017, 0x0018, 0x0019, 0x001A, 0x001B, 0x001C, 0x001D,
    0x001E, 0x001F, 0x0020, 0x0021, 0x0022, 0x0023, 0x0024, 0x0025, 0x0026, 0x0027,
    0x0028, 0x0029, 0x002A, 0x002B, 0x002C, 0x002D, 0x002E, 0x002F, 0x0030, 0x0031,
    0x0032, 0x0033, 0x0034, 0x0035, 0x0036, 0x0037, 0x0038, 0x0039, 0x003A, 0x003B,
    0x003C, 0x003D, 0x003E, 0x003F, 0x0040, 0x0041, 0x0042, 0x0043, 0x0044, 0x0045,
    0x0046, 0x0047, 0x0048, 0x0049, 0x004A, 0x004B, 0x004C, 0x004D, 0x004E, 0x004F,
    0x0050, 0x0051, 0x0052, 0x0053, 0x0054, 0x0055, 0x0056, 0x0057, 0x0058, 0x0059,
    0x005A, 0x005B, 0x005C, 0x005D, 0x005E, 0x005F, 0x0060, 0x0061, 0x0062, 0x0063,
    0x0064, 0x0065, 0x0066, 0x0067, 0x0068, 0x0069, 0x006A, 0x006B, 0x006C, 0x006D,
    0x006E, 0x006F, 0x0070, 0x0071, 0x0072, 0x0073, 0x0074, 0x0075, 0x0076, 0x0077,
    0x0078, 0x0079, 0x007A, 0x007B, 0x007C, 0x007D, 0x007E, 0x007F,
    // Second half excerpted from encoding_rs
    0x20AC, 0x0081, 0x201A, 0x0192, 0x201E, 0x2026, 0x2020, 0x2021, 0x02C6, 0x2030,
    0x0160, 0x2039, 0x0152, 0x008D, 0x017D, 0x008F, 0x0090, 0x2018, 0x2019, 0x201C,
    0x201D, 0x2022, 0x2013, 0x2014, 0x02DC, 0x2122, 0x0161, 0x203A, 0x0153, 0x009D,
    0x017E, 0x0178, 0x00A0, 0x00A1, 0x00A2, 0x00A3, 0x00A4, 0x00A5, 0x00A6, 0x00A7,
    0x00A8, 0x00A9, 0x00AA, 0x00AB, 0x00AC, 0x00AD, 0x00AE, 0x00AF, 0x00B0, 0x00B1,
    0x00B2, 0x00B3, 0x00B4, 0x00B5, 0x00B6, 0x00B7, 0x00B8, 0x00B9, 0x00BA, 0x00BB,
    0x00BC, 0x00BD, 0x00BE, 0x00BF, 0x00C0, 0x00C1, 0x00C2, 0x00C3, 0x00C4, 0x00C5,
    0x00C6, 0x00C7, 0x00C8, 0x00C9, 0x00CA, 0x00CB, 0x00CC, 0x00CD, 0x00CE, 0x00CF,
    0x00D0, 0x00D1, 0x00D2, 0x00D3, 0x00D4, 0x00D5, 0x00D6, 0x00D7, 0x00D8, 0x00D9,
    0x00DA, 0x00DB, 0x00DC, 0x00DD, 0x00DE, 0x00DF, 0x00E0, 0x00E1, 0x00E2, 0x00E3,
    0x00E4, 0x00E5, 0x00E6, 0x00E7, 0x00E8, 0x00E9, 0x00EA, 0x00EB, 0x00EC, 0x00ED,
    0x00EE, 0x00EF, 0x00F0, 0x00F1, 0x00F2, 0x00F3, 0x00F4, 0x00F5, 0x00F6, 0x00F7,
    0x00F8, 0x00F9, 0x00FA, 0x00FB, 0x00FC, 0x00FD, 0x00FE, 0x00FF,
];

impl std::fmt::Debug for FieldType {
    fn fmt(&self, fmt: &mut std::fmt::Formatter) -> std::fmt::Result {
        match &self {
            FieldType::NtStr(max_len) => {
                write!(fmt, "FieldType::NtStr (max: {max_len})")
            }
            FieldType::SizeStr => write!(fmt, "FieldType::SizeStr"),
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
                string_from_u8vec_ntstr1252(id.as_ref(), 0, AVS_APE_ID_LEN)
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

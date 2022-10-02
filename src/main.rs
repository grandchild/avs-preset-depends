use preset_depends::get_depends;
use preset_depends::Arguments;
use preset_depends::Resource;

fn main() {
    let mut args: Arguments = argh::from_env();
    let resources_for_paths = get_depends(&mut args);
    for (path, resources) in resources_for_paths {
        println!("{}:", quote_yaml_string_if_needed(path));
        let mut last_resource_type = None;
        for Resource { string, rtype } in &resources {
            if Some(rtype) != last_resource_type {
                println!("  {rtype}s:");
            }
            println!("    - {}", quote_yaml_string_if_needed(string));
            last_resource_type = Some(rtype);
        }
    }
}

/// Add quotes around the string and escapes as needed if the string would otherwise
/// violate YAML's requirements for a bare string. If not, return the string unchanged.
fn quote_yaml_string_if_needed(string: &str) -> String {
    if string.is_empty() {
        return String::from("\"\"");
    }
    let mut is_number = true;
    let mut is_hex_number = false;
    let mut no_number_separator_yet = true;
    for c in string.chars() {
        match c {
            '0'..='9' => (),
            'a'..='f' if is_hex_number => (),
            '.' | 'e' if no_number_separator_yet => {
                no_number_separator_yet = false;
                is_hex_number = false;
            }
            'x' if string.starts_with("0x") && no_number_separator_yet => {
                no_number_separator_yet = false;
                is_hex_number = true;
            }
            _ => {
                is_number = false;
                break;
            }
        }
    }
    let special_start_chars = [
        '.', '&', '*', '?', '|', '-', '<', '>', '=', '!', '%', '@', '`', '{', '[',
        '\'', ' ', '#',
    ];
    if is_number
        || string.starts_with(special_start_chars)
        || string.contains(": ")
        || string.contains(|c: char| matches!(c, '\0'..='\x1f'))
        || string.contains('"')
        || string.ends_with([' ', ':'])
        || ["yes", "no", "true", "false", "on", "off", "null", "~"]
            .contains(&string.to_lowercase().as_str())
    {
        format!("\"{}\"", string.escape_default())
    } else {
        string.to_string()
    }
}

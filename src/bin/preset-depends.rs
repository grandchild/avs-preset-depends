use preset_depends::get_depends;
use preset_depends::Resource;
use preset_depends::ResourceAvailable;

use argh::FromArgs;

/// For each path (either file or directory) print out a sectioned list of resources the
/// preset(s) depend on.
#[derive(FromArgs)]
pub struct Arguments {
    /// path(s) to preset files or directories.
    #[argh(positional)]
    pub path: Vec<String>,
    /// path to Winamp base directory, if given will resolve filenames for many
    /// resources including images and APE plugin files.
    /// also tolerates if you pass paths to `Winamp/Plugins` or `Winamp/Plugins/avs`.
    #[argh(option, short = 'w')]
    pub winamp_dir: Option<String>,
    /// collect preset counts for each resource. note multiple uses in one preset still
    /// only count as one.
    #[argh(switch, short = 'c')]
    pub count: bool,
    /// report default resource usage. the default images/fonts are builtin, so
    /// technically it's not a resource, but it can be interesting for usage
    /// statistics.
    #[argh(switch, short = 'd')]
    pub defaults: bool,
}

fn main() {
    let args: Arguments = argh::from_env();
    let resources_for_paths = get_depends(&args.path, args.winamp_dir.as_ref());
    for (path, resources) in resources_for_paths {
        println!("{}:", quote_yaml_string_if_needed(path));
        let mut last_resource_type = None;
        for (Resource { string, rtype, available, default_for }, count) in &resources {
            if !args.defaults && default_for.is_some() {
                continue;
            }
            if Some(rtype) != last_resource_type {
                println!("  {rtype}s:");
            }
            print!("    ");
            if !args.count {
                print!("- ");
            }
            match default_for {
                None => {
                    if available == &ResourceAvailable::No {
                        print!("!missing ");
                    }
                    print!("{}", quote_yaml_string_if_needed(string));
                }
                Some(effect) => {
                    print!("!default ");
                    let default_str = format!("DEFAULT {rtype} for {effect}");
                    print!("{}", quote_yaml_string_if_needed(default_str.as_ref()));
                }
            }
            if args.count {
                print!(": {count}");
            }
            println!();
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
    let starts_with_0x = string.starts_with("0x");
    for c in string.chars() {
        match c {
            '0'..='9' => (),
            'a'..='f' if is_hex_number => (),
            '.' | 'e' if no_number_separator_yet => {
                no_number_separator_yet = false;
                is_hex_number = false;
            }
            'x' if starts_with_0x && no_number_separator_yet => {
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
        || string.contains(|c: char| matches!(c, '\0'..='\x1f' | '"'))
        || string.ends_with([' ', ':'])
        || ["yes", "no", "true", "false", "on", "off", "null", "~"]
            .contains(&string.to_lowercase().as_str())
    {
        format!(
            "\"{}\"",
            string
                .replace('\\', "\\\\")
                .replace('\"', "\\\"")
                .replace('\n', "\\n")
                .replace('\t', "\\t")
                .replace('\r', "\\r")
        )
    } else {
        string.to_string()
    }
}

#[cfg(test)]
mod test {
    #[test]
    fn test_quote_yaml_string_if_needed() {
        let cases = [
            ("", "\"\""),
            ("a", "a"),
            ("1", "\"1\""),
            ("1.0", "\"1.0\""),
            (".0", "\".0\""),
            ("1.", "\"1.\""),
            ("0x1", "\"0x1\""),
            ("2e2", "\"2e2\""),
            ("2e2e2", "2e2e2"),
            ("0x2e2", "\"0x2e2\""),
            ("0e2x2", "0e2x2"),
            ("0xa", "\"0xa\""),
            ("no", "\"no\""),
            ("true", "\"true\""),
            ("false", "\"false\""),
            ("on", "\"on\""),
            ("off", "\"off\""),
            ("null", "\"null\""),
            ("~", "\"~\""),
            ("yes", "\"yes\""),
            ("yEs", "\"yEs\""),
            ("YES", "\"YES\""),
            ("ye:s", "ye:s"),
            ("ye: s", "\"ye: s\""),
            ("yes:", "\"yes:\""),
            (":yes", ":yes"),
            ("ye\"s", "\"ye\\\"s\""),
            (" weird", "\" weird\""),
            ("weird ", "\"weird \""),
            (".weird", "\".weird\""),
            ("&weird", "\"&weird\""),
            ("*weird", "\"*weird\""),
            ("?weird", "\"?weird\""),
            ("|weird", "\"|weird\""),
            ("-weird", "\"-weird\""),
            ("<weird", "\"<weird\""),
            (">weird", "\">weird\""),
            ("=weird", "\"=weird\""),
            ("!weird", "\"!weird\""),
            ("%weird", "\"%weird\""),
            ("@weird", "\"@weird\""),
            ("`weird", "\"`weird\""),
            ("{weird", "\"{weird\""),
            ("[weird", "\"[weird\""),
            ("'weird", "\"'weird\""),
            ("#weird", "\"#weird\""),
            ("\nweird", "\"\\nweird\""),
            ("\nweird", "\"\\nweird\""),
        ];
        for (input, expected) in cases {
            let result = super::quote_yaml_string_if_needed(input);
            assert_eq!(result, expected);
        }
    }
}

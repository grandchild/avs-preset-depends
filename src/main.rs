use preset_depends::print_depends;
use preset_depends::Arguments;

fn main() {
    let mut args: Arguments = argh::from_env();
    print_depends(&mut args);
}

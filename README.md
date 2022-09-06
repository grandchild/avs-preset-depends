## AVS Preset Depends

A CLI tool to scan Winamp AVS presets for any files it might need.

Scan individual files or whole directories.

### Build:

Install Rust & Cargo, then:

```shell
cargo build --release
```

### Usage:

For each path (either file or directory) the tool will print out a sectioned list of
resources the preset(s) wants to use.

```shell
target/release/preset-depends preset.avs
# or
target/release/preset-depends ~/Winamp/Plugins/avs/Me/MyPack/
```

If you pass multiple paths, it will output separate lists for each path.

### License

CC0 - free software.
To the extent possible under law, all copyright and related or neighboring
rights to this work are waived. See the LICENSE file for more information.

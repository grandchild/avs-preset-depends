## AVS Preset Depends

A CLI tool to scan Winamp AVS presets for any files it might need.

Scan individual files or whole directories.

### Build

Install Rust & Cargo, then:

```shell
cargo build --release
```

### Usage

For each path (either file or directory) the tool will print out a sectioned list of
resources the preset(s) wants to use.

```shell
target/release/preset-depends preset.avs
# or
target/release/preset-depends ~/Winamp/Plugins/avs/Me/MyPack/
```

If you pass multiple paths, it will output separate lists for each path.

#### Example Output

```shell
❯ preset-depends \
    "~/Winamp/Plugins/avs/zamuz - visions five/" \
    "~/Winamp/Plugins/avs/VISBOT/VC017/01 skupers - same old intro.avs"
```
```yaml
/home/me/Winamp/Plugins/avs/zamuz - visions five:
  Images:
    - v4_texer7.bmp
    - v5_texer1.bmp
    - v5_circle.bmp
    - V5_intro4.bmp
    - v5_square.bmp
    - V5_intro2.bmp
    - v5_circle2.bmp
  APEs:
    - Channel Shift
    - Color Map
    - Holden04: Video Delay
    - Holden03: Convolution Filter
    - Acko.net: Texer II
/home/me/Winamp/Plugins/avs/VISBOT/VC017/01 skupers - same old intro.avs:
  Images:
    - vb.bmp
  APEs:
    - Color Map
    - Holden03: Convolution Filter
```

### Todo

- Translate APE ID strings into `.ape` filenames if available.
- Make precompiled releases downloadable
- Allow setting a `Winamp/Plugins/avs` base-dir to find and print full paths for available and warnings for missing files
- Fix YAML output (i.e. quote values with ": " in them)

### License

CC0 - free software.
To the extent possible under law, all copyright and related or neighboring
rights to this work are waived. See the LICENSE file for more information.

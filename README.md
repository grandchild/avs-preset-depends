## AVS Preset Depends

A CLI tool to scan Winamp AVS presets for any files it might need.

Scan individual files or whole directories.


### Build

Install Rust & Cargo, then:

```shell
cargo build --release
```


### Usage

```
Usage: preset-depends [<path...>] [--winamp-dir <winamp-dir>] [-a] [--check]

For each path (either file or directory) print out a sectioned list of resources
the preset(s) depend on.

Positional Arguments:
  path              path(s) to preset files or directories.

Options:
  --winamp-dir      path to Winamp base directory, can also tolerate if you pass
                    paths to `Winamp/Plugins` or `Winamp/Plugins/avs`.
  -a, --find-apes   try and resolve APE ID strings into APE filenames within
                    `--winamp-dir`.
  --help            display usage information
```


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
    - v5_circle.bmp
    - v5_circle2.bmp
    - V5_intro2.bmp
    - V5_intro4.bmp
    - v5_square.bmp
    - v5_texer1.bmp
  APEs:
    - "Acko.net: Texer II"
    - Channel Shift
    - Color Map
    - "Holden03: Convolution Filter"
    - "Holden04: Video Delay"
/home/me/Winamp/Plugins/avs/VISBOT/VC017/01 skupers - same old intro.avs:
  Images:
    - vb.bmp
  APEs:
    - Color Map
    - "Holden03: Convolution Filter"
```


### Todo

- Print full paths for available and warnings for missing files
- Unit- & integration testing
- CI & downloadable release builds
- Try retrieving resources `async`.


### Learning Rust

While this project does serve a useful purpose, it is with _equal_ importance a project
for learning Rust. I try hard to make the code as idiomatic as possible and to apply
various parts of the language and libraries. Other than that the code should have
minimal dependencies and produce the smallest possible binary size.


### License

CC0 - free software.
To the extent possible under law, all copyright and related or neighboring
rights to this work are waived. See the LICENSE file for more information.

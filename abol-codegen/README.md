# abol-codegen

`abol-codegen` is a code generation tool for the Abol project. It transforms RADIUS dictionary files (in standard FreeRADIUS format) into type-safe Rust traits.

This generator produces access methods (getters and setters) for each attribute defined in the dictionary, making it easier to manipulate RADIUS packets without having to manually handle raw data types or attribute codes.

## Features

- **Extension Trait Generation**: Creates traits (e.g., `Rfc2865Ext`) that extend Abol's `Packet` struct.
- **RADIUS Type Support**: Handles standard types (Integer, String, IpAddr, Ipv6Addr, Octets, Date, etc.).
- **Enums for Attribute Values**: Automatically generates Rust enumerations for attributes with named values defined in the dictionary.
- **Automatic Validation**: Includes size and type checks when setting attributes.
- **Vendor-Specific Attributes (VSA) Support**: Handles vendor-specific attributes.

## Usage (CLI)

The tool can be used via the command line to generate Rust files from dictionaries.

```bash
abol-codegen \
  --inputs path/to/dictionary.rfc2865 \
  --output src/generated/rfc2865.rs \
  --name Rfc2865
```

### Arguments

- `-i, --inputs <INPUTS>`: One or more input dictionary files.
- `-o, --output <OUTPUT>`: Path to the output file or directory.
- `-n, --name <NAME>`: Base name for the generated trait (e.g., `Rfc2865` will generate `Rfc2865Ext`).
- `--ignore-identical-attributes`: If present, does not produce an error if an attribute is defined identically in multiple input files.

##  License

Licensed under either of:

* Apache License, Version 2.0 ([LICENSE-APACHE](../LICENSE-APACHE) or http://www.apache.org/licenses/LICENSE-2.0)
* MIT license ([LICENSE-MIT](../LICENSE) or http://opensource.org/licenses/MIT)

at your option.
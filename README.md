# rust-sleigh
This project attempts to implement a binary lifter for [SLEIGH](https://ghidra.re/ghidra_docs/languages/html/sleigh.html) processor modules in pure Rust.

The project depends on the slaspec/sinc files being pre-compiled into sla (XML) which is by default the case in any Ghidra release.
The sla files are by default read from the `$GHIDRA_PATH` environment variable which is expected to have the following directory structure:

```
- $GHIDRA_PATH
  - Ghidra
    - Processors
      - <PROCESSOR>
        - data
          - languages
            - sla, ldefs, pspec, and cspec files
```

This is also the default directory structure for Ghidra so if you have Ghidra installed, you shouldn't need to do anything.

If `$GHIDRA_PATH` isn't set, `rust-sleigh` will look in the project root's folder which has copies of the x86 and AARCH64 directories.

## Usage
From the project root, run `cargo run [--release] -- <arguments>` with the following arguments:

* `-f/--file_name`: The binary file to lift. `rust-sleigh` uses the [object](https://docs.rs/object/latest/object/) crate for binary object parsing.
* `-l/--langage_id`: The language id to use for the lifting. Find this in the `ldefs` file for your chosen architecture, e.g. `x86:LE:64:default` for x86-64 or `AARCH64:LE:64:v8A`.
* `-c/--compiler_id`: The compiler id to use. This can also be found in the `ldefs` file. This shouldn't currently have an effect on the lifting.
* `-s/--start_addr`: [Optional] The address at which to start lifting.
* `-e/--end_addr`: [Optional] The address at which to stop lifting.
* `-n/--num`: [Optional] The maximum number of instructions to lift.
* `--print_asm`: Whether or not to print the assembly of the lifted instructions.
* `--print_pcode`: Whether or not the print the p-code of the lifted instructions.
* `-m/--log`: [Optional,Repeated] Turns on logging for different modules. Currently you can pass `disassembler` or `resolver`.

## Notes
Lifting has currently only been tested with the `x86:LE:64:default` and `AARCH64:le:64:v8A` languages. The project has been written to handle generic SLEIGH, so it should work on some other architectures as well. Although probably architectures with a delay slot won't work.

Also, most of the inner working were either figured out by brute force or by trying to understand the analogous code in Ghidra. Therefore, there are likely bugs or inconsistencies. If you encounter one, please file an issue.

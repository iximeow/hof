use hof_tags::{FFIStableStr, GeneratorName, TagGeneratorState};

use object::read::Architecture;
use object::BinaryFormat;
use object::Object;

use std::io::Read;
use std::path::Path;

#[no_mangle]
pub extern "C" fn generator_name() -> GeneratorName {
    GeneratorName::from_str("binary-format-arch")
}

#[no_mangle]
pub extern "C" fn version() -> u64 {
    1
}

pub fn report_tag(tag_sink: *mut hof_tags::TagSink, name: &str, value: Option<&str>) {
    unsafe { hof_tags::report_tag(
        tag_sink,
        FFIStableStr::from_str(name),
        value.is_some(),
        FFIStableStr::from_str(value.unwrap_or("")));
    }
}

#[no_mangle]
pub extern "C" fn make_tags(tag_sink: *mut hof_tags::TagSink, path_data: *const u8, path_len: usize) -> TagGeneratorState {
    let path = unsafe {
        std::str::from_utf8_unchecked(std::slice::from_raw_parts(path_data, path_len))
    };
    let path = Path::new(path);
    let mut f = match std::fs::File::open(path) {
        Ok(f) => f,
        Err(e) => {
            eprintln!("can't open {}: {}", path.display(), e);
            return TagGeneratorState::Uninterested;
        }
    };
    let mut magic = [0u8; 4];
    match f.read_exact(&mut magic) {
        Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => {
            return TagGeneratorState::Uninterested;
        },
        Err(e) => {
            eprintln!("reading {} yielded {}", path.display(), e);
        }
        Ok(()) => {}
    }

    let (format, arch) = match &magic {
        b"\x7fELF" |
        b"\xCF\xFA\xED\xFE" |
        b"\xFE\xFA\xED\xFE" |
        b"\xFE\xED\xFE\xED" |
        b"\xFE\xED\xFA\xCE" |
        &[b'M', b'Z', _, _] => {
            let mut buf = magic.to_vec();
            f.read_to_end(&mut buf).expect("can read the rest of it");
            match object::File::parse(buf.as_slice()) {
                Ok(obj) => {
                    let mut format = match obj.format() {
                        BinaryFormat::Coff => "coff",
                        BinaryFormat::Elf => "elf",
                        BinaryFormat::MachO => "macho",
                        BinaryFormat::Pe => "pe",
                        BinaryFormat::Wasm => "wasm",
                        BinaryFormat::Xcoff => "xcoff",
                        f => {
                            panic!("unknown binary format: {:?}", f);
                        }
                    };
                    if format == "pe" {
                        let mut buf = [0u8; 4];
                        use std::io::Seek;
                        if f.seek(std::io::SeekFrom::Start(0x168)).is_ok() && f.read_exact(&mut buf).is_ok() {
                            if buf != [0u8; 4] {
                                format = "clr";
                            }
                        }
                    }
                    let arch = match obj.architecture() {
                        Architecture::Aarch64 => "aarch64",
                        Architecture::Arm => "arm",
                        Architecture::Avr => "avr",
                        Architecture::Bpf => "bpf",
                        Architecture::Csky => "csky",
                        Architecture::I386 => "i386",
                        Architecture::X86_64 => "x86_64",
                        Architecture::X86_64_X32 => "x86_64_x32",
                        Architecture::Hexagon => "hexagon",
                        Architecture::LoongArch64 => "loongarch64",
                        Architecture::Mips => "mips",
                        Architecture::Mips64 => "mips64",
                        Architecture::Msp430 => "msp430",
                        Architecture::PowerPc => "powerpc",
                        Architecture::PowerPc64 => "powerpc64",
                        Architecture::Riscv32 => "riscv32",
                        Architecture::Riscv64 => "riscv64",
                        Architecture::S390x => "s390x",
                        Architecture::Sbf => "sbf",
                        Architecture::Sharc => "sharc",
                        Architecture::Sparc => "sparc",
                        Architecture::Sparc32Plus => "sparc32plus",
                        Architecture::Sparc64 => "sparc64",
                        Architecture::Wasm32 => "wasm32",
                        Architecture::Wasm64 => "wasm64",
                        Architecture::Xtensa => "xtensa",
                        Architecture::Unknown => "unknown",
                        a => {
                            panic!("unknown architecture: {:?}", a);
                        }
                    };
                    (format, arch)
                }
                Err(e) => {
                    eprintln!("{} had magic but was not valid? {}", path.display(), e);
                    return TagGeneratorState::Uninterested;
                }
            }
        }
        _ => {
            return TagGeneratorState::Uninterested;
        }
    };

    report_tag(tag_sink, "format", Some(format));
    report_tag(tag_sink, "architecture", Some(arch));

    TagGeneratorState::Ok
}

#[cfg(debug_assertions)]
#[no_mangle]
pub extern "C" fn report_tag(sink: *const u8, s: u8, u: u8, v: u8) {
}

#[test]
fn date_pat_matches() {
    assert!(date_re().is_match("20220404"));
    assert!(date_re().is_match("2022-04-04"));
    assert!(date_re().is_match("2022-12-30")); // could be yyyy-mm-dd
    assert!(date_re().is_match("2022-30-12")); // could be yyyy-dd-mm
    assert!(!date_re().is_match("2022-90-90")); // do not match obviously-invalid dates
    assert!(!date_re().is_match("202a-bcde")); // do not match date-shaped hex strings...
    assert!(!date_re().is_match("2024/20/04")); // do not match path separators between "date" parts
}

use hof_tags::{FFISlice, FFIStableStr, Interest, GeneratorName, TagGeneratorState};

use std::process::Command;

#[no_mangle]
pub extern "C" fn generator_name() -> GeneratorName {
    GeneratorName::from_str("fits-fwhm")
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

static INTERESTS: &'static [Interest<'static>] = &[
    Interest::has_tag(FFIStableStr::from_str("target"))
        .with_source(FFIStableStr::from_str("fits-file-tag")),
];

#[no_mangle]
pub extern "C" fn interests() -> FFISlice<'static, Interest<'static>> {
    FFISlice::from_slice(INTERESTS)
}

#[no_mangle]
pub extern "C" fn make_tags(tag_sink: *mut hof_tags::TagSink, path_data: *const u8, path_len: usize) -> TagGeneratorState {
    let path = unsafe {
        std::str::from_utf8_unchecked(std::slice::from_raw_parts(path_data, path_len))
    };
    if !path.ends_with(".fit") {
        return TagGeneratorState::Uninterested;
    }

    match Command::new("/toy/astro_tools/autofocus/ixi/target/release/ixi")
        .args(["framefwhm", path])
        .output() {
        Ok(output) => {
            match String::from_utf8(output.stdout) {
                Ok(output) => {
                    let output = output.trim();
                    if output.contains('\n') {
                        eprintln!("too much output for path {}", path);
                        TagGeneratorState::Error
                    } else if output.len() == 0 {
                        eprintln!("no output for path {}", path);
                        TagGeneratorState::Error
                    } else {
                        report_tag(tag_sink, "fwhm", Some(output));
                        TagGeneratorState::Ok
                    }
                }
                Err(e) => {
                    eprintln!("bad output from tool on {}: {:?}", path, e);
                    TagGeneratorState::Error
                }
            }
        },
        Err(e) => {
            eprintln!("path {} resulted in {:?}", path, e);
            TagGeneratorState::Error
        }
    }
}

#[cfg(debug_assertions)]
#[no_mangle]
pub extern "C" fn report_tag(sink: *const u8, s: u8, u: u8, v: u8) {
}

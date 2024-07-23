use hof_tags::{FFIStableStr, GeneratorName, TagGeneratorState};

use regex::Regex;

use std::sync::RwLock;

static DATE_RE: RwLock<Option<&'static Regex>> = RwLock::new(None);

fn date_re() -> &'static Regex {
    let lock = DATE_RE.read().unwrap();
    if let Some(re) = *lock {
        re
    } else {
        std::mem::drop(lock);
        let re_ref = Box::leak(Box::new(Regex::new(
            "(20\\d\\d-?[0-3]\\d-?[0-3]\\d)"
        ).expect("regex is valid?")));
        *DATE_RE.write().unwrap() = Some(re_ref);
        DATE_RE.read().unwrap().unwrap()
    }
}

#[no_mangle]
pub extern "C" fn generator_name() -> GeneratorName {
    GeneratorName::from_str("fits-file-tag")
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
    if !path.ends_with(".fit") {
        return TagGeneratorState::Uninterested;
    }

    if let Some(captures) = date_re().captures(path) {
        let date = captures.get(0).unwrap().as_str();
        report_tag(tag_sink, "date", Some(date));
        let mut path_parts = path.split("/").skip_while(|x| x != &date);
        path_parts.next(); // skip date
        let maybe_target = path_parts.next();
        let maybe_filter = path_parts.next();
        if let (Some(maybe_target), Some(filter)) = (maybe_target, maybe_filter) {
            if ["ha", "oiii", "sii", "l", "lum", "lpro", "r", "g", "b"].contains(&filter) {
                report_tag(tag_sink, "filter", Some(filter));
                report_tag(tag_sink, "target", Some(maybe_target));
            }
        } else {
            report_tag(tag_sink, "strange_path", None);
        }
    } else {
        return TagGeneratorState::Error;
    }

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

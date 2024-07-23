pub use hof_ffi::{FFISlice, FFIStableStr, Interest};

/// it's not actually a zst. it contains state. no, you can not look at it. do not think about it.
/// for all intents and purposes it is a void pointer.
#[repr(C)]
pub struct TagSink {
    _dummy: u8
}

// THESE VALUES ARE IN THE DATABASE. DO NOT CHANGE THE MEANING OF MAPPED VALUES HERE.
#[repr(C)]
pub enum TagGeneratorState {
    Started = 0,
    Ok = 1,
    Error = 2,
    Uninterested = 3,
    NoContent = 4,
}

pub type GeneratorName = hof_ffi::FFIStableStr<'static>;

extern "C" {
    pub fn get_tag_sink() -> *mut TagSink;

    pub fn report_tag(
        state: *mut TagSink,
        tag: hof_ffi::FFIStableStr,
        value_present: bool, value: hof_ffi::FFIStableStr
    );

    pub fn close_tag_sink(state: *mut TagSink);
}

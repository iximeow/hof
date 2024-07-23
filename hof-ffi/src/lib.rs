#[derive(Copy, Clone)]
#[repr(C)]
pub struct FFISlice<'a, T> {
    data: *const T,
    len: usize,
    _marker: std::marker::PhantomData::<&'a ()>,
}

#[derive(Copy, Clone)]
#[repr(C)]
pub struct FFIStableStr<'a> {
    data: FFISlice<'a, u8>,
}

// safety: TODO: think really hard about this
unsafe impl<'a, T: Send> Send for FFISlice<'a, T> {}
unsafe impl<'a, T: Sync> Sync for FFISlice<'a, T> {}

impl<'a, T> FFISlice<'a, T> {
    pub const fn from_slice(data: &[T]) -> Self {
        Self {
            data: data.as_ptr(),
            len: data.len(),
            _marker: std::marker::PhantomData,
        }
    }

    pub const fn as_slice(&self) -> &'a [T] {
        unsafe {
            std::slice::from_raw_parts(self.data, self.len)
        }
    }
}

impl<'a> FFIStableStr<'a> {
    pub const fn from_str(s: &'a str) -> Self {
        Self {
            data: FFISlice::from_slice(s.as_bytes())
        }
    }

    pub const fn as_str(&self) -> &'a str {
        unsafe {
            std::str::from_utf8_unchecked(self.data.as_slice())
        }
    }
}

// THESE LIFETIMES ARE SUPER QUESTIONABLE. if a module is ever unloaded these likely-static
// references will become invalid...
#[derive(Copy, Clone)]
#[repr(C)]
pub struct Interest<'a> {
    tag: FFIStableStr<'a>,
    value: Option<FFIStableStr<'a>>,
    source: Option<FFIStableStr<'a>>,
}

impl<'a> Interest<'a> {
    pub const fn new(tag: FFIStableStr<'a>, value: Option<FFIStableStr<'a>>, source: Option<FFIStableStr<'a>>) -> Self {
        Self { tag, value, source }
    }

    pub const fn has_tag(tag: FFIStableStr<'a>) -> Self {
        Self::new(tag, None, None)
    }

    pub const fn with_value(mut self, value: FFIStableStr<'a>) -> Self {
        self.value = Some(value);
        self
    }

    pub const fn with_source(mut self, source: FFIStableStr<'a>) -> Self {
        self.source = Some(source);
        self
    }

    pub fn tag(&self) -> &str {
        self.tag.as_str()
    }

    pub fn value(&self) -> Option<&str> {
        self.value.map(|x| x.as_str())
    }

    pub fn source(&self) -> Option<&str> {
        self.source.map(|x| x.as_str())
    }
}

use clap::{Parser, Subcommand};

use std::collections::HashSet;
use std::fmt;
use std::path::PathBuf;
use std::sync::RwLock;
use std::time::Instant;

use hofvarpnir::Hof;

use hof_ffi::{FFIStableStr, Interest};

#[derive(Parser)]
#[command(version, about, long_about = None)]
struct Args {
    /// path to a hof database (defaults to "./hof.db")
    db_path: Option<String>,

    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// run the provided native plugin across locally-reachable indexed files.
    RunTagGenerator {
        #[arg(long, short='n')]
        dry_run: bool,

        library_path: String,

        file: Option<PathBuf>,

        force_all: bool,
    },
}

#[derive(Copy, Clone, Debug, Eq, PartialEq, clap::ValueEnum)]
enum ItemCategory {
    Path,
    Hash,
    Id,
}

impl fmt::Display for ItemCategory {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let label = match self {
            ItemCategory::Path => { "path" },
            ItemCategory::Hash => { "hash" },
            ItemCategory::Id => { "id" },
        };

        f.write_str(label)
    }
}

static DB_PATH: RwLock<String> = RwLock::new(String::new());

fn main() {
    /*
    eprintln!("{}", get_tag_sink as u64);
    eprintln!("{}", report_tag as u64);
    eprintln!("{}", close_tag_sink as u64);
    */

    let args = Args::parse();

    let db_path = args.db_path.unwrap_or_else(|| "./hof.db".to_owned());

    *DB_PATH.write().unwrap() = db_path.to_string();

    let hof = Hof::new(db_path);

    match args.command {
        Command::RunTagGenerator { library_path, file, dry_run, force_all } => {
            let hostname = gethostname::gethostname();
            let hostname_str = hostname.to_str().expect("utf8 hostname");

            // look up the tag source name from library_path.so
            // fetch version of tag source from library_path.so
            //
            // work through all files in the following priority order:
            // * file ids where there is no tag determination from <tag source>
            // * file ids where there is a tag from an old version of <tag source>
            // * file ids where some other instance is producing tags for this version of <tag source>

            let lib = TagGenerator::open(&library_path).expect("can open .so");
            println!("loaded tag generator: {} version {}", lib.name(), lib.version());
            let generator_id = hof.db.get_tag_generator_id(lib.name(), lib.version()).expect("can lookup");
            let worklist = if let Some(file) = file {
                let path_str = file.to_str().expect("utf8 pathname");
                match hof.db.replica_lookup(hostname_str, path_str).expect("can query") {
                    Some(id) => {
                        vec![id]
                    }
                    None => {
                        eprintln!("path {} is not known in replica {}", file.display(), hostname_str);
                        std::process::exit(1);
                    }
                }
            } else {
                let interests = if force_all {
                    None
                } else {
                    Some(lib.interests())
                };
                hof.db.tag_worklist(generator_id, interests).expect("can compute worklist")
            };

            let generator_id: u64 = generator_id.unwrap_or_else(|| {
                hof.db.create_tag_generator_id(lib.name(), lib.version()).expect("can create id")
            });
            eprintln!("generator id: {}", generator_id);

            println!("need to operate on {} items..", worklist.len());

            let mut tagged = 0;
            for &item in worklist.iter() {
                print!("[.] file {} ({} of {})..", item, tagged + 1, worklist.len());
                if let Some(path) = hof.db.find_local_replica(hostname_str, item)
                    .expect("can query") {
                    println!(" at {}", path);
                    hof.db.tag_generator_state(item, generator_id, hof_tags::TagGeneratorState::Started).expect("can update state");
                    let mut task_state = Box::new(
                        HostTagSink {
                            hof: if !dry_run {
                                Some(Hof::new(DB_PATH.read().unwrap().clone()))
                            } else {
                                None
                            },
                            generator_id,
                            item,
                        }
                    );
                    let result = lib.make_tags(task_state.as_mut(), &path);
                    hof.db.tag_generator_state(item, generator_id, result);
                } else {
                    hof.db.tag_generator_state(item, generator_id, hof_tags::TagGeneratorState::NoContent);
                }
                tagged += 1;
            }
        },
    }
}

struct TagGenerator {
    library: *const std::ffi::c_void,
    name_fn: fn() -> hof_tags::GeneratorName,
    version_fn: fn() -> u64,
    tag_fn: fn(*mut hof_tags::TagSink, *const u8, usize) -> hof_tags::TagGeneratorState,
    interests_fn: fn() -> (*const Interest<'static>, usize),
}

impl TagGenerator {
    pub fn name(&self) -> &'static str {
        let name = (self.name_fn)();
        unsafe {
            name.as_str()
        }
    }

    pub fn version(&self) -> u64 {
        (self.version_fn)()
    }

    pub fn make_tags(&self, tag_sink: &mut HostTagSink, path: &str) -> hof_tags::TagGeneratorState {
        (self.tag_fn)(
            tag_sink as *mut HostTagSink as *mut hof_tags::TagSink,
            path.as_ptr(),
            path.len(),
        )
    }

    pub fn interests(&self) -> &[Interest] {
        let (data, len) = (self.interests_fn)();
        unsafe {
            std::slice::from_raw_parts(data, len)
        }
    }

    pub fn open(path: &str) -> Result<Self, String> {
        let mut null_terminated = path.to_owned().into_bytes();
        null_terminated.push(0x00);

        let lib = unsafe {
            libc::dlopen(null_terminated.as_ptr() as *const std::ffi::c_char, libc::RTLD_NOW)
        };

        if lib.is_null() {
            let msg = unsafe { libc::dlerror() };
            unsafe {
                eprintln!("dlopen error: {}", std::ffi::CStr::from_ptr(msg).to_str().unwrap());
            }
            return Err(format!("unable to load {}", path));
        }

        macro_rules! resolve {
            ($lib: expr, $sym: expr, $f_ty: ty) => { {
                let sym: &str = $sym;
                let mut sym_bytes = sym.to_owned().into_bytes();
                sym_bytes.push(0x00);

                let res: Result<$f_ty, String>;

                let ptr = unsafe {
                    libc::dlsym($lib, sym_bytes.as_ptr() as *const std::ffi::c_char)
                };
                if ptr.is_null() {
                    res = Err(format!("could not resolve {}", sym));
                } else {
                    res = Ok(unsafe { core::mem::transmute::<*mut std::ffi::c_void, $f_ty>(ptr) })
                }

                res
            } }
        }

        let name_fn = resolve!(lib, "generator_name", fn() -> hof_tags::GeneratorName)
            .expect("can resolve");
        let version_fn = resolve!(lib, "version", fn() -> u64)
            .expect("can resolve");
        let tag_fn = resolve!(lib, "make_tags", fn(*mut hof_tags::TagSink, *const u8, usize) -> hof_tags::TagGeneratorState)
            .expect("can resolve");
        let interests_fn = resolve!(lib, "interests", fn() -> (*const Interest<'static>, usize))
            .expect("can resolve");

        Ok(Self {
            library: lib,
            name_fn,
            version_fn,
            tag_fn,
            interests_fn,
        })
    }
}

struct HostTagSink {
    hof: Option<Hof>,
    generator_id: u64,
    item: u64,
}

#[no_mangle]
pub extern "C" fn get_tag_sink() -> *mut std::ffi::c_void {
    eprintln!("aw you want a tag sink, that's cute");
    std::ptr::null_mut()
}

#[no_mangle]
pub extern "C" fn report_tag(sink: *mut std::ffi::c_void, name: FFIStableStr, value_present: bool, value: FFIStableStr) {
    let ptr = sink as *mut HostTagSink;
    let sink_ref: &mut HostTagSink = unsafe { ptr.as_mut().unwrap() };
//    let tag_id = sink_ref.hof.db.create_tag(name.as_str()).expect("can turn tag name into an id");
    eprint!("attempting to report tag {}", name.as_str());
    let value = if value_present {
        eprint!("(! bonus !");
        eprint!(" value: {})", value.as_str());
        value.as_str()
    } else {
        ""
    };
    eprintln!("");
    if let Some(hof) = sink_ref.hof.as_mut() {
        hof.add_file_tag(sink_ref.item, sink_ref.generator_id, name.as_str(), value).expect("can create tag");
    } else {
        eprintln!("[-] dry run");
    }
}

#[no_mangle]
pub extern "C" fn close_tag_sink(sink: *mut std::ffi::c_void) {
    eprintln!("aw you want to close a tag sink, that's cute");
}

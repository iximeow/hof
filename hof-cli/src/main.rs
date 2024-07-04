use clap::{Parser, Subcommand};

use std::collections::HashSet;
use std::path::PathBuf;

use hofvarpnir::Hof;

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
    /// add _something_ to hof
    AddFile {
        #[clap(long, short)]
        recursive: Option<bool>,
        what: String,
    },

    /// add a file known by some hashes, held by some remote
    AddRemoteFile {
        #[clap(long)]
        remote: Option<String>,
        #[clap(long)]
        allow_new_remote: bool,
        #[clap(long)]
        path: Option<String>,
        #[clap(long)]
        sha256: Option<String>,
        #[clap(long)]
        sha1: Option<String>,
        #[clap(long)]
        md5: Option<String>,
    },

    /// add a tag to a file either by hash or path
    AddTag {
        what: String,
        tag_key: String,
        tag_value: String,
    },

    IndexTree {
        root: String,
    },

    ListTags,

    SearchTags { tags: Vec<String> },

    /// find files with `part` in their name.
    SearchPath {
        /// which replica do we care about results in? default: any
        #[clap(long)]
        replica: Option<String>,
        /// must files exactly end with the path `path` to be printed? or is containing `path` in
        /// the path string sufficient?
        #[clap(short, long, action)]
        exact: bool,
        /// some fragment of a path to find in known files. if not exact, `path` must only be a
        /// substring of a file path for it to be included in the results.
        path: String
    },

    /// list all files known to be at or under a provided path, if any
    ListPath {
        #[clap(long)]
        replica: Option<String>,
        #[clap(short, long, action)]
        exact: bool,
        /// some prefix of a path to list files under. if exact, `prefix` must begin a replica's
        /// path to be included in the result set. otherwise, `prefix` may exist anywhere in a
        /// replica's path to be included in the result set.
        prefix: String,
    },

    Describe {
        what: String,

        #[clap(long, short, action, default_value_t = false)]
        by_id: bool
    },
}

fn main() {
    let args = Args::parse();

    let db_path = args.db_path.unwrap_or_else(|| "./hof.db".to_owned());

    let hof = Hof::new(db_path);

    match args.command {
        Command::Describe { what, by_id } => {
            let id = if by_id {
                let id: u64 = what.parse().expect("TODO: handle non-int \"id\"");
                id
            } else {
                let id = if let Some(id) = hof.hash_lookup(&what).expect("TODO: can do db query") {
                    Some(id)
                } else {
                    hof.replica_lookup("localhost", &what).expect("TODO: can do db query")
                };

                let id = match id {
                    Some(id) => id,
                    None => {
                        panic!("item {} is not known", what);
                    }
                };

                id
            };

            let desc = hof.db.describe_file(id).expect("can describe file");

            print_description(&desc);
        },
        Command::AddFile { what, recursive } => {
            match recursive {
                Some(true) => {
                    panic!("recursive add not supported yet");
                },
                _ => {
                    hof.add_file(what).expect("works");
                }
            }
        },
        Command::AddRemoteFile { remote, allow_new_remote, path, sha256, sha1, md5 } => {
            // check if the remote seems new, if so then double-check that a new remote is actually
            // requested.

            if let Some(remote) = remote.as_ref() {
                if !hof.db.remote_is_known(remote.as_str()) && !allow_new_remote {
                    panic!("remote {} is not known and --new-remote was not passed: assuming this remote is incorrect", remote);
                }
            }

            hof.add_remote_file(hofvarpnir::file::MaybeHashes::new(
                sha256.map(hex::decode).map(|v| {
                    *TryInto::<&[u8; 32]>::try_into(v.expect("TODO: ok").as_slice()).expect("TODO: right size")
                }),
                sha1.map(hex::decode).map(|v| {
                    *TryInto::<&[u8; 20]>::try_into(v.expect("TODO: ok").as_slice()).expect("TODO: right size")
                }),
                md5.map(hex::decode).map(|v| {
                    *TryInto::<&[u8; 16]>::try_into(v.expect("TODO: ok").as_slice()).expect("TODO: right size")
                }),
            ).expect("at least one hash is present"), remote, path).expect("can add remote file");
        }
        Command::AddTag { what, tag_key, tag_value } => {
            if let Ok(Some(file_id)) = hof.hash_lookup(&what) {
                hof.add_file_tag(file_id, &tag_key, &tag_value).expect("works");
            } else if let Ok(Some(file_id)) = hof.replica_lookup("localhost", &what) {
                hof.add_file_tag(file_id, &tag_key, &tag_value).expect("works");
            } else {
                panic!("unsure what {} is", what);
            }
        }
        Command::ListTags => {
            for tag_id in hof.db.list_tags().expect("can list tags").into_iter() {
                println!("{}", hof.db.tag_name(tag_id).expect("can get tag names").expect("if tag was listed it has a name"));
            }
        }
        Command::SearchTags { tags } => {
            let mut computed_tags = Vec::new();
            for t in tags.iter() {
                match t.split_once("=") {
                    Some((k, v)) => {
                        if let Ok(Some(tag_id)) = hof.db.tag_to_id(k) {
                            let mut values = HashSet::new();
                            values.insert(v.to_string());
                            computed_tags.push(hofvarpnir::TagFilter {
                                key: hofvarpnir::TagId(tag_id),
                                values: Some(values),
                            });
                        } else {
                            panic!("unknown tag: {}", k);
                        }
                    },
                    None => {
                        let k = t;
                        if let Ok(Some(tag_id)) = hof.db.tag_to_id(k) {
                            computed_tags.push(hofvarpnir::TagFilter {
                                key: hofvarpnir::TagId(tag_id),
                                values: None,
                            });
                        } else {
                            panic!("unknown tag: {}", k);
                        }
                    }
                }
            }

            let file_ids = hof.db.select_by_tags(&computed_tags).expect("can query tags");
            for f in file_ids.iter() {
                let desc = hof.db.describe_file(*f).expect("can describe file");

                println!("file {}", desc.file_id);
                println!("  sha256: {}", desc.sha256.as_ref().map(|x| x.as_str()).unwrap_or("<null>"));
                println!("  sha1:   {}", desc.sha1.as_ref().map(|x| x.as_str()).unwrap_or("<null>"));
                println!("  md5:    {}", desc.md5.as_ref().map(|x| x.as_str()).unwrap_or("<null>"));
                println!("replicas:");
                for replica in desc.replicas.iter() {
                    if let Some(replica_name) = replica.replica.as_ref() {
                        print!("  {}: {}, checked {}", replica.who, replica_name, replica.last_check_ts);
                        if replica.valid {
                            print!(" (valid)");
                        }
                    } else {
                        print!("  {}: remote", replica.who);
                    }
                    println!("");
                }
                println!("tags:");
                for tag in desc.tags.iter() {
                    println!("  {}: {}, from {}", tag.name, tag.value, tag.source);
                }

//                println!("file {}", f);
            }
        },
        Command::IndexTree { root } => {
            index_tree(hof, root);
        },
        Command::SearchPath {
            replica,
            exact,
            path
        } => {
            use hofvarpnir::PathLookup;

            let replica = replica.as_ref().map(|x| x.as_str()); //unwrap_or_else(|| gethostname::gethostname());
            let results = if exact {
                hof.db.path_lookup(
                    replica,
                    PathLookup::Suffix(path),
                )
            } else {
                hof.db.path_lookup(
                    replica,
                    PathLookup::Contains(path),
                )
            };
            let results = results.expect("can query");
            for id in results.into_iter() {
                let desc = hof.db.describe_file(id).expect("can describe");
                print_description(&desc);
            }
        },
        Command::ListPath {
            replica,
            exact,
            prefix
        } => {
//            hof.db.select_from_replica_
            panic!("search path");
        },
    }
}

fn index_tree(hof: Hof, root: String) {
    // not sure if `root` is a file or a directory yet. worklist will only yet-untraversed
    // directory paths. so check if we're even doing all that for `root` first...

    let mut worklist: Vec<PathBuf> = Vec::new();

    match std::fs::metadata(&root) {
        Ok(md) => {
            if md.is_file() {
                panic!("indexing a file?");
            } else if md.is_dir() {
                worklist.push(PathBuf::from(&root));
            } else {
                panic!("unclear what {} is", root);
            }
        }
        Err(e) => {
            panic!("unable to get metadata for {}: {}", root, e);
        }
    }

    while let Some(item) = worklist.pop() {
        match std::fs::read_dir(&item) {
            Ok(iter) => {
                for entry in iter {
                    let entry = match entry {
                        Ok(entry) => entry,
                        Err(e) => {
                            panic!("error iterating dir: {:?}", e);
                        }
                    };
                    match entry.file_type() {
                        Ok(t) if t.is_dir() => {
                            worklist.push(entry.path());
                        }
                        Ok(t) if t.is_file() => {
                            println!("indexing {}", entry.path().display());
                        }
                        Ok(_) => {
                            panic!("what is {}?", entry.path().display());
                        }
                        Err(e) => {
                            panic!("cant get file type of {}? {}", entry.path().display(), e);
                        }
                    }
                }
            }
            Err(e) => {
                panic!("unable to read dir for item {}: {}", item.display(), e);
            }
        }
    }

    println!("[+] indexed {}!", root);
}


fn print_description(desc: &hofvarpnir::Description) {
    println!("file {}", desc.file_id);
    println!("  sha256: {}", desc.sha256.as_ref().map(|x| x.as_str()).unwrap_or("<null>"));
    println!("  sha1:   {}", desc.sha1.as_ref().map(|x| x.as_str()).unwrap_or("<null>"));
    println!("  md5:    {}", desc.md5.as_ref().map(|x| x.as_str()).unwrap_or("<null>"));
    println!("replicas:");
    for replica in desc.replicas.iter() {
        if let Some(replica_name) = replica.replica.as_ref() {
            print!("  {}: {}, checked {}", replica.who, replica_name, replica.last_check_ts);
            if replica.valid {
                print!(" (valid)");
            }
        } else {
            print!("  {}: remote", replica.who);
        }
        println!("");
    }
    println!("tags:");
    for tag in desc.tags.iter() {
        println!("  {}: {}, from {}", tag.name, tag.value, tag.source);
    }
}

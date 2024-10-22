use clap::{Args, Parser, Subcommand};

use std::collections::HashSet;
use std::fmt;
use std::path::PathBuf;
use std::time::Instant;

use hofvarpnir::Hof;

#[derive(Parser)]
#[command(version, about, long_about = None)]
struct Cli {
    /// path to a hof database (defaults to "./hof.db")
    db_path: Option<String>,

    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// add _something_ to hof
    AddFile {
        #[clap(long, short, default_value_t = false)]
        recursive: bool,
        #[clap(long, default_value_t = false)]
        intern: bool,
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

    /// search for tags or tag values
    #[command(subcommand)]
    Tag(TagOp),

    Search { tags: Vec<String> },

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
        #[clap(long)]
        category: Option<ItemCategory>,

        what: String,
    },

    #[command(subcommand)]
    Config(Config),

    Replicate {
        #[clap(long)]
        category: Option<ItemCategory>,

        what: String,

        // TODO: should this be able to take a "src" to replicate from? in which case the behavior
        // is more like we're asking remote A to act on our behalf to replicate to remote B,
        // presumably using our credentials
        /// a remote hof to replicate the file into.
        ///
        /// this is used for two purposes:
        /// * to find the remote address to replicae the file to,
        /// * to identify what host holds the new replica, since we record that as a remote
        /// replica of this file too
        ///
        /// this can be a hostname or IP address (and port, if non-default). if this is a name, the
        /// local hof replica configuration is checked to see if we know a remote hostname for the
        /// replica, rather than using the name directly for DNS.
        ///
        /// since uploads require a token valid for writing to the remote, use a token from the
        /// local hof's remote config if one is present. if not, raise an error...
        dest: String,

        /// where we'd like to suggest the remote store the file.
        dest_path: Option<String>,
    }
}

#[derive(Subcommand)]
enum TagOp {
    #[command(subcommand)]
    Search(TagSearch),
}

#[derive(Subcommand)]
enum TagSearch {
    Name {
        #[clap(long, default_value_t = false)]
        exact: bool,
        substr: String,
    },
    Value {
        #[clap(long, default_value_t = false)]
        exact: bool,
        /// only return results for tags with less than this many distinct values.
        /// this can be useful to avoid unintentionally picking tags for highly-variable tags like
        /// "cite" or "ref". defaults to 10. set to 0 to disable this filter.
        #[clap(long, default_value_t = 10)]
        max_cardinality: u64,
        substr: String,
    },
}

#[derive(Clone, Subcommand)]
enum Config {
    Identity,
    Remote {
        #[command(subcommand)]
        operation: RemoteConf
    },
}

#[derive(Clone, Subcommand)]
enum RemoteConf {
    Add {
        name: String,
        addr: String,
        pubkey: String,
    },
    List {
        name: Option<String>,
    },
    Remove {
        name: String,
    },
    AlterToken {
        token: String,
        private_ok: bool,
    }
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

fn main() {
    let args = Cli::parse();

    let db_path = args.db_path.unwrap_or_else(|| "./hof.db".to_owned());
    let config_path = "./config".to_owned();

    let hof = Hof::new(db_path, config_path);

    match args.command {
        Command::Describe { category, what } => {
            let id = match category {
                Some(ItemCategory::Path) => {
                    let hostname: String = gethostname::gethostname()
                        .into_string()
                        .expect("hostname is a valid utf8 string");

                    hof.replica_lookup(&hostname, &what).expect("TODO: can do db query")
                },
                Some(ItemCategory::Hash) => {
                    hof.hash_lookup(&what).expect("TODO: can do db query")
                },
                Some(ItemCategory::Id) => {
                    let id: u64 = what.parse().expect("TODO: handle non-int \"id\"");
                    Some(id)
                },
                None => {
                    // we don't know if the provided thing is a hash, file path, or id. the user
                    // hasn't suggested one way or the other. try a hash lookup, assume it might be
                    // a file path if not.
                    if let Some(id) = hof.hash_lookup(&what).expect("TODO: can do db query") {
                        Some(id)
                    } else {
                        let hostname: String = gethostname::gethostname()
                            .into_string()
                            .expect("hostname is a valid utf8 string");

                        hof.replica_lookup(&hostname, &what).expect("TODO: can do db query")
                    }
                }
            };

            let id = match id {
                Some(id) => id,
                None => {
                    if let Some(category) = category {
                        eprintln!("no {} tracked as {}", category, what);
                    } else {
                        eprintln!("{} is not a known path or hash", what);
                    }
                    std::process::exit(1);
                }
            };

            let desc = hof.db.describe_file(id).expect("can describe file");

            print_description(&desc);
        },
        Command::Config(Config::Identity) => {
            println!("my identity: {}", hof.cfg.pubkey_base64());
        },
        Command::Config(Config::Remote { operation: RemoteConf::Add { name, addr, pubkey }}) => {
            match hof.cfg.add_remote(&name, &addr, &pubkey) {
                Ok(()) => {
                    println!("[+] added remote {}", name);
                }
                Err(e) => {
                    println!("[!] could not add remote {}: {}", name, e);
                }
            }
        },
        Command::Config(Config::Remote { operation: RemoteConf::List { name }}) => {
        },
        Command::Config(Config::Remote { operation: RemoteConf::Remove { name }}) => {
        },
        Command::Config(Config::Remote { operation: RemoteConf::AlterToken { token, private_ok }}) => {
        },
        Command::AddFile { what, intern, recursive } => {
            if recursive {
                panic!("recursive add not supported yet");
            } else {
                if intern {
                    // hof.intern_file(what).expect("works");
                } else {
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
                // TODO:
                // source = manual = 2
                hof.add_file_tag(file_id, 2, &tag_key, &tag_value).expect("works");
            } else if let Ok(Some(file_id)) = {
                let hostname: String = gethostname::gethostname()
                    .into_string()
                    .expect("hostname is a valid utf8 string");

                hof.replica_lookup(&hostname, &what)
            } {
                // source = manual = 2
                hof.add_file_tag(file_id, 2, &tag_key, &tag_value).expect("works");
            } else {
                panic!("unsure what {} is", what);
            }
        }
        Command::ListTags => {
            for tag_id in hof.db.list_tags().expect("can list tags").into_iter() {
                println!("{}", hof.db.tag_name(tag_id).expect("can get tag names").expect("if tag was listed it has a name"));
            }
        }
        Command::Tag(TagOp::Search(TagSearch::Name { exact, substr })) => {
            for tag_id in hof.db.select_tags_with_name_like(exact, &substr).expect("can serach tags").into_iter() {
                println!("{}", hof.db.tag_name(tag_id).expect("can get tag name").expect("if tag was found it has a name"));
            }
        }
        Command::Tag(TagOp::Search(TagSearch::Value { exact, max_cardinality, substr })) => {
            let max_cardinality = if max_cardinality != 0 {
                Some(max_cardinality)
            } else {
                None
            };

            for (name, _, value) in hof.db.select_tags_with_value_like(exact, &substr, max_cardinality).expect("can search").into_iter() {
                println!("{}: {}", name, value);
            }
        }
        Command::Search { tags } => {
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
                print_description(&desc);
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
        Command::Replicate {
            category,
            what,
            dest,
            dest_path,
        } => {
            use reqwest::header::HeaderValue;
            let id = match category {
                Some(ItemCategory::Path) => {
                    let hostname: String = gethostname::gethostname()
                        .into_string()
                        .expect("hostname is a valid utf8 string");

                    hof.replica_lookup(&hostname, &what).expect("TODO: can do db query")
                },
                Some(ItemCategory::Hash) => {
                    hof.hash_lookup(&what).expect("TODO: can do db query")
                },
                Some(ItemCategory::Id) => {
                    let id: u64 = what.parse().expect("TODO: handle non-int \"id\"");
                    Some(id)
                },
                None => {
                    // we don't know if the provided thing is a hash, file path, or id. the user
                    // hasn't suggested one way or the other. try a hash lookup, assume it might be
                    // a file path if not.
                    if let Some(id) = hof.hash_lookup(&what).expect("TODO: can do db query") {
                        Some(id)
                    } else {
                        let hostname: String = gethostname::gethostname()
                            .into_string()
                            .expect("hostname is a valid utf8 string");

                        hof.replica_lookup(&hostname, &what).expect("TODO: can do db query")
                    }
                }
            };

            let id = match id {
                Some(id) => id,
                None => {
                    if let Some(category) = category {
                        eprintln!("no {} tracked as {}", category, what);
                    } else {
                        eprintln!("{} is not a known path or hash", what);
                    }
                    std::process::exit(1);
                }
            };

            let desc = hof.db.describe_file(id).expect("can describe file");

            let hostname: String = gethostname::gethostname()
                .into_string()
                .expect("hostname is a valid utf8 string");

            let path: PathBuf = {
                let mut path = None;
                for replica in desc.replicas.iter() {
                    if replica.valid && replica.who.as_ref() == Some(&hostname) {
                        if let Some(replica_path) = replica.path.as_ref() {
                            match std::fs::metadata(&replica_path) {
                                Ok(md) => {
                                    if md.is_file() {
                                        path = Some(replica_path.to_owned());
                                        break;
                                    }
                                }
                                Err(e) => {
                                    eprintln!("could not get metadata for {}: {}", replica_path, e);
                                }
                            }
                        }
                    }
                }

                match path {
                    Some(p) => p.into(),
                    None => {
                        panic!("no local replica for {:?} {}", category, what);
                    }
                }
            };

            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_io()
                .build().expect("TODO: current thread runtime");

            let resp = rt.block_on(async move {
                let file = match tokio::fs::File::open(&path).await {
                    Ok(f) => f,
                    Err(e) => {
                        eprintln!("couldn't open file {} but we know it? {:?}", path.display(), e);
                        std::process::exit(1);
                    }
                };

                // ok, file exists, lets.. put it over there now.
                use reqwest::{Client, header::HeaderMap};

                let client = reqwest::Client::new();
                let mut headers = HeaderMap::new();

                if let Some(md5) = desc.md5.as_ref() {
                    headers.insert("file-md5", HeaderValue::from_str(md5).expect("valid value"));
                }

                if let Some(sha1) = desc.sha1.as_ref() {
                    headers.insert("file-sha1", HeaderValue::from_str(sha1).expect("valid value"));
                }

                if let Some(sha256) = desc.sha256.as_ref() {
                    headers.insert("file-sha256", HeaderValue::from_str(sha256).expect("valid value"));
                }

                if let Some(dest) = dest_path.as_ref() {
                    headers.insert("file-path", HeaderValue::from_str(dest).expect("valid value"));
                }

                headers.insert("auth", HeaderValue::from_str("trustme").expect("valid value"));

                // TODO: lookup procedure for "dest"
                //
                // problems:
                // * i may want to replicate to `astronomy_storage`, wherever that is. just
                // replicate to it. go.
                //   - the exact replication strategy for `astronomy_storage` may be fuzzier:
                //      "store on this disk, that disk, and backblaze"
                // * i may want to replicate specifically to `www.iximeow.net`. `www.iximeow.net`
                //   might even call the collection some name i don't know. i don't really care,
                //   just put the data there.
                // * i may want to replicate to one specific collection on ivorytower. not to all,
                //   and definitely not to an arbtrarily chosen one.
                //
                // i think this means the resolution procedure is:
                // * for collections like `astronomy_storage`, the collection's replication
                // strategy and internal details are tracked elsewhere. perhaps part of the
                // collection type? at which point i pick the "best" mirror by some metric and
                // replicate to it.
                // * for collections like `www.iximeow.net`. the remote should have a default
                // replica. we just need to look up the name. we don't need to know the default
                // destination replica.
                // * easiest case: replicate to the host and tell it it can pick where to put the
                // data. this likely means interning it.
                let dest_addr = hof.cfg.lookup_remote_addr(&dest).expect("TODO: works").unwrap_or_else(|| dest.clone());

                eprintln!("[i] headers: {:?}", headers);

                let req = client.post(&format!("http://{}/file/upload", dest_addr))
                    .headers(headers)
                    .body(file);
                let resp = req.send().await.expect("TODO: can send");

                match resp.status() {
                    reqwest::StatusCode::OK => {
                        eprintln!("[+] remote accepted the data");
                        let body = resp.text().await.expect("can get body");
                        let remote_file_id: u64 = body.parse()
                            .expect("valid integer");
                        for tag in desc.tags.iter() {
                            eprintln!("sending tag {}={}", tag.name, tag.value);
                            let mut tag_headers = HeaderMap::new();
                            tag_headers.insert("tag", HeaderValue::from_str(&tag.name).expect("can header"));
                            tag_headers.insert("tag-value", HeaderValue::from_str(&tag.value).expect("can header"));
                            let tag_res = client.post(
                                &format!(
                                    "http://{}/file/{}/tag",
                                    dest_addr,
                                    remote_file_id,
                                )
                            )
                                .headers(tag_headers)
                                .send()
                                .await
                                .expect("can send tag req");

                            eprintln!("[!] tag res: {:?}", tag_res);
                        }
                        // TODO: add local replica tracking remote
                    },
                    reqwest::StatusCode::FOUND => {
                        eprintln!("[i] remote already has the data");
                    },
                    o => {
                        eprintln!("[!] remote said {}. full response: {:?}", o, resp);
                    }
                }
            });
        }
    }
}

fn index_tree(hof: Hof, root: String) {
    // not sure if `root` is a file or a directory yet. worklist will only yet-untraversed
    // directory paths. so check if we're even doing all that for `root` first...

    let mut worklist: Vec<PathBuf> = Vec::new();

    match std::fs::metadata(&root) {
        Ok(md) => {
            if md.is_file() {
                print!("indexing {}... ", root.as_str());
                let start = Instant::now();
                hof.add_file(root.as_str()).expect("can index file");
                println!("done in {:0.2}ms", start.elapsed().as_micros() as f64 / 1000.0);
                return;
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
        println!("worklist: {} dirs", worklist.len() + 1);
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
                            println!("discovered dir {}", entry.path().display());
                            worklist.push(entry.path());
                        }
                        Ok(t) if t.is_file() => {
                            print!("indexing {}... ", entry.path().display());
                            use std::io::Write;
                            std::io::stdout().flush().expect("can flush");
                            let start = Instant::now();
                            hof.add_file(entry.path()).expect("can index file");
                            println!("done in {:0.2}ms", start.elapsed().as_micros() as f64 / 1000.0);
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
        if let Some(collection_id) = replica.collection_id.as_ref() {
            if let Some(path) = replica.path.as_ref() {
                print!("  collection {} ({}), path={}", replica.collection_name.as_ref().unwrap(), collection_id, path);
                if let Some(base) = replica.collection_base.as_ref() {
                    let base = base.strip_suffix("/").unwrap_or(base);
                    let path = path.strip_prefix("/").unwrap_or(path);
                    print!("\n    full path: {}/{}", base, path);
                }
            } else {
                print!("  collection {}, no path?", replica.collection_name.as_ref().unwrap());
            }
        } else if let Some(replica_name) = replica.path.as_ref() {
            if let Some(who) = replica.who.as_ref() {
                print!("  {}: {}, checked {}", who, replica_name, replica.last_check_ts);
                if replica.valid {
                    print!(" (valid)");
                }
            } else {
                print!("  <unknown>: {}", replica_name);
            }
        } else if let Some(replica_who) = replica.who.as_ref() {
            print!("  {}: remote", replica_who);
        } else {
            print!("  <unknown>");
        }
        println!("");
    }
    println!("tags:");
    for tag in desc.tags.iter() {
        println!("  {}: {}, from {}", tag.name, tag.value, tag.source);
    }
}

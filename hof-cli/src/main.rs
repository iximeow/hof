use clap::{Parser, Subcommand};

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


    /// add a tag to a file either by hash or path
    AddTag {
        what: String,
        tag_key: String,
        tag_value: String,
    },

    ListTags,

    SearchTags { tags: Vec<String> }
}

fn main() {
    let args = Args::parse();

    let db_path = args.db_path.unwrap_or_else(|| "./hof.db".to_owned());

    let mut hof = Hof::new(db_path);

    match args.command {
        Command::AddFile { what, recursive } => {
            if recursive == Some(true) {
                panic!("recursive add not supported yet");
            } else {
                hof.add_file(what).expect("works");
            }
        },
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
                            computed_tags.push(hofvarpnir::Tag {
                                key: hofvarpnir::TagId(tag_id),
                                value: Some(v.to_string()),
                            });
                        } else {
                            panic!("unknown tag: {}", k);
                        }
                    },
                    None => {
                        let k = t;
                        if let Ok(Some(tag_id)) = hof.db.tag_to_id(k) {
                            computed_tags.push(hofvarpnir::Tag {
                                key: hofvarpnir::TagId(tag_id),
                                value: None,
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
                println!("  sha256: {}", desc.sha256);
                println!("  sha1:   {}", desc.sha1);
                println!("  md5:    {}", desc.md5);
                println!("replicas:");
                for replica in desc.replicas.iter() {
                    print!("  {}: {}, checked {}", replica.who, replica.replica, replica.last_check_ts);
                    if replica.valid {
                        print!(" (valid)");
                    }
                    println!("");
                }
                println!("tags:");
                for tag in desc.tags.iter() {
                    println!("  {}: {}, from {}", tag.name, tag.value, tag.source);
                }

//                println!("file {}", f);
            }
        }
    }
}

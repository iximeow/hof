use std::collections::HashSet;
use std::fs::File;
use std::path::{Path, PathBuf};

use serde_derive::{Deserialize, Serialize};

/// a "file". some thingy somewhere. importantly, it might be an archive, tag in some other
/// content-tracking system (git, etc), and it may be referenced as the source of other content.
/// a file may have associated data and replicas as tracked in a hof database.
struct FileId(u64);

/// a file's data is stored somewhere. it might be here, it might not be here. in either case, it
/// might be internal or external. or it's even in a remote storage service (s3, b2, etc). one
/// file may have many replicas.
///
/// for files tracked in other content-tracking systems (like git), this may even be a compound
/// path referencing a commit sha and path. in such cases, a replica might look like:
/// ```text
/// Replica {
///     who: "https://git.iximeow.net/yaxpeax-x86.git",
///     path: ReplicaPath("git:1.1.1:src/lib.rs"),
/// }
/// ```
///
/// especially for other content-tracking systems, like git, a replica might not refer to a single
/// item on a filesystem - a replica for `yaxpeax-x86` version `1.1.1` could reasonably be,
/// ```text
/// Replica {
///     who: "https://www.github.com/iximeow/yaxpeax-x86.git",
///     path: ReplicaPath("git:1.1.1"),
/// }
/// ```
struct Replica {
    // who has it? these two fields are optional because it is possible we know about a file
    // without being able to say where it is or who might have it. this is uncommon... it's also
    // probably the case that for such a file there simply should not be a replica recorded, and
    // any information about the file's theorized location somewhere should be retained as a tag on
    // the file instead.
    who: Option<String>,
    // and where do they think it is? again, optional because we may only know where the file
    // exists, or we may not even know where to find it, just that something exists.
    path: Option<ReplicaPath>,
}

/// the path to a replica of some data. its exact meaning depends on the replica processing this
/// path. it's probably a filesystem path, but could be an object name in s3/b2/etc.
struct ReplicaPath(String);

/// some storage medium a replica lives on. this might be a disk name, a volume name,
/// backblaze bucket, s3 bucket, etc.
///
/// TODO: this is probably a prefix of a ReplicaPath. i'm not sure yet.
///
/// note: disk/volume names are not attached to hostnames because disks can move between hosts.
struct StorageMedium(String);

#[derive(Debug)]
pub struct TagId(pub u64);

enum TagValue {
    Unit,
    Value(String),
}

/// metadata about a file. many files may have the same tags, which is expected even: among other
/// things, files might be tagged by archive they're extracted from, or if they're computed, tagged
/// by the inputs to their computation. selecting all files tagged 'rust', 'crate', 'yaxpeax-x86',
/// '1.1.1' might yield a whole source tree.
pub struct Tag {
    pub key: TagId,
    pub value: Option<String>,
}

#[derive(Debug)]
pub struct TagFilter {
    pub key: TagId,
    pub values: Option<HashSet<String>>,
}

trait TagSource {
    fn compute_tags(f: File) -> Vec<Tag>;
}

struct FileAddition {
    
}

trait Database {
    fn select_files(&self, tags: &[Tag]) -> dyn Iterator<Item=FileId>;
    fn add_file(&self, hash: String) -> Result<FileAddition, ()>;
    fn add_tag(&self, hash: String, tag: Tag) -> Result<(), ()>;
}

pub use db::data::{Collection, Description, PathLookup, Token};

mod db {
    use rusqlite::{params, Connection, OptionalExtension};
    use std::path::{Path, PathBuf};
    use std::sync::Mutex;

    pub mod audit {
        use serde_derive::{Deserialize, Serialize};

        #[derive(Deserialize, Serialize)]
        pub enum AuditEvent {
            KeyAdded { key: u64 },
            KeyDisabled { key: u64 },
            TokenCreated { key: u64, token: u64 },
            TokenRetired { token: u64 },
        }
    }

    pub mod data {
        use std::path::PathBuf;

        pub enum PathLookup {
            Exact(String),
            Prefix(String),
            Suffix(String),
            Contains(String),
        }
        #[derive(Debug)]
        pub struct Replica {
            // who has it? these two fields are optional because it is possible we know about a file
            // without being able to say where it is or who might have it. this is uncommon... it's also
            // probably the case that for such a file there simply should not be a replica recorded, and
            // any information about the file's theorized location somewhere should be retained as a tag on
            // the file instead.
            pub who: Option<String>,
            pub collection_id: Option<u64>,
            pub collection_name: Option<String>,
            pub collection_base: Option<String>,
            // we may know someone has the file by some name, but not who or where. retain the name
            // for tracking purposes, but this is basically a dead reference..
            pub path: Option<String>,
            pub valid: bool,
            pub last_check_ts: u64,
        }

        pub struct Tag {
            pub name: String,
            pub value: String,
            pub source: String,
        }

        pub struct Description {
            pub file_id: u64,
            pub sha256: Option<String>,
            pub sha1: Option<String>,
            pub md5: Option<String>,
            pub replicas: Vec<Replica>,
            pub tags: Vec<Tag>,
        }

        pub struct Token {
            pub id: u32,
            pub token: String,
            pub pubkey_id: u32,
            pub not_after: u64,
            pub issued_at: u64,
            pub private_ok: bool,
            pub write_ok: bool,
            pub revoked: bool,
            pub administrative: bool,
        }

        pub struct Collection {
            pub id: u32,
            pub name: String,
            pub style: String,
            pub description: String,
            pub location: PathBuf,
        }
    }

    pub enum FileAddResult {
        New(u64),
        Exists(u64),
    }

    pub struct DbCtx {
        conn: Mutex<Connection>
    }

    impl DbCtx {
        pub fn new<P: AsRef<Path>>(db_path: P) -> Self {
            DbCtx {
                conn: Mutex::new(Connection::open(db_path).unwrap())
            }
        }

        pub fn create_tables(&self) -> Result<(), ()> {
            let conn = self.conn.lock().unwrap();
            conn.execute("\
                CREATE TABLE IF NOT EXISTS files (\
                    id INTEGER PRIMARY KEY, \
                    sha256 TEXT, sha1 TEXT, md5 TEXT, \
                    UNIQUE(sha256) ON CONFLICT ABORT, \
                    UNIQUE(sha1) ON CONFLICT ABORT, \
                    UNIQUE(md5) ON CONFLICT ABORT
                );", params![]).unwrap();
            conn.execute("\
                CREATE TABLE IF NOT EXISTS tags (id INTEGER PRIMARY KEY, name TEXT, UNIQUE(name));", params![]).unwrap();
            // a record of which tag sources have processed a file (and when)
            conn.execute("\
                CREATE TABLE IF NOT EXISTS tag_log (id INTEGER PRIMARY KEY, file_id INTEGER, source INTEGER, state INTEGER, version INTEGER, tag_time INTEGER);", params![]).unwrap();
            conn.execute("\
                CREATE TABLE IF NOT EXISTS file_tags (id INTEGER PRIMARY KEY, tag INTEGER, file_id INTEGER, source INTEGER, value TEXT);", params![]).unwrap();
            // this index is also useful for `fn tag_worklist`, specifically when a worklist may
            // have only a few specific interesting tags
            conn.execute("\
                CREATE INDEX IF NOT EXISTS file_tag_sources on file_tags (tag, file_id, source);", params![]).unwrap();
            // not immediately useful, but if `fn tag_worklist` joins on file id with no query on
            // tags' source_id or generator_state then the lack of index is a real drag.
            //
            // this can end up being useful if a tag generator declares a list of interests that
            // specifies no tags.
            conn.execute("\
                CREATE INDEX IF NOT EXISTS file_tag_file_ids on file_tags (file_id);", params![]).unwrap();
            conn.execute("\
                CREATE TABLE IF NOT EXISTS replicas (id INTEGER PRIMARY KEY, file_id INTEGER, who TEXT, collection_id INTEGER, path TEXT, valid TINYINT, last_check INTEGER);", params![]).unwrap();
            // each replica exists somewhere, replica_host describes a somewhere.
            // replica hosts might be a directory on a host, a disk, an ID for removable storage
            // (such as a disk), an s3, digitalocean, backblaze bucket name, a hostname, who knows.
            //
            // "name" is a human-readable name to summarize the replica host, "description" is a
            // secondary field if more expansive text is appropriate.
            //
            // "style" and "location" work together to describe the mechanics of the replica: how
            // it is accessed, how the presence of contents should be validated, if it can be read
            // or written to, if it should be synced to or from, etc
            //
            // for example, `"style=filesystem,ssh@iximeow,net@midgard.iximeow.net",
            // "location=midgard:/zfs18t/astro/indexed" describes a replica rooted at
            // /zfs18t/astro/indexed on the host `midgard`. it is accessible via filesystem (if the
            // local machine is "midgard"), ssh (if it is not), and via internet through the name
            // `midgard.iximeow.net`. these are tried in order. how to address a replica depends on
            // the mechanism it is being accessed through.
            //
            // this isn't expressive enough! unfortunate. figure this out at some point. maybe each
            // replica needs a list of "access mechanism" or something..?
            conn.execute("\
                CREATE TABLE IF NOT EXISTS collections (id INTEGER PRIMARY KEY, name TEXT, style TEXT, description TEXT, location TEXT);", params![]).unwrap();

            conn.execute("\
                CREATE TABLE IF NOT EXISTS acls (id INTEGER PRIMARY KEY, rule TEXT);", params![]).unwrap();
            conn.execute("\
                CREATE TABLE IF NOT EXISTS file_acls (id INTEGER PRIMARY KEY, file_id INTEGER, rule INTEGER);", params![]).unwrap();
            conn.execute("\
                CREATE TABLE IF NOT EXISTS tag_worklist (id INTEGER PRIMARY KEY, file_id INTEGER, source_id INTEGER, generator_state INTEGER, tag_time INTEGER);", params![]).unwrap();
            conn.execute("\
                CREATE UNIQUE INDEX IF NOT EXISTS idx_tag_worklist_state ON tag_worklist (file_id, source_id);", params![]).unwrap();
            // this in particular helps calculate worklists per-tag-generator in a reasonable
            // amount of time... (fn tag_worklist() is about 6x slower without this one)
            conn.execute("\
                CREATE UNIQUE INDEX IF NOT EXISTS idx_tag_worklist_state2 ON tag_worklist (file_id, source_id, generator_state);", params![]).unwrap();
            conn.execute("\
                CREATE TABLE IF NOT EXISTS tag_sources (id INTEGER PRIMARY KEY, name TEXT, version INTEGER);", params![]).unwrap();
            conn.execute("\
                CREATE UNIQUE INDEX IF NOT EXISTS idx_tag_sources ON tag_sources (name, version);", params![]).unwrap();

            // and i guess it's time to include a bunch of auth stuff...
            conn.execute("\
                CREATE TABLE IF NOT EXISTS pubkeys (id INTEGER PRIMARY KEY, key BLOB, name TEXT, email TEXT, allowed BOOL);", params![]).unwrap();
            conn.execute("\
                CREATE UNIQUE INDEX IF NOT EXISTS key_uniqueness on pubkeys (key);", params![]).unwrap();
            // no real acl logic yet, just a bool for if the token is allowed to see `adhoc:access=private` files
            conn.execute("\
                CREATE TABLE IF NOT EXISTS tokens (id INTEGER PRIMARY KEY, token TEXT, pubkey INTEGER, not_after INTEGER, issued_at INTEGER, private_ok BOOL, write_ok BOOL, revoked BOOL, administrative BOOL);", params![]).unwrap();
            conn.execute("\
                CREATE UNIQUE INDEX IF NOT EXISTS token_uniqueness on tokens (token);", params![]).unwrap();
            conn.execute("\
                CREATE UNIQUE INDEX IF NOT EXISTS token_key_lookup on tokens (token, pubkey);", params![]).unwrap();
            conn.execute("\
                CREATE TABLE IF NOT EXISTS audit (id INTEGER PRIMARY KEY, time INTEGER, token_id INTEGER, action INTEGER, desc TEXT);", params![]).unwrap();

            Ok(())
        }

        pub fn audit_event(&self, token_id: Option<u64>, action: audit::AuditEvent) -> Result<(), String> {
            let now = crate::now_ms();
            let (action, desc) = match action {
                audit::AuditEvent::KeyAdded { .. } => {
                    (1, serde_json::to_string(&action))
                },
                audit::AuditEvent::KeyDisabled { .. } => {
                    (2, serde_json::to_string(&action))
                },
                audit::AuditEvent::TokenCreated { .. } => {
                    (3, serde_json::to_string(&action))
                },
                audit::AuditEvent::TokenRetired { .. } => {
                    (4, serde_json::to_string(&action))
                }
            };

            // TODO: record audit events

            Ok(())
        }

        pub fn lookup_collection(&self, collection_name: &str) -> Result<Option<data::Collection>, String> {
            let conn = self.conn.lock().unwrap();

            let mut stmt = conn.prepare_cached("select id, name, style, description, location from collections where name=?1;")
                .map_err(|e| format!("unable to prepare query: {:?}", e))?;
            let mut rows = stmt.query_map(params![collection_name], |row| {
                let id: u32 = row.get(0).unwrap();
                let name: String = row.get(1).unwrap();
                let style: String = row.get(2).unwrap();
                let description: String = row.get(3).unwrap();
                let location: String = row.get(4).unwrap();
                let location: PathBuf = location.into();
                Ok(data::Collection {
                    id,
                    name,
                    style,
                    description,
                    location,
                })
            })
                .map_err(|e| format!("unable to execute query: {:?}", e))?;

            match rows.next() {
                Some(Ok(collection)) => {
                    if rows.next().is_some() {
                        return Err(format!("multiple collections for {}?", collection_name));
                    }

                    Ok(Some(collection))
                },
                Some(Err(e)) => {
                    return Err(format!("query error: {:?}", e));
                }
                None => {
                    Ok(None)
                }
            }
        }

        pub fn lookup_token(&self, token_str: &str) -> Result<Option<data::Token>, String> {
            let conn = self.conn.lock().unwrap();

            let mut stmt = conn.prepare_cached("select id, token, pubkey, not_after, issued_at, private_ok, write_ok, revoked, administrative from tokens where token=?1;")
                .map_err(|e| format!("unable to prepare query: {:?}", e))?;
            let mut rows = stmt.query_map(params![token_str], |row| {
                let id: u32 = row.get(0).unwrap();
                let token: String = row.get(1).unwrap();
                let pubkey_id: u32 = row.get(2).unwrap();
                let not_after: u64 = row.get(3).unwrap();
                let issued_at: u64 = row.get(4).unwrap();
                let private_ok: bool = row.get(5).unwrap();
                let write_ok: bool = row.get(6).unwrap();
                let revoked: bool = row.get(7).unwrap();
                let administrative: bool = row.get(8).unwrap();
                Ok(data::Token {
                    id,
                    token,
                    pubkey_id,
                    not_after,
                    issued_at,
                    private_ok,
                    write_ok,
                    revoked,
                    administrative,
                })
            })
                .map_err(|e| format!("unable to execute query: {:?}", e))?;

            match rows.next() {
                Some(Ok(token)) => {
                    if rows.next().is_some() {
                        return Err(format!("multiple tokens for {}?", token_str));
                    }

                    Ok(Some(token))
                },
                Some(Err(e)) => {
                    return Err(format!("query error: {:?}", e));
                }
                None => {
                    Ok(None)
                }
            }
        }

        pub fn refresh_token(&self, token: &data::Token) -> Result<(), String> {
            let conn = self.conn.lock().unwrap();

            let now = crate::now_ms();
            // rough idea: expire a token if it has not been used in a month.
            let not_after = now + 1000 * 3600 * 24 * 30;

            let res = conn.execute(
                "update tokens set not_after=?1 where id=?2 and revoked=0;",
                params![not_after, token.id],
            );

            res
                .map(|rows| assert_eq!(rows, 1))
                .map_err(|e| format!("failed to update: {:?}", e))
        }

        pub fn create_token(&self, pubkey: u64, private_ok: bool) -> Result<String, String> {
            let conn = self.conn.lock().unwrap();
            let token = "new token".to_string();
            // TODO: should check that pubkey references something in the pubkeys table... honestly
            // should have a foreign key constraint too
            let now = crate::now_ms();
            let issued_at = now;
            // rough idea: expire a token if it has not been used in a month.
            let not_after = now + 1000 * 3600 * 24 * 30;

            let insert_res = conn.execute(
                "insert into tokens (token, pubkey, not_after, issued_at, private_ok, write_ok, revoked, administrative) values (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8);",
                // not for private access, not for writing, not revoked, and definitely not
                // administrative by default.
                params![token, pubkey, not_after, issued_at, false, false, false, false],
            );

            match insert_res {
                Ok(1) => {
                    // inserted onw item, so that's the new id.
                    let last_id = conn.last_insert_rowid() as u64;
                    drop(conn);
                    self.audit_event(None, audit::AuditEvent::TokenCreated { key: last_id, token: last_id, })
                        .expect("can record");
                    Ok(token.to_owned())
                }
                Ok(rows) => {
                    unreachable!("attempted to insert one row, actually inserted .... {} ???", rows);
                }
                Err(rusqlite::Error::SqliteFailure(sql_err, _)) if sql_err.code == rusqlite::ErrorCode::ConstraintViolation => {
                    Err("already exists".to_string())
                }
                Err(e) => {
                    panic!("unexpected err: {:?}", e);
                }
            }
        }

        pub fn add_key(&self, key: &[u8], name: &str, email: &str) -> Result<u64, String> {
            let conn = self.conn.lock().unwrap();
            let insert_res = conn.execute(
                "insert into pubkeys (key, name, email, allowed, administrative) values (?1, ?2, ?3, ?4, ?5);",
                params![key, name, email, true, false]
            );

            match insert_res {
                Ok(1) => {
                    // inserted onw item, so that's the new id.
                    let last_id = conn.last_insert_rowid() as u64;
                    drop(conn);
                    self.audit_event(None, audit::AuditEvent::KeyAdded { key: last_id })
                        .expect("can record");
                    Ok(last_id)
                }
                Ok(rows) => {
                    unreachable!("attempted to insert one row, actually inserted .... {} ???", rows);
                }
                Err(rusqlite::Error::SqliteFailure(sql_err, _)) if sql_err.code == rusqlite::ErrorCode::ConstraintViolation => {
                    Err("already exists".to_string())
                }
                Err(e) => {
                    panic!("unexpected err: {:?}", e);
                }
            }
        }

        pub fn get_tag_generator_manual_id(&self) -> Result<u64, String> {
            let name = "manual";
            let version = Option::<u32>::None;

            let conn = self.conn.lock().unwrap();
            let insert_res = conn.execute(
                "insert into tag_sources (name, version) values (?1, ?2);",
                params![name, version]
            );

            match insert_res {
                Ok(1) => {
                    // inserted onw item, so that's the new id.
                    Ok(conn.last_insert_rowid() as u64)
                }
                Ok(rows) => {
                    unreachable!("attempted to insert one row, actually inserted .... {} ???", rows);
                }
                Err(rusqlite::Error::SqliteFailure(sql_err, _)) if sql_err.code == rusqlite::ErrorCode::ConstraintViolation => {
                    Ok(conn.query_row(
                        "select id from tag_sources where name=?1 and version=?2",
                        params![name, version],
                        |row| { row.get(0) }
                    ).unwrap())
                }
                Err(e) => {
                    panic!("unexpected err: {:?}", e);
                }
            }
        }

        pub fn get_tag_generator_id(&self, name: &str, version: u64) -> Result<Option<u64>, String> {
            let conn = self.conn.lock().unwrap();
            Ok(conn.query_row(
                "select id from tag_sources where name=?1 and version=?2",
                params![name, version],
                |row| { row.get(0) }
            ).optional().unwrap())
        }

        pub fn create_tag_generator_id(&self, name: &str, version: u64) -> Result<u64, String> {
            let conn = self.conn.lock().unwrap();
            let insert_res = conn.execute(
                "insert into tag_sources (name, version) values (?1, ?2);",
                params![name, version]
            );

            match insert_res {
                Ok(1) => {
                    // inserted onw item, so that's the new id.
                    Ok(conn.last_insert_rowid() as u64)
                }
                Ok(rows) => {
                    unreachable!("attempted to insert one row, actually inserted .... {} ???", rows);
                }
                Err(rusqlite::Error::SqliteFailure(sql_err, _)) if sql_err.code == rusqlite::ErrorCode::ConstraintViolation => {
                    Ok(conn.query_row(
                        "select id from tag_sources where name=?1 and version=?2",
                        params![name, version],
                        |row| { row.get(0) }
                    ).unwrap())
                }
                Err(e) => {
                    panic!("unexpected err: {:?}", e);
                }
            }
        }

        // TODO: theoretically this doesn't need to construct a full vec of ids, but to do
        // concurrent queries i'd need to pass the locked connection around(?) or maybe have
        // multiple database connections..
        //
        // this won't survive having tens of millions of files. alas.
        pub fn tag_worklist(&self, source_id: Option<u64>, interests: Option<&[hof_ffi::Interest]>) -> Result<Vec<u64>, String> {
            let query = if let Some(interests) = interests {
                let mut interests_filter: Vec<String> = Vec::new();
                let mut additional_params: Vec<String> = Vec::new();

                for interest in interests.iter() {
                    let tag_id = self.tag_to_id(interest.tag())
                        .expect("can try finding tag");
                    let tag_id = match tag_id {
                        Some(id) => id,
                        None => {
                            eprintln!("want worklist including files tagged {}, but no such tag exists, so no file exists with it", interest.tag());
                            return Ok(Vec::new());
                        }
                    };

                    match (interest.value(), interest.source()) {
                        (Some(value), Some(source)) => {
                            let source_id = self.get_tag_generator_id(source, 1)
                                .expect("can get source");
                            let source_id = match source_id {
                                Some(source_id) => source_id,
                                None => {
                                    return Ok(Vec::new());
                                }
                            };

                            additional_params.push(value.to_owned());
                            let query = format!("(file_tags.tag={} and file_tags.source={} and file_tags.value=?{})", tag_id, source_id, additional_params.len() + 1);
                            interests_filter.push(query);
                        },
                        (Some(value), None) => {
                            additional_params.push(value.to_owned());
                            let query = format!("(file_tags.tag={} and file_tags.value=?{})", tag_id, additional_params.len() + 1);
                            interests_filter.push(query);
                        },
                        (None, Some(source)) => {
                            let source_id = self.get_tag_generator_id(source, 1)
                                .expect("can get source");
                            let source_id = match source_id {
                                Some(source_id) => source_id,
                                None => {
                                    return Ok(Vec::new());
                                }
                            };

                            let query = format!("(file_tags.tag={} and file_tags.source={})", tag_id, source_id);
                            interests_filter.push(query);
                        },
                        (None, None) => {
                            let query = format!("(file_tags.tag={})", tag_id);
                            interests_filter.push(query);
                        }
                    }
                }

                let interests_filter = interests_filter.join(" and ");
                let mut query = "select files.id from files left join tag_worklist on files.id=tag_worklist.file_id and tag_worklist.source_id=?1 left join file_tags on files.id=file_tags.file_id where (tag_worklist.generator_state=0 or tag_worklist.generator_state is null) and ".to_string();
                query.push_str(&interests_filter);
                query.push_str(";");

                query
            } else {
                "select files.id from files left join tag_worklist on files.id=tag_worklist.file_id and tag_worklist.source_id=?1 where (tag_worklist.generator_state=0 or tag_worklist.generator_state is null);".to_owned()
            };

            let conn = self.conn.lock().unwrap();

            let mut stmt = conn.prepare(&query)
                    .expect("can prepare query");

            let rows = stmt.query_map(params![source_id], |row| row.get(0))
                .map_err(|e| format!("unable to execute query: {:?}", e))?;

            let mut worklist: Vec<u64> = Vec::new();
            for file_id in rows {
                let file_id = file_id.map_err(|e| format!("failed to iterate row: {}", e))?;
                worklist.push(file_id);
            }
            Ok(worklist)
        }

        pub fn select_tags_with_name_like(&self, exact: bool, substr: &str) -> Result<Vec<u64>, String> {
            // TODO: sanitize out % in the search string
            let (where_clause, param) = if exact {
                ("name=?1", substr.to_owned())
            } else {
                ("name like ?1", format!("%{}%", substr))
            };

            let query = format!("select id from tags where {};", where_clause);
            let conn = self.conn.lock().unwrap();
            let mut res = Vec::new();

            let mut stmt = conn.prepare(&query)
                .map_err(|e| format!("unable to prepare query: {:?}", e))?;
            let mut rows = stmt.query(params![param])
                .map_err(|e| format!("unable to execute query: {:?}", e))?;

            while let Ok(Some(row)) = rows.next() {
                res.push(row.get(0).expect("can convert selected column to u64"));
            }

            Ok(res)
        }

        pub fn select_tags_with_value_like(&self, exact: bool, substr: &str, cardinality_limit: Option<u64>) -> Result<Vec<(String, u64, String)>, String> {
            let mut params = Vec::new();
            let mut where_clause = if exact {
                params.push(substr.to_owned());
                "file_tags.value=?1".to_owned()
            } else {
                params.push(format!("%{}%", substr));
                "file_tags.value like ?1".to_owned()
            };

            let mut query = "select tags.name, file_tags.tag, file_tags.value from file_tags join tags on file_tags.tag=tags.id where ".to_string();
            query.push_str(&where_clause);

            if let Some(lim) = cardinality_limit {
                let cardinality_filter = format!("file_tags.tag in (select distinct tag from file_tags where {} group by tag having count(distinct value) < {})", where_clause, lim);
                query.push_str(" and ");
                query.push_str(&cardinality_filter);
            }

            query.push_str(" group by file_tags.tag, file_tags.value;");

            let conn = self.conn.lock().unwrap();

            let mut stmt = conn.prepare(&query)
                .map_err(|e| format!("unable to prepare query: {:?}", e))?;
            let mut rows = stmt.query(rusqlite::params_from_iter(params))
                .map_err(|e| format!("unable to execute query: {:?}", e))?;

            let mut res = Vec::new();

            while let Ok(Some(row)) = rows.next() {
                res.push((
                    row.get(0).expect("can convert selected column to String"),
                    row.get(1).expect("can convert selected column to u64"),
                    row.get(2).expect("can convert selected column to String"),
                ));
            }

            Ok(res)
        }

        pub fn select_by_tags<'query>(&'query self, tags: &[crate::TagFilter]) -> Result<Vec<u64>, String> {
            // TODO: extremely simple query logic:
            // * accept multiple tags, multiple values for each tag
            // * results are all files with at least the listed tags, where for each tag the file has least
            // one value matching a searched-for value

            // realistically "select by []" could be made to make sense by using a different query
            // below, but at that point you want "select all files" anyway. so just error early.
            if tags.len() == 0 {
                return Err("cannot select by tags with zero tags".to_string());
            }

            let conn = self.conn.lock().unwrap();
            let mut params = Vec::new();
            let mut prepared_subqueries = Vec::new();
            for tag_filter in tags.iter() {
                let mut tag_query: String;

                if let Some(filters) = tag_filter.values.as_ref() {
                    let mut additional_filter = false;
                    tag_query = String::new();
                    tag_query.push_str("(");

                    for item in filters.iter() {
                        if additional_filter {
                            tag_query.push_str(" OR ");
                        } else {
                            additional_filter = true;
                        }
                        use std::fmt::Write;
                        write!(tag_query, "(tag={} and value=?{})", tag_filter.key.0, params.len() + 1);
                        params.push(item.to_owned());
                    }
                    tag_query.push_str(")");
                } else {
                    tag_query = format!("(tag={})", tag_filter.key.0);
                }

                prepared_subqueries.push(tag_query);
            }
            let filter = prepared_subqueries.join(" OR ");
            let query = format!("select file_id from file_tags where {} group by file_id, tag having count(distinct tag)={}", filter, tags.len());
            eprintln!("query: {}", query);
            let params = rusqlite::params_from_iter(params);
            let mut stmt = conn.prepare(&query)
                .map_err(|e| format!("unable to prepare query: {:?}", e))?;
            let mut rows = stmt.query_map(params, |row| row.get(0))
                .map_err(|e| format!("unable to execute query: {:?}", e))?;

            let mut selected_files: Vec<u64> = Vec::new();
            for file_id in rows {
                let file_id = file_id.map_err(|e| format!("failed to iterate row: {}", e))?;
                selected_files.push(file_id);
            }
            Ok(selected_files)
        }

        // ohhhhhhhhhhhhhhhhhhhhh the replica table needs another unique constraint....
        pub fn find_replica_by_names(&self, collection_name: &str, path: &str) -> Result<Option<data::Replica>, String> {
            let hostname = gethostname::gethostname()
                .into_string()
                .expect("can turn hostname into string");

            let conn = self.conn.lock().unwrap();
            let mut stmt = conn.prepare_cached("select who, collection_id, collections.name, collections.location, path, valid, last_check from replicas join collections on collections.id=replicas.collection_id where replicas.who=?1 and collections.name=?2 and replicas.path=?3;")
                .map_err(|e| format!("unable to prepare query: {:?}", e))?;
            let mut rows = stmt.query_map(params![hostname, collection_name, path], |row| {
                let who: Option<String> = row.get(0).unwrap();
                let collection_id: Option<u64> = row.get(1).unwrap();
                let collection_name: Option<String> = row.get(2).unwrap();
                let collection_base: Option<String> = row.get(3).unwrap();
                let path: Option<String> = row.get(4).unwrap();
                let valid: bool = row.get(5).unwrap();
                let last_check: u64 = row.get(6).unwrap();
                Ok((who, collection_id, collection_name, collection_base, path, valid, last_check))
            })
                .map_err(|e| format!("unable to execute query: {:?}", e))?;

            let res = match rows.next() {
                Some(Ok((who, collection_id, collection_name, collection_base, path, valid, last_check_ts))) => {
                    data::Replica {
                        who,
                        collection_id,
                        collection_name,
                        collection_base,
                        path,
                        valid,
                        last_check_ts,
                    }
                },
                None => {
                    return Ok(None);
                }
                Some(Err(e)) => {
                    return Err(format!("some kind of query error: {}", e));
                }
            };

            if rows.next().is_some() {
                eprintln!("duplicate replicas for hostname={}/collection={}/path={}", hostname, collection_name, path);
                return Err("multiple replicas for a specific hostname/collection/path lookup?".to_string());
            }

            Ok(Some(res))
        }

        pub fn find_local_replica(&self, remote: &str, file_id: u64) -> Result<Option<String>, String> {
            let conn = self.conn.lock().unwrap();
            Ok(conn.query_row(
                "select path from replicas where who=?1 and file_id=?2 and valid=1",
                params![remote, file_id],
                |row| { row.get(0) }
            ).optional().unwrap())
        }

        /// find a file at path `path` in replica `replica`. because this is exact on both
        /// parameters, either there is one result or no result.
        pub fn replica_lookup(&self, replica: &str, path: &str) -> Result<Option<u64>, String> {
            let conn = self.conn.lock().unwrap();
            Ok(conn.query_row(
                "select file_id from replicas where who=?1 and replica=?2 and valid=1",
                params![replica, path],
                |row| { row.get(0) }
            ).optional().unwrap())
        }

        /// find a file related to path `path`, optionally constraining results to those in replica
        /// `replica`.
        pub fn path_lookup(&self, replica: Option<&str>, lookup: data::PathLookup) -> Result<Vec<u64>, String> {
            let (lookup_part, param) = match lookup {
                data::PathLookup::Exact(path) => {
                    ("replica=?1", path)
                },
                data::PathLookup::Prefix(prefix) => {
                    ("replica like ?1", format!("{prefix}%"))
                },
                data::PathLookup::Suffix(suffix) => {
                    ("replica like ?1", format!("%{suffix}"))
                },
                data::PathLookup::Contains(substr) => {
                    ("replica like ?1", format!("%{substr}%"))
                },
            };

            let mut params = vec![param];

            let mut query = format!("select file_id from replicas where {lookup_part}");
            if let Some(replica) = replica {
                query.push_str(" and who=?2");
                params.push(replica.to_owned());
            }
            query.push_str(" group by file_id");
            query.push_str(";");

            let conn = self.conn.lock().unwrap();
            eprintln!("query: {}", query);
            eprintln!("params: {:?}", params);
            let params = rusqlite::params_from_iter(params);
            let mut stmt = conn.prepare(query.as_str())
                .map_err(|e| format!("unable to prepare query: {:?}", e))?;
            let mut rows = stmt.query_map(params, |row| row.get(0))
                .map_err(|e| format!("unable to execute query: {:?}", e))?;

            let mut selected_files: Vec<u64> = Vec::new();
            for file_id in rows {
                let file_id = file_id.map_err(|e| format!("failed to iterate row: {}", e))?;
                selected_files.push(file_id);
            }
            Ok(selected_files)
        }

        pub fn find_file(&self, sha256: &str) -> Result<Option<u64>, String> {
            let conn = self.conn.lock().unwrap();
            Ok(conn.query_row(
                "select id from files where sha256=?1",
                params![&sha256],
                |row| { row.get(0) }
            ).optional().unwrap())
        }

        pub fn tag_to_id(&self, tag: &str) -> Result<Option<u64>, String> {
            let conn = self.conn.lock().unwrap();

            let res = conn.query_row(
                "select id from tags where name=?1",
                params![tag],
                |row| { row.get(0) }
            ).optional().unwrap();

            Ok(res)
        }

        pub fn tag_name(&self, tag_id: u64) -> Result<Option<String>, String> {
            let conn = self.conn.lock().unwrap();

            let res = conn.query_row(
                "select name from tags where id=?1",
                params![tag_id],
                |row| { row.get(0) }
            ).optional().unwrap();

            Ok(res)
        }

        pub fn create_tag(&self, tag: &str) -> Result<u64, String> {
            let conn = self.conn.lock().unwrap();

            let insert_res = conn.execute(
                "insert into tags (name) values (?1);",
                params![tag]
            );

            match insert_res {
                Ok(1) => {
                    // inserted onw item, so that's the new id.
                    Ok(conn.last_insert_rowid() as u64)
                }
                Ok(rows) => {
                    unreachable!("attempted to insert one row, actually inserted .... {} ???", rows);
                }
                Err(rusqlite::Error::SqliteFailure(sql_err, _)) if sql_err.code == rusqlite::ErrorCode::ConstraintViolation => {
                    let res = conn.query_row(
                        "select id from tags where name=?1",
                        params![tag],
                        |row| { row.get(0) }
                    ).unwrap();
                    Ok(res)
                }
                Err(e) => {
                    panic!("unexpected err: {:?}", e);
                }
            }
        }

        pub fn list_tags(&self) -> Result<Vec<u64>, String> {
            let conn = self.conn.lock().unwrap();

            let mut selected_tags: Vec<u64> = Vec::new();

            let mut stmt = conn.prepare("select id from tags;")
                .map_err(|e| format!("unable to prepare query: {:?}", e))?;
            let mut rows = stmt.query(params![])
                .map_err(|e| format!("unable to execute query: {:?}", e))?;

            while let Ok(Some(row)) = rows.next() {
                selected_tags.push(row.get(0).expect("can convert selected column to u64"));
            }

            Ok(selected_tags)
        }

        pub fn add_tag(&self, file_id: u64, source: u64, tag_id: u64, value: &str) -> Result<(), String> {
            let conn = self.conn.lock().unwrap();
            // we'll be simply trusting this replica to be added is currently valid...
            // TODO: reject duplicate tags from the same source?
            let _rows_modified = conn.execute(
                "insert into file_tags (file_id, tag, source, value) values (?1, ?2, ?3, ?4);",
                params![file_id, tag_id, source, value]
            ).unwrap();

            Ok(())
        }

        pub fn tag_generator_state(&self, file_id: u64, generator_id: u64, state: hof_tags::TagGeneratorState) -> Result<(), String> {
            let conn = self.conn.lock().unwrap();
            let rows_modified = conn.prepare_cached(
                "insert or replace into tag_worklist (id, file_id, source_id, generator_state, tag_time) values ((select id from tag_worklist where file_id=?1 and source_id=?2), ?1, ?2, ?3, ?4);",
            ).expect("can prepare statement")
                .execute(params![file_id, generator_id, state as u8, crate::now_ms()]).unwrap();
            assert_eq!(rows_modified, 1);

            Ok(())
        }

        pub fn remote_is_known(&self, host: &str) -> bool {
            let conn = self.conn.lock().unwrap();
            // "select who from replicas where who="?1" group by who
            let query = "select who from replicas where who=?1 group by who;";
            conn.query_row(
                query,
                params![host],
                |row| { Ok(row.get::<usize, String>(0)) }
            ).optional().unwrap().is_some()
        }

        pub fn add_replica(&self, file_id: u64, host: Option<&str>, replica_path: Option<&str>) -> Result<(), ()> {
            use std::time::{SystemTime, UNIX_EPOCH};

            if host == None && replica_path == None {
                panic!("use `add_file` to add a reference to a file known only by a hash, unavailable to the local machine");
            }

            let conn = self.conn.lock().unwrap();
            // see if (host, replica_path) is already tracked as some replica. if it is, we're
            // really just refreshing the last check of that replica. otherwise, add a new one.

            let replica_id: Option<u64> = conn.query_row(
                "select id from replicas where file_id=?1 and who=?2 and replica=?3;",
                params![file_id, host, replica_path],
                |row| { row.get(0) }
            ).optional().unwrap();

            let now_ts = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();

            match replica_id {
                Some(id) => {
                    // this is the "just update it" case
                    let rows_modified = conn.prepare(
                        "update replicas set last_check=?1, valid=1 where id=?2;"
                    ).expect("can prepare statement")
                        .execute(params![now_ts, id]).unwrap();
                    assert_eq!(rows_modified, 1);

                    Ok(())
                },
                None => {
                    // it seems like a totally new edition of the file, add a new replica

                    // we'll be simply trusting this replica to be added is currently valid...
                    let mut stmt = conn.prepare(
                        "insert into replicas (file_id, who, path, valid, last_check) values (?1, ?2, ?3, ?4, ?5);"
                    ).expect("can prepare statement");
                    let rows_modified = stmt
                        .execute(params![file_id, host, replica_path, 1, now_ts]).unwrap();
                    assert_eq!(rows_modified, 1);

                    Ok(())
                }
            }
        }

        pub fn find_by_hash(&self, hashes: &crate::file::MaybeHashes) -> Result<Option<u64>, ()> {
            let md5 = hashes.md5.as_ref().map(hex::encode);
            let sha1 = hashes.sha1.as_ref().map(hex::encode);
            let sha256 = hashes.sha256.as_ref().map(hex::encode);

            let mut params = Vec::new();

            let mut filtering = false;

            let mut query = "select id from files where".to_string();

            if let Some(md5) = md5 {
                if filtering {
                    query.push_str(" or");
                }
                filtering = true;

                query.push_str(&format!(" md5=?{}", params.len() + 1));
                params.push(md5);
            }

            if let Some(sha1) = sha1 {
                if filtering {
                    query.push_str(" or");
                }
                filtering = true;

                query.push_str(&format!(" sha1=?{}", params.len() + 1));
                params.push(sha1);
            }

            if let Some(sha256) = sha256 {
                if filtering {
                    query.push_str(" or");
                }
                filtering = true;

                query.push_str(&format!(" sha256=?{}", params.len() + 1));
                params.push(sha256);
            }

            let conn = self.conn.lock().unwrap();
            conn.query_row(query.as_str(), rusqlite::params_from_iter(params.into_iter()), |row| row.get(0))
                .map_err(|e| { println!("TODO: rusqlite error: {}", e); () })
        }

        pub fn add_file(&self, hashes: &crate::file::MaybeHashes) -> Result<FileAddResult, ()> {
            let md5 = hashes.md5.as_ref().map(hex::encode);
            let sha1 = hashes.sha1.as_ref().map(hex::encode);
            let sha256 = hashes.sha256.as_ref().map(hex::encode);

            let conn = self.conn.lock().unwrap();
            match conn.execute(
                "insert into files (sha256, sha1, md5) values (?1, ?2, ?3);",
                params![sha256.as_ref(), sha1.as_ref(), md5.as_ref()]
            ) {
                Ok(1) => {
                    Ok(FileAddResult::New(conn.last_insert_rowid() as u64))
                },
                Ok(other) => {
                    // TODO: pretty severe logical error here..
                    panic!("how did inserting one row succeed but instead insert {} rows?", other);
                }
                // UNIQUE constraint violated. so one of these hashes already exist.
                // TODO: try updating the matching hash's row to the other provided hashes?
                Err(rusqlite::Error::SqliteFailure(libsqlite3_sys::Error {
                    code: libsqlite3_sys::ErrorCode::ConstraintViolation,
                    extended_code: 2067
                }, _)) => {
                    // ok, so the hash already exists. look it up and return that id.
                    // note: `sha256 OR sha1 OR md5` - any of the hashes may be the one that was
                    // present and conflicted, the local addition may provide hashes that were not
                    // yet known. selecting on all hashes we were just told may be overly
                    // restrictive.
                    let res = conn.query_row(
                        "select id from files where sha256=?1 or sha1=?2 or md5=?3",
                        params![&sha256, sha1, md5],
                        |row| { row.get(0) }
                    ).unwrap();
                    Ok(FileAddResult::Exists(res))
                },
                Err(other) => {
                    panic!(
                        "unexpected error inserting hashes {{ sha256: {}, sha1: {}, md5: {} }}: {:?}",
                        sha256.as_ref().map(|x| x.as_str()).unwrap_or("<none>"),
                        sha1.as_ref().map(|x| x.as_str()).unwrap_or("<none>"),
                        md5.as_ref().map(|x| x.as_str()).unwrap_or("<none>"),
                        other
                    );
                }
            }
        }

        pub fn describe_file(&self, file_id: u64) -> Result<data::Description, String> {
            let conn = self.conn.lock().unwrap();
                // CREATE TABLE IF NOT EXISTS files (id INTEGER PRIMARY KEY, sha256 TEXT, sha1 TEXT, md5 TEXT, UNIQUE(sha256, sha1, md5));", params![]).unwrap();

            let mut selected_tags: Vec<u64> = Vec::new();

            let (sha256, sha1, md5): (Option<String>, Option<String>, Option<String>) = match conn.query_row(
                "select sha256, sha1, md5 from files where id=?1;",
                params![file_id],
                |row| {
                    Ok((
                        row.get(0).unwrap(),
                        row.get(1).unwrap(),
                        row.get(2).unwrap(),
                    ))
                }
            ) {
                Ok(result) => result,
                Err(rusqlite::Error::QueryReturnedNoRows) => {
                    return Err("no data".to_string());
                }
                Err(e) => {
                    panic!("unexpected query error: {:?}", e);
                }
            };

            let mut description = data::Description {
                file_id,
                sha256,
                sha1,
                md5,
                replicas: Vec::new(),
                tags: Vec::new(),
            };

                // CREATE TABLE IF NOT EXISTS file_tags (id INTEGER PRIMARY KEY, tag INTEGER, file_id INTEGER, source INTEGER, value TEXT);", params![]).unwrap();
                // CREATE TABLE IF NOT EXISTS replicas (id INTEGER PRIMARY KEY, file_id INTEGER, who TEXT, replica TEXT, valid TINYINT, last_check INTEGER);", params![]).unwrap();
            let replicas_start = std::time::Instant::now();
            let mut stmt = conn.prepare_cached("select who, collection_id, collections.name, collections.location, path, valid, last_check from replicas join collections on collections.id=replicas.collection_id where file_id=?1;")
                .map_err(|e| format!("unable to prepare query: {:?}", e))?;
            let mut rows = stmt.query_map(params![file_id], |row| {
                let who: Option<String> = row.get(0).unwrap();
                let collection_id: Option<u64> = row.get(1).unwrap();
                let collection_name: Option<String> = row.get(2).unwrap();
                let collection_base: Option<String> = row.get(3).unwrap();
                let path: Option<String> = row.get(4).unwrap();
                let valid: bool = row.get(5).unwrap();
                let last_check: u64 = row.get(6).unwrap();
                Ok((who, collection_id, collection_name, collection_base, path, valid, last_check))
            })
                .map_err(|e| format!("unable to execute query: {:?}", e))?;

            while let Some(Ok((who, collection_id, collection_name, collection_base, path, valid, last_check_ts))) = rows.next() {
                description.replicas.push(data::Replica {
                    who,
                    collection_id,
                    collection_name,
                    collection_base,
                    path,
                    valid,
                    last_check_ts,
                });
            }
//            eprintln!("replicas done in {}ms", replicas_start.elapsed().as_micros() as f64 / 1000.0);

            let tags_start = std::time::Instant::now();
            let mut stmt = conn.prepare("select tags.name, file_tags.value, tag_sources.name \
                from file_tags \
                    join tags on tags.id=file_tags.tag \
                    join tag_sources on file_tags.source=tag_sources.id \
                    where file_tags.file_id=?1 \
                    order by tags.id,file_tags.value;")
                .map_err(|e| format!("unable to prepare query: {:?}", e))?;
            let mut rows = stmt.query_map(params![file_id], |row| {
                let name: String = row.get(0).unwrap();
                let value: String = row.get(1).unwrap();
                let source: String = row.get(2).unwrap();
                Ok((name, value, source))
            })
                .map_err(|e| format!("unable to execute query: {:?}", e))?;

            while let Some(Ok((name, value, source))) = rows.next() {
                description.tags.push(data::Tag {
                    name,
                    value,
                    source,
                });
            }
//            eprintln!("tags done in {}ms", tags_start.elapsed().as_micros() as f64 / 1000.0);

            Ok(description)
        }
    }
}

pub mod file {
    use digest::Digest;
    use sha2::Sha256;
    use sha1::Sha1;
    use md5::Md5;

    pub struct Hashes {
        pub sha256: [u8; 32],
        pub sha1: [u8; 20],
        pub md5: [u8; 16],
    }

    impl Hashes {
        pub fn as_maybe_hashes(self) -> MaybeHashes {
            let Self {
                sha256,
                sha1,
                md5,
            } = self;

            MaybeHashes {
                sha256: Some(sha256),
                sha1: Some(sha1),
                md5: Some(md5),
            }
        }
    }

    pub struct MaybeHashes {
        pub sha256: Option<[u8; 32]>,
        pub sha1: Option<[u8; 20]>,
        pub md5: Option<[u8; 16]>,
    }

    impl MaybeHashes {
        pub fn new(
            sha256: Option<[u8; 32]>,
            sha1: Option<[u8; 20]>,
            md5: Option<[u8; 16]>,
        ) -> Result<Self, ()> {
            if sha256.is_none() && sha1.is_none() && md5.is_none() {
                Err(())
            } else {
                Ok(MaybeHashes {
                    sha256,
                    sha1,
                    md5,
                })
            }
        }
    }

    pub fn hashes(file: &mut std::fs::File) -> Result<Hashes, String> {
        use std::io::{Read, Seek};

        file.rewind().map_err(|e| format!("couldn't seek? {:?}", e))?;
        let mut buf = [0u8; 128 * 1024];
        let mut md5 = Md5::new();
        let mut sha1 = Sha1::new();
        let mut sha256 = Sha256::new();

        loop {
            let len = file.read(&mut buf).map_err(|e| format!("failed to read: {}", e))?;
            if len == 0 {
                let res = Hashes {
                    sha256: sha256.finalize().as_slice().try_into().unwrap(),
                    sha1: sha1.finalize().as_slice().try_into().unwrap(),
                    md5: md5.finalize().as_slice().try_into().unwrap(),
                };
                return Ok(res);
            }
            md5.update(&buf[0..len]);
            sha1.update(&buf[0..len]);
            sha256.update(&buf[0..len]);
        }
    }
}

pub struct Hof {
    pub db: db::DbCtx,
    pub cfg: Config,
}

pub struct Config {
    pub config_root: PathBuf,
    pub identity: ring::signature::Ed25519KeyPair,
    pub default_replica: Option<String>,
}

#[derive(Deserialize, Serialize)]
struct PeerConfig {
    name: String,
    address: String,
    pubkey: String,
}

impl Config {
    pub fn lookup_remote_addr(&self, name: &str) -> Result<Option<String>, String> {
        let peer_configs = match std::fs::read_dir(self.config_root.join("peers")) {
            Ok(iter) => iter,
            Err(e) => { return Err(format!("TODO: ??? {:?}", e)); }
        };

        for f in peer_configs {
            let path = f.expect("TODO: works").path();
            if path.file_name().expect("TODO: exists").to_str().expect("TODO: works").ends_with(".json") {
                let s = std::fs::read_to_string(path)
                    .expect("TODO: works");
                let peer_config: PeerConfig = serde_json::from_str(&s)
                    .expect("TODO: works");

                if peer_config.name == name {
                    return Ok(Some(peer_config.address.clone()));
                }
            }
        }

        Ok(None)
    }

    fn new<P: AsRef<Path>>(config_path: P) -> Result<Self, String> {
        let config_path = config_path.as_ref();
        if let Ok(md) = std::fs::metadata(&config_path) {
            if md.is_dir() {
                // config directory exists. might have contents?
            } else {
                return Err(format!("config path is not a directory: {}", config_path.display()));
            }
        } else {
            // config directory doesn't exist.
            eprintln!("[+] initial setup: creating config dir at {}", config_path.display());
            match std::fs::create_dir_all(config_path) {
                Ok(()) => {},
                Err(e) => {
                    return Err(format!("config dir could not be created: {:?}", e));
                }
            }
            match std::fs::create_dir_all(config_path.join("peers")) {
                Ok(()) => {},
                Err(e) => {
                    return Err(format!("peers dir could not be created: {:?}", e));
                }
            }
        }

        let identity_file = config_path.join("identity.pem");
        let identity_pubkey = config_path.join("identity.pub");
        let keypair: ring::signature::Ed25519KeyPair = match std::fs::metadata(&identity_file) {
            Ok(md) => {
                if md.is_file() {
                    // great, identity file exists and is a file
                    let pkcs8_pem = String::from_utf8(std::fs::read(&identity_file)
                        .expect("read is quick")).expect("ok");

                    let (label, decoded) = pkcs8::Document::from_pem(&pkcs8_pem)
                        .expect("works");

                    let keypair = ring::signature::Ed25519KeyPair::from_pkcs8(decoded.as_bytes())
                        .expect("keypair to be valid");

                    keypair
                } else {
                    return Err(format!("identity file ({}) is not a file", identity_file.display()));
                }
            },
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                // identity file doesn't exist, lets make it.
                eprintln!("[+] initial startup: creating identity file");
                let mut rng = ring::rand::SystemRandom::new();
                let document = ring::signature::Ed25519KeyPair::generate_pkcs8(&rng)
                    .expect("can generate identity file");
                let doc_bytes: &[u8] = document.as_ref();
                let pem = pkcs8::Document::try_from(doc_bytes)
                    .expect("works")
                    .to_pem("HOF IDENTITY", pkcs8::LineEnding::LF)
                    .expect("also works");
                let keypair = ring::signature::Ed25519KeyPair::from_pkcs8(doc_bytes)
                    .expect("new keypair is valid");
                use ring::signature::KeyPair;
                let public_key: &[u8] = keypair.public_key().as_ref();
                use base64::prelude::*;
                let pub_doc = BASE64_STANDARD.encode(public_key);
                std::fs::write(identity_file, pem.as_bytes());
                std::fs::write(identity_pubkey, pub_doc.as_bytes());
                eprintln!("[+] identity generated");
                keypair
            }
            Err(e) => {
                return Err(format!("unable to open identity file: {:?}", e));
            }
        };

        Ok(Config {
            config_root: config_path.to_path_buf(),
            identity: keypair,
            // TODO: actually load this from somewhere
            default_replica: None,
        })
    }

    pub fn pubkey_base64(&self) -> String {
        use ring::signature::KeyPair;
        let public_key: &[u8] = self.identity.public_key().as_ref();
        use base64::prelude::*;
        BASE64_STANDARD.encode(public_key)
    }

    pub fn add_remote(&self, name: &str, address: &str, pubkey: &str) -> Result<(), String> {
        if name.contains(',') {
            return Err("TODO: dont want to deal with you rn".to_string());
        }

        let obj = PeerConfig {
            name: name.to_owned(),
            address: address.to_owned(),
            pubkey: pubkey.to_owned(),
        };

        let peer_filename = format!("{},{}.json", name, address);

        std::fs::write(self.config_root.join("peers").join(peer_filename), serde_json::to_string(&obj).expect("works").as_bytes())
            .expect("TODO: can write peer config");

        Ok(())
    }
}

use db::FileAddResult;

impl Hof {
    pub fn new<P: AsRef<Path>>(db_path: P, config_path: P) -> Self {
        let mut db = db::DbCtx::new(db_path);
        let mut cfg = Config::new(config_path)
            .expect("can get initial configs together");
        // TODO: don't just always initialize...
        db.create_tables().expect("can create tables");
        Self {
            db,
            cfg,
        }
    }

    pub fn add_file<P: AsRef<Path>>(&self, path: P) -> Result<u64, String> {
        let path: &Path = path.as_ref();
        let mut file = File::open(path).map_err(|e| format!("{}", e))?;

        let hashes = file::hashes(&mut file)?;
        // TODO: do not actually create a new file when hashes indicates we already know the file;
        // in that cae we should only add a new local replica...
        let file_id = match self.db.add_file(&hashes.as_maybe_hashes()).map_err(|e| format!("err adding new file hash: {:?}", e))? {
            FileAddResult::New(file_id) => {
                file_id
            }
            FileAddResult::Exists(file_id) => {
                file_id
            }
        };

        let canonical = std::fs::canonicalize(path)
            .map_err(|e| format!("cannot canonicalize {}: {:?}", path.display(), e))?;

        let hostname: String = gethostname::gethostname()
            .into_string()
            .expect("hostname is a valid utf8 string ????? look i know this isn't guaranteed but come on");
        self.db.add_replica(file_id, Some(hostname.as_str()), Some(&format!("{}", canonical.display()))).expect("can add replica");
        Ok(file_id)
    }

    pub fn add_remote_file(&self, hashes: crate::file::MaybeHashes, remote: Option<String>, path: Option<String>) -> Result<(), String> {
        // TODO: do not actually create a new file when hashes indicates we already know the file;
        // in that case we should only add a new replica..
        let file_id = match self.db.add_file(&hashes).map_err(|e| format!("err adding new file hash: {:?}", e))? {
            FileAddResult::New(file_id) => {
                file_id
            }
            FileAddResult::Exists(file_id) => {
                file_id
            }
        };

        if remote.is_some() || path.is_some() {
            self.db.add_replica(
                file_id,
                remote.as_ref().map(|x| x.as_str()),
                path.as_ref().map(|x| x.as_str())
            ).expect("can add replica");
        }

        Ok(())
    }

    pub fn hash_lookup(&self, sha256: &str) -> Result<Option<u64>, String> {
        let sha256 = sha256.to_owned().to_lowercase();
        self.db.find_file(&sha256)
    }

    pub fn replica_lookup(&self, replica: &str, path: &str) -> Result<Option<u64>, String> {
        let canonical = std::fs::canonicalize(path)
            .map_err(|e| format!("cannot canonicalize {}: {:?}", path, e))?;
        let canonical = format!("{}", canonical.display());
        self.db.replica_lookup(replica, &canonical)
    }

    pub async fn open_replica(&self, replica: &crate::db::data::Replica) -> Result<tokio::fs::File, &'static str> {
        eprintln!("testing replica {:?}", replica);
        let hostname = gethostname::gethostname()
            .into_string()
            .expect("can turn hostname into string");

        if replica.who != Some(hostname) {
            return Err("not this hostname");
        }

        if let (Some(collection_base), Some(path)) = (replica.collection_base.as_ref(), replica.path.as_ref()) {
            let path = format!("{}/{}", collection_base, path);
            if path.contains("/../") {
                eprintln!("replica {:?} yields potentially directory traversal path?", replica);
                return Err("however that happened, no");
            }
            match tokio::fs::File::open(&path).await {
                Ok(file) => { return Ok(file); },
                Err(e) => {
                    eprintln!("opening {} yielded {:?}", path, e);
                    return Err("tokio error opening file");
                }
            }
        } else {
            return Err("this hostname, but collection has no base, or no path?");
        }
    }

    pub fn add_tag(&self, sha256: &str, source: u64, key: &str, value: &str) -> Result<(), String> {
        let file_id = self.db.find_file(sha256).and_then(|r| {
            r.ok_or_else(|| format!("hash {} is not known", sha256))
        })?;

        self.add_file_tag(file_id, source, key, value)
    }

    pub fn add_file_tag(&self, file_id: u64, source: u64, key: &str, value: &str) -> Result<(), String> {
        let tag_id = self.db.create_tag(key).map_err(|e| format!("failed to create tag {}: {}", key, e))?;

        self.db.add_tag(file_id, source, tag_id, value)?;

        Ok(())
    }
}

use std::time::{SystemTime, UNIX_EPOCH};
fn now_ms() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).expect("now is later than epoch").as_millis() as u64
}

use std::collections::HashSet;
use std::fs::File;
use std::path::Path;

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
    // who has it?
    who: String,
    // and where do they think it is?
    path: ReplicaPath,
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

mod db {
    use rusqlite::{params, Connection, OptionalExtension};
    use std::path::Path;
    use std::sync::Mutex;

    mod data {
        pub struct Replica {
            pub who: String,
            pub replica: String,
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
            conn.execute("\
                CREATE TABLE IF NOT EXISTS tag_source (id INTEGER PRIMARY KEY, name TEXT);", params![]).unwrap();
            // a record of which tag sources have processed a file (and when)
            conn.execute("\
                CREATE TABLE IF NOT EXISTS tag_log (id INTEGER PRIMARY KEY, file_id INTEGER, source INTEGER, state INTEGER, version INTEGER, tag_time INTEGER);", params![]).unwrap();
            conn.execute("\
                CREATE TABLE IF NOT EXISTS file_tags (id INTEGER PRIMARY KEY, tag INTEGER, file_id INTEGER, source INTEGER, value TEXT);", params![]).unwrap();
            conn.execute("\
                CREATE TABLE IF NOT EXISTS replicas (id INTEGER PRIMARY KEY, file_id INTEGER, who TEXT, replica TEXT, valid TINYINT, last_check INTEGER);", params![]).unwrap();
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
                CREATE TABLE IF NOT EXISTS replica_host (id INTEGER PRIMARY KEY, name TEXT, style TEXT, description TEXT, location TEXT);", params![]).unwrap();

            conn.execute("\
                CREATE TABLE IF NOT EXISTS acls (id INTEGER PRIMARY KEY, rule TEXT);", params![]).unwrap();
            conn.execute("\
                CREATE TABLE IF NOT EXISTS file_acls (id INTEGER PRIMARY KEY, file_id INTEGER, rule INTEGER);", params![]).unwrap();
            Ok(())
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
            let query = format!("select file_id from file_tags where {} group by file_id having count(*)={}", filter, tags.len());
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

        pub fn replica_lookup(&self, replica: &str, path: &str) -> Result<Option<u64>, String> {
            let conn = self.conn.lock().unwrap();
            Ok(conn.query_row(
                "select file_id from replicas where who=?1 and replica=?2 and valid=1",
                params![replica, path],
                |row| { row.get(0) }
            ).optional().unwrap())
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

        pub fn add_tag(&self, file_id: u64, tag_id: u64, value: &str) -> Result<(), String> {
            let conn = self.conn.lock().unwrap();
            // we'll be simply trusting this replica to be added is currently valid...
            // TODO: reject duplicate tags from the same source?
            let _rows_modified = conn.execute(
                "insert into file_tags (file_id, tag, source, value) values (?1, ?2, ?3, ?4);",
                params![file_id, tag_id, 1, value]
            ).unwrap();

            Ok(())
        }

        pub fn add_replica(&self, file_id: u64, host: &str, replica_path: Option<&str>) -> Result<(), ()> {
            use std::time::{SystemTime, UNIX_EPOCH};

            let conn = self.conn.lock().unwrap();
            // we'll be simply trusting this replica to be added is currently valid...
            let mut stmt = conn.prepare(
                "insert into replicas (file_id, who, replica, valid, last_check) values (?1, ?2, ?3, ?4, ?5);"
            ).expect("can prepare statement");
            let rows_modified = stmt
                .execute(params![file_id, host, replica_path, 1, SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs()]).unwrap();
            assert_eq!(rows_modified, 1);

            Ok(())
        }

        pub fn add_file(&self, hashes: &crate::file::MaybeHashes) -> Result<FileAddResult, ()> {
            let md5 = hashes.md5.as_ref().map(hex::encode);
            let sha1 = hashes.sha1.as_ref().map(hex::encode);
            let sha256 = hashes.sha256.as_ref().map(hex::encode);

            let conn = self.conn.lock().unwrap();
            let rows_modified = conn.execute(
                "insert into files (sha256, sha1, md5) values (?1, ?2, ?3);",
                params![sha256, sha1, md5]
            ).unwrap();

            if rows_modified == 1 {
                Ok(FileAddResult::New(conn.last_insert_rowid() as u64))
            } else {
                let res = conn.query_row(
                    "select id from files where sha256=?1 and sha1=?2 and md5=?3",
                    params![&sha256, sha1, md5],
                    |row| { row.get(0) }
                ).unwrap();
                Ok(FileAddResult::Exists(res))
            }
        }

        pub fn describe_file(&self, file_id: u64) -> Result<data::Description, String> {
            let conn = self.conn.lock().unwrap();
                // CREATE TABLE IF NOT EXISTS files (id INTEGER PRIMARY KEY, sha256 TEXT, sha1 TEXT, md5 TEXT, UNIQUE(sha256, sha1, md5));", params![]).unwrap();

            let mut selected_tags: Vec<u64> = Vec::new();

            let (sha256, sha1, md5): (Option<String>, Option<String>, Option<String>) = conn.query_row(
                "select sha256, sha1, md5 from files where id=?1;",
                params![file_id],
                |row| {
                    Ok((
                        row.get(0).unwrap(),
                        row.get(1).unwrap(),
                        row.get(2).unwrap(),
                    ))
                }
            ).expect("TODO: can query");

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
            let mut stmt = conn.prepare("select who, replica, valid, last_check from replicas where file_id=?1;")
                .map_err(|e| format!("unable to prepare query: {:?}", e))?;
            let mut rows = stmt.query_map(params![file_id], |row| {
                let who: String = row.get(0).unwrap();
                let replica: String = row.get(1).unwrap();
                let valid: bool = row.get(2).unwrap();
                let last_check: u64 = row.get(3).unwrap();
                Ok((who, replica, valid, last_check))
            })
                .map_err(|e| format!("unable to execute query: {:?}", e))?;

            while let Some(Ok((who, replica, valid, last_check_ts))) = rows.next() {
                description.replicas.push(data::Replica {
                    who,
                    replica,
                    valid,
                    last_check_ts,
                });
            }

            let mut stmt = conn.prepare("select tags.name, file_tags.value, tag_source.name \
                from file_tags \
                    join tags on tags.id=file_tags.tag \
                    join tag_source on file_tags.source=tag_source.id \
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
}

use db::FileAddResult;

impl Hof {
    pub fn new<P: AsRef<Path>>(db_path: P) -> Self {
        let mut db = db::DbCtx::new(db_path);
        // TODO: don't just always initialize...
        db.create_tables().expect("can create tables");
        Self {
            db,
        }
    }

    pub fn add_file<P: AsRef<Path>>(&self, path: P) -> Result<(), String> {
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

        self.db.add_replica(file_id, "localhost", Some(&format!("{}", canonical.display()))).expect("can add replica");
        Ok(())
    }

    pub fn add_remote_file(&self, hashes: crate::file::MaybeHashes, remote: String, path: Option<String>) -> Result<(), String> {
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

        self.db.add_replica(file_id, &remote, path.as_ref().map(|x| x.as_str())).expect("can add replica");
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

    pub fn add_tag(&self, sha256: &str, key: &str, value: &str) -> Result<(), String> {
        let file_id = self.db.find_file(sha256).and_then(|r| {
            r.ok_or_else(|| format!("hash {} is not known", sha256))
        })?;

        self.add_file_tag(file_id, key, value)
    }

    pub fn add_file_tag(&self, file_id: u64, key: &str, value: &str) -> Result<(), String> {
        let tag_id = self.db.create_tag(key).map_err(|e| format!("failed to create tag {}: {}", key, e))?;

        self.db.add_tag(file_id, tag_id, value)?;

        Ok(())
    }
}

use chrono::{Utc, TimeZone};
use serde::{Deserialize, Serialize};
use serde_json::json;

use std::collections::{HashMap, HashSet, hash_map::Entry};
use std::fmt::Write;
use std::sync::Arc;
use std::path::PathBuf;

use axum::async_trait;
use axum::Router;
use axum::routing::{get, post};
use axum::response::{Html, IntoResponse};
use axum::extract::{FromRequestParts, Path, State, RawQuery};
use axum::body::Body;
use axum::body::HttpBody;
use axum::{Error, Json};
use axum::extract::rejection::JsonRejection;
use axum::body::Bytes;
use axum::http::{StatusCode, Uri};
use http::header::HeaderMap;
use http::request::Parts;

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWriteExt};

use tracing::error;

use hofvarpnir::{Hof, file::MaybeHashes};

#[derive(Serialize, Deserialize)]
struct WebserverConfig {
    debug_addr: Option<serde_json::Value>,
    db_path: PathBuf,
    config_path: PathBuf,
    incoming_dir: PathBuf,
}

struct Auth {
    can_read: bool,
    can_write: bool,
    visibility: bool,
}

impl Auth {
    fn all() -> Self {
        Auth {
            can_read: true,
            can_write: true,
            visibility: true,
        }
    }

    fn default() -> Self {
        Auth {
            can_read: true,
            can_write: false,
            visibility: false,
        }
    }
}

#[async_trait]
impl FromRequestParts<WebserverState> for Auth {
    type Rejection = (StatusCode, &'static str);

    async fn from_request_parts(parts: &mut Parts, state: &WebserverState) -> Result<Self, Self::Rejection> {
        match get_one_header(&parts.headers, "auth") {
            Some(value) => {
                if value == "trustme" {
                    Ok(Auth::all())
                } else {
                    Err((StatusCode::BAD_REQUEST, "bad auth"))
                }
            }
            None => {
                Ok(Auth::default())
            }
        }
    }
}

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt::init();

    let mut args = std::env::args();
    args.next().expect("first arg exists");

    let config_path = args.next().unwrap_or("./webserver_config.json".to_string());
    let web_config: WebserverConfig = serde_json::from_reader(
        std::fs::File::open(config_path).expect("file exists and is accessible")
    ).expect("valid json for WebserverConfig");
    let db_path = web_config.db_path.clone();
    let config_path = web_config.config_path.clone();
    let incoming_dir = web_config.incoming_dir.clone();

    if let Some(addr_conf) = web_config.debug_addr.as_ref() {
        tokio::spawn(bind_server(addr_conf.clone(), db_path.clone(), config_path.clone(), incoming_dir.clone()));
    }

    loop {
        tokio::time::sleep(std::time::Duration::from_millis(1000)).await;
    }
}

async fn fallback_get(uri: Uri) -> impl IntoResponse {
    (StatusCode::NOT_FOUND, Html("<html><head><title>not found</title></head><body><p>not found</p></body></html>".to_string()))
}

async fn handle_help(State(ctx): State<WebserverState>) -> impl IntoResponse {
    let mut resp = String::new();
    resp.push_str("<html>\n");
    resp.push_str("  <body>\n");
    resp.push_str("  <pre>
/help                 this help
/                     tag list and hof index
/file/:id             describe file :id
/file/:id/download    download file :id
/file/upload          POST. provide a file to be tracked by this hof. optionally provide any of its hashes as headers (file-{md5,sha1,sha256}) to allow the remote end to quickly reply if it knows the file already
/file/report          POST. tell the remote end about a file by hashes, without providing contents
/tags/search          search by tags (query string is a list of tag=value, tag=1&tag=2 means `tag in [1, 2]` and tag=&tag2= means `has tag 1 and tag 2`
/tags/report          POST. tell the remote end about a file tag (file_id=XXX, tag=YYY, optional value=ZZZ)
</pre>");
    resp.push_str("  </body>\n");
    resp.push_str("</html>\n");
    (StatusCode::OK, Html(resp))
}

struct FilePaths {
    target: Option<PathBuf>,
    target_base: PathBuf,
    interim: PathBuf,
}

async fn handle_uploaded_file(auth: Auth, headers: HeaderMap, State(ctx): State<WebserverState>, body: axum::body::Body) -> impl IntoResponse {
    if !auth.can_write {
        return (StatusCode::FORBIDDEN, Html("no")).into_response();
    }

    let maybe_md5 = match get_one_header(&headers, "file-md5")
        .map(|h| hex::decode(h).map(|v| TryInto::<[u8; 16]>::try_into(v))) {
        Some(Ok(Ok(bytes))) => Some(bytes),
        None => None,
        _ => {
            return (StatusCode::BAD_REQUEST, Html("file-md5 invalid")).into_response();
        }
    };

    let maybe_sha1 = match get_one_header(&headers, "file-sha1")
        .map(|h| hex::decode(h).map(|v| TryInto::<[u8; 20]>::try_into(v))) {
        Some(Ok(Ok(bytes))) => Some(bytes),
        None => None,
        _ => {
            return (StatusCode::BAD_REQUEST, Html("file-sha1 invalid")).into_response();
        }
    };

    let maybe_sha256 = match get_one_header(&headers, "file-sha256")
        .map(|h| hex::decode(h).map(|v| TryInto::<[u8; 32]>::try_into(v))) {
        Some(Ok(Ok(bytes))) => Some(bytes),
        None => None,
        _ => {
            return (StatusCode::BAD_REQUEST, Html("file-sha256 invalid")).into_response();
        }
    };

    let content_length: Option<u64> = match get_one_header(&headers, "content-length").map(|cl| cl.parse()) {
        Some(Ok(cl)) => {
            if cl > 1024 * 1024 * 1024 {
                return (StatusCode::BAD_REQUEST, Html("content too large")).into_response();
            }

            Some(cl)
        }
        Some(Err(e)) => {
            return (StatusCode::BAD_REQUEST, Html(format!("invalid content-length: {}", e))).into_response();
        },
        None => {
            None
        }
    };

    let maybe_hashes = if let Ok(maybe_hashes) = MaybeHashes::new(maybe_sha256, maybe_sha1, maybe_md5) {
        let hashes_id = ctx.dbctx.db.find_by_hash(&maybe_hashes);
        eprintln!("lookup result: {:?}", hashes_id);
        if let Ok(Some(id)) = hashes_id {
            let resp = json!({
                "id": id
            });
            let resp = serde_json::to_string(&resp)
                .expect("can stringify");

            let headers = [
                (http::header::CONTENT_TYPE, "application/json"),
            ];
            return (StatusCode::FOUND, headers, Body::new(resp)).into_response();
        }
        Some(maybe_hashes)
    } else {
        eprintln!("no hashes provided");
        None
    };

    let file_paths = match get_one_header(&headers, "file-path") {
        Some(desired_path) => {
            // TODO: overly-broad hammer to disallow file-path doing arbitrary file writes.
            // should this be a chroot? should this be an unshare with appropriate bind mounts?
            // yes! but at the moment i am lazy AND i am the only user. so as long as i trust me to
            // not pwn myself...
            if desired_path.contains("../") || desired_path.contains("..\\") || desired_path.contains("/..") || desired_path.contains("\\..") || desired_path == ".." {
                return (StatusCode::BAD_REQUEST, Html("file-path invalid")).into_response();
            }

            // ok: and from here the strategy is to check if the destination file already exists -
            // doesn't really matter if it's the same or not, it's a conflict and we'll error.
            //
            // still: accept bytes into a temporary file and move it into place atomically once
            // the upload is complete. this avoids interrupted uploads leaving broken files on our
            // end.
            //
            // register in-progress uploads so we can clean up if we accumulate junk through
            // interrupted uploads.
            //
            // in-progress file will be named `<desired_path>.hofpart`. conflict on the in-progress
            // file name is also an error.
            //
            // create both files atomically to error early if either is a conflict. error
            // resolution is a little subtle, described later.

            let mut target_path = ctx.incoming_dir.clone();
            target_path.push(desired_path);
            eprintln!("want to save to {}", target_path.display());

            let mut interim_path = target_path.clone();
            let last_part = interim_path.pop();
            let interim_path = interim_path.join(&format!("{}.hofpart", last_part));

            FilePaths {
                target: Some(target_path),
                target_base: ctx.incoming_dir.clone(),
                interim: interim_path,
            }
        }
        None => {
            // similar to the above, except here we don't know the destination path until the file
            // is fully received.
            //
            // since the client didn't indicate a desired path, we'll just invent one from the
            // contents' hash.
            //
            // don't assume the `file-{md5,sha1,sha256}` are correct, if provided. they are only
            // used as a cross-check once the upload is complete, to validate that the content we
            // got is what the other end expected to give us.
            //
            // since we don't know a desired path yet, we can't pick a good interim storage
            // location. so use a totally random path instead, hope it all works out.
            let interim_path = "test.hofpart".into();
            FilePaths {
                target: None,
                target_base: ctx.incoming_dir.clone(),
                interim: interim_path,
            }
        }
    };

    match save_file(body, &file_paths, maybe_hashes).await {
        Ok(final_path) => {
            // ok! we've saved the file. now we can insert it into the db...
            let id = ctx.dbctx.add_file(final_path)
                .expect("can add file");
//            eprintln!("pretend i just added {} to the db", final_path.display());
            (StatusCode::OK, Html(id.to_string())).into_response()
        },
        Err(SaveError::Conflict) => {
            StatusCode::CONFLICT.into_response()
        }
        Err(e) => {
            eprintln!("failed to receive file: {:?}", e);
            // TODO: distinguish if it's on us or the client...
            StatusCode::BAD_REQUEST.into_response()
        }
    }
}

#[derive(Debug)]
enum SaveError {
    Conflict,
    Other(String),
}

async fn save_file(body: axum::body::Body, paths: &FilePaths, maybe_hashes: Option<MaybeHashes>) -> Result<PathBuf, SaveError> {
    eprintln!("[.] interim file path: {:?}", paths.interim.display());
    let mut interim_file = match tokio::fs::File::options().read(true).write(true).create_new(true).open(&paths.interim).await {
        Ok(f) => f,
        Err(e) => {
            // TODO: was the error because the file exists, or something else?
            eprintln!("[!] error opening {}: {:?}", paths.interim.display(), e);
            return Err(SaveError::Conflict);
        }
    };
    // return StatusCode::CONFLICT.into_response();

    use futures::StreamExt;

    let mut input_stream = body.into_data_stream();

    let mut buf = [0u8; 65536];

    loop {
        match input_stream.next().await {
            Some(Ok(b)) => {
                match interim_file.write_all(&b).await {
                    Ok(()) => {
                    }
                    Err(e) => {
                        eprintln!("error writing to file: {:?}", e);
                        return Err(SaveError::Other(format!("write: {:?}", e)));
                    }
                }

                if input_stream.is_end_stream() {
                    // done reading, no error so the client fully delivered its body?
                    break;
                }
            }
            Some(Err(e)) => {
                eprintln!("error reading from file: {:?}", e);
                return Err(SaveError::Other(format!("read: {:?}", e)));
            }
            None => {
                if !input_stream.is_end_stream() {
                    eprintln!("TODO: think this is impossible: input stream next() yielded None, but stream is not done");
                    break;
                }
            }
        }
    }

    // ok, we've stored the whole file. hash it, make sure those hashes match what we expected to
    // get (if anything)
    let hashes = hofvarpnir::file::hashes(&mut interim_file.into_std().await)
        .expect("can hash what we just wrote");

    if let Some(maybe_hashes) = maybe_hashes {
        if let Some(sha256) = maybe_hashes.sha256.as_ref() {
            if sha256 != &hashes.sha256 {
                return Err(SaveError::Other(format!("sha256s dont match")));
            }
        }
        if let Some(sha1) = maybe_hashes.sha1.as_ref() {
            if sha1 != &hashes.sha1 {
                return Err(SaveError::Other(format!("sha1s dont match")));
            }
        }
        if let Some(md5) = maybe_hashes.md5.as_ref() {
            if md5 != &hashes.md5 {
                return Err(SaveError::Other(format!("md5s dont match")));
            }
        }
    }

    // at this point if there were hashes, they match what we got. if we didn't know a path to put
    // this before, we can compute one: the sha256 of the file.
    let dest_path: PathBuf = match paths.target.as_ref() {
        Some(target) => target.clone(),
        None => {
            // TODO: at last split this by the first byte, or two bytes, so they all don't go in
            // the same directory...
            paths.target_base.join(hex::encode(hashes.sha256))
        }
    };

    eprintln!("dest file: {:?}", dest_path.display());

    // atomically move the interim file in place

    let mut standin_final_file = match tokio::fs::File::options().read(true).write(true).create_new(true).open(&dest_path).await {
        Ok(f) => f,
        Err(e) => {
            eprintln!("conflict on final file, apparently we already have this? {:?}", e);
            // conflict on the final file, but we don't already have it and we didn't conflict on
            // an interim file? this might have been a race with another upload of the same
            // file...???
            return Err(SaveError::Conflict);
        }
    };

    match std::fs::rename(&paths.interim, &dest_path) {
        Ok(()) => {
            // all done! yay!
        }
        Err(e) => {
            eprintln!("could not move interim file into place...? {:?}", e);
            return Err(SaveError::Conflict);
        }
    }

    Ok(dest_path)
}

async fn handle_tag_file(Path(path): Path<String>, headers: HeaderMap, State(ctx): State<WebserverState>) -> impl IntoResponse {
    let file_id = if let Ok(id) = path.parse() {
        id
    } else {
        return (StatusCode::BAD_REQUEST, Html("Invalid ID".to_string())).into_response();
    };

    let desc = if let Ok(description) = ctx.dbctx.db.describe_file(file_id) {
        description
    } else {
        return (StatusCode::NOT_FOUND, Html("Not Found".to_string())).into_response();
    };

    let tag = match get_one_header(&headers, "tag") {
        Some(tag) => tag,
        _ => {
            return (StatusCode::BAD_REQUEST, Html("you have to provide a tag")).into_response();
        }
    };

    let value = match get_one_header(&headers, "tag-value") {
        Some(value) => value,
        _ => {
            return (StatusCode::BAD_REQUEST, Html("you have to provide a tag value (???)")).into_response();
        }
    };

    ctx.dbctx.add_file_tag(file_id, 2, tag, value).expect("TODO: works");

    StatusCode::OK.into_response()
}

async fn handle_download_file(Path(path): Path<String>, State(ctx): State<WebserverState>) -> impl IntoResponse {
    let file_id = if let Ok(id) = path.parse() {
        id
    } else {
        return (StatusCode::BAD_REQUEST, Html("Invalid ID".to_string())).into_response();
    };

    let desc = if let Ok(description) = ctx.dbctx.db.describe_file(file_id) {
        description
    } else {
        return (StatusCode::NOT_FOUND, Html("Not Found".to_string())).into_response();
    };

    let hostname = gethostname::gethostname()
        .into_string()
        .expect("hostname is a valid utf8 string");

    for replica in desc.replicas.iter() {
        if let Ok(file) = ctx.dbctx.open_replica(replica).await {
            let stream = tokio_util::io::ReaderStream::new(file);
            let headers = [
                (http::header::CONTENT_TYPE, "application/octet-stream"),
            ];
            return (headers, axum::body::Body::from_stream(stream)).into_response();
        }
    }

    (StatusCode::NOT_FOUND, Html("No replica is local and valid")).into_response()
}

async fn handle_describe_file(Path(path): Path<String>, State(ctx): State<WebserverState>) -> impl IntoResponse {
    let mut html = String::new();

    let file_id = if let Ok(id) = path.parse() {
        id
    } else {
        return (StatusCode::BAD_REQUEST, Html("Invalid ID".to_string()));
    };

    let desc = if let Ok(description) = ctx.dbctx.db.describe_file(file_id) {
        description
    } else {
        return (StatusCode::NOT_FOUND, Html("Not Found".to_string()));
    };

    html.push_str("<html>\n");
    html.push_str("  <body>\n");
    html.push_str("    <pre>");
    writeln!(html, "file {}", desc.file_id);
    writeln!(html, "  sha256: {}", desc.sha256.as_ref().map(|x| x.as_str()).unwrap_or("<null>"));
    writeln!(html, "  sha1:   {}", desc.sha1.as_ref().map(|x| x.as_str()).unwrap_or("<null>"));
    writeln!(html, "  md5:    {}", desc.md5.as_ref().map(|x| x.as_str()).unwrap_or("<null>"));
    writeln!(html, "replicas:");
    for replica in desc.replicas.iter() {
        if let (Some(who), Some(path)) = (replica.who.as_ref(), replica.replica.as_ref()) {
            write!(html, "  {}: {}, checked {}", who, path, replica.last_check_ts);
            if replica.valid {
                write!(html, " (valid)");
            }
        } else {
            write!(html, "  &lt;unknown&gt;");
        }
        writeln!(html, "");
    }
    html.push_str("    </pre>\n");

    html.push_str("    <h4>tags</h4>\n");
    html.push_str("    <table>\n");
    html.push_str("      <thead><tr><th>tag</th><td>value</td><td>source</td></tr></thead>\n");
    for tag in desc.tags.iter() {
        writeln!(html, "<tr><th>{}<th><td>{}</td><td>{}</td>", tag.name, tag.value, tag.source);
    }
    html.push_str("    </table>\n");
    html.push_str("  </body>\n");
    html.push_str("</html>\n");

    (StatusCode::OK, Html(html))
}

async fn handle_search_tags(State(ctx): State<WebserverState>, RawQuery(q): RawQuery) -> impl IntoResponse {
    // TODO: extremely simple query logic:
    // * accept multiple tags, multiple values for each tag
    // * results are all files with at least the listed tags, where for each tag the file has least
    // one value matching a searched-for value
    let q = if let Some(q) = q {
        q
    } else {
        return (StatusCode::BAD_REQUEST, Html("<html><body>bad request, no biscuits</body></html>".to_string()));
    };
    let pairs = q.split("&");

    struct Search {
        details: HashMap<String, hofvarpnir::TagFilter>,
        hof: Arc<Hof>,
    }

    impl Search {
        fn filter_for_tag_mut(&mut self, tag: &str) -> Result<&mut hofvarpnir::TagFilter, (StatusCode, Html<String>)> {
            match self.details.entry(tag.to_owned()) {
                Entry::Occupied(mut oe) => {
                    Ok(oe.into_mut())
                }
                Entry::Vacant(mut ve) => {
                    let id = match self.hof.db.tag_to_id(tag) {
                        Ok(Some(id)) => id,
                        Ok(None) => {
                            // TODO: don't just do a reflected xss here lol
                            return Err((StatusCode::BAD_REQUEST, Html("<html><body>tag doesn't exist</body></html>".to_string())));
                        }
                        Err(e) => {
                            return Err((StatusCode::BAD_REQUEST, Html("<html><body>bad request, no biscuits</body></html>".to_string())));
                        }
                    };
                    Ok(ve.insert(
                        hofvarpnir::TagFilter {
                            key: hofvarpnir::TagId(id),
                            values: Some(HashSet::new()),
                        }
                    ))
                }
            }
        }
    }

    let mut search = Search {
        details: HashMap::new(),
        hof: Arc::clone(&ctx.dbctx),
    };

    for p in pairs {
        if let Some((k, v)) = p.split_once("=") {
            let mut filter = match search.filter_for_tag_mut(k) {
                Ok(filter) => filter,
                Err(res) => { return res; }
            };
            if let Some(values) = filter.values.as_mut() {
                values.insert(v.to_owned());
            } else {
                // already know the filter accepts all tag values
                break;
            }
        } else {
            let mut filter = match search.filter_for_tag_mut(p) {
                Ok(filter) => filter,
                Err(res) => { return res; }
            };
            filter.values = None;
        }
    }

    let tag_list: Vec<hofvarpnir::TagFilter> = search.details.into_values().collect();

    eprintln!("search: {:?}", tag_list);
    use std::time::Instant;
    let start = Instant::now();
    let results = match ctx.dbctx.db.select_by_tags(&tag_list) {
        Ok(results) => results,
        Err(e) => {
            error!("select by tags error: {}", e);
            return (StatusCode::BAD_REQUEST, Html("<html><body>bad request, no biscuits</body></html>".to_string()))
        }
    };
    eprintln!(" done in {}ms", start.elapsed().as_millis());

//    println!("results: {:?}", results);

    let mut html = String::new();
    html.push_str("<html>\n");
    html.push_str("  <body>\n");
    html.push_str(&format!("  <h2>results: {}</h2>\n", results.len()));
    let mut tags: HashMap<String, HashSet<String>> = HashMap::new();

    let mut result_html = String::new();
    for result in results.iter() {
        let start = Instant::now();
        let desc = match ctx.dbctx.db.describe_file(*result) {
            Ok(desc) => desc,
            Err(e) => {
                error!("tag search error: {}", e);
                return (StatusCode::BAD_REQUEST, Html("<html><body>bad request, no biscuits</body></html>".to_string()));
            }
        };
//        eprintln!("file {} described in {}ms", result, start.elapsed().as_micros() as f64 / 1000.0);

        result_html.push_str(&format!("    <p>file {}</p>\n", result));
        result_html.push_str("<pre>");
        write!(result_html, "  sha256: {}\n", desc.sha256.as_ref().map(|x| x.as_str()).unwrap_or("<null>"));
        write!(result_html, "replicas:\n");
        for replica in desc.replicas.iter() {
            if let (Some(who), Some(path)) = (replica.who.as_ref(), replica.replica.as_ref()) {
                write!(result_html, "  {}: {}, checked {}", who, path, replica.last_check_ts);
                if replica.valid {
                    write!(result_html, " (valid)");
                }
            } else {
                write!(result_html, "  &lt;unknown&gt;");
            }
            result_html.push_str("\n");
        }
        write!(result_html, "tags:\n");
        for tag in desc.tags.iter() {
            tags.entry(tag.name.clone()).or_default()
                .insert(tag.value.clone());
            writeln!(result_html, "  {}: {}, from {}", tag.name, tag.value, tag.source);
        }
        result_html.push_str("</pre>");
    }

    let mut tag_names: Vec<&str> = tags.keys().map(|x| x.as_str()).collect();
    tag_names.sort();

    let mut tag_summary = String::new();
    tag_summary.push_str("  <p>tags in result set:</p>\n");
    for tag in tag_names {
        write!(tag_summary, "<p><a href=\"/tags/search?{q}&{tag}\">{tag}</a>: ");
        let mut values = tags.get(tag).expect("tag is still present")
            .iter().map(|x| x.as_str()).collect::<Vec<&str>>();
        values.sort();
        if (values.len() as f64 / (results.len() as f64) < 0.05) || (values.len() < 20) {
            let mut first = true;
            for v in values {
                if !first {
                    tag_summary.push_str(", ");
                } else {
                    first = false;
                }
                write!(tag_summary, "<a href=\"/tags/search?{q}&{tag}={v}\">{v}</a>");
            }
        } else {
            write!(tag_summary, "&lt;{} values&gt;", values.len());
        }
        write!(tag_summary, "</p>\n");
    }

    html.push_str(&tag_summary);
    html.push_str(&result_html);

    html.push_str("  </body>\n");
    html.push_str("</html>\n");

    eprintln!("search handled in {}ms", start.elapsed().as_micros() as f64 / 1000.0);

    (StatusCode::OK, Html(html))
}

async fn handle_tags_index(State(ctx): State<WebserverState>) -> impl IntoResponse {
    eprintln!("root index");

    let mut tags: Vec<String> = Vec::new();

    for tag_id in ctx.dbctx.db.list_tags().expect("can list tags").into_iter() {
        tags.push(ctx.dbctx.db.tag_name(tag_id).expect("can get tag names").expect("if tag was listed it has a name"));
    }

    let mut html = String::new();
    html.push_str("<html>\n");
    html.push_str("  <body>\n");
    html.push_str("    <p>hof tag explorer</p>\n");
    html.push_str("    <h3>tags</h3>\n");
    html.push_str("    <table>\n");
    html.push_str("      <tbody>\n");
    for tag in tags.iter() {
        html.push_str(&format!("        <tr><th>{}</th><td></td>\n", tag));
    }
    html.push_str("      </tbody>\n");
    html.push_str("    </table>\n");
    html.push_str("  </body>\n");
    html.push_str("</html>\n");

    (StatusCode::OK, Html(html))
}

#[derive(Clone)]
struct WebserverState {
    dbctx: Arc<Hof>,
    incoming_dir: PathBuf
}

async fn make_app_server(db_path: &PathBuf, config_path: &PathBuf, incoming_dir: PathBuf) -> Router {
    Router::new()
        .route("/", get(handle_tags_index))
        .route("/help", get(handle_help))
        .route("/file/:id", get(handle_describe_file))
        .route("/file/:id/download", get(handle_download_file))
        .route("/file/:id/tag", post(handle_tag_file))
        .route("/file/upload", post(handle_uploaded_file))
        .route("/tags/search", get(handle_search_tags))
        .fallback(fallback_get)
        .with_state(WebserverState {
            dbctx: Arc::new(Hof::new(db_path, config_path)),
            incoming_dir,
        })
}

async fn bind_server(conf: serde_json::Value, db_path: PathBuf, config_path: PathBuf, incoming_dir: PathBuf) -> std::io::Result<()> {
    let server = make_app_server(&db_path, &config_path, incoming_dir).await.into_make_service();

    use serde_json::Value;
    match conf {
        Value::String(address) => {
            axum_server::bind(address.parse().unwrap())
                .serve(server).await
        }
        other => {
            panic!("invalid server configuration: {:?}", other);
        }
    }
}

fn get_one_header<'header>(headers: &'header HeaderMap, header: &str) -> Option<&'header str> {
    let mut header_iter = headers.get_all(header).iter();
    let v = header_iter.next()?;
    if header_iter.next().is_some() {
        return None;
    }

    Some(v.to_str().expect("TODO: good strings only pls"))
}

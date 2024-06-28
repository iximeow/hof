use chrono::{Utc, TimeZone};
use serde::{Deserialize, Serialize};

use std::collections::{HashMap, HashSet, hash_map::Entry};
use std::fmt::Write;
use std::sync::Arc;
use std::path::PathBuf;

use axum::Router;
use axum::routing::get;
use axum::response::{Html, IntoResponse};
use axum::extract::{Path, State, RawQuery};
use axum::{Error, Json};
use axum::extract::rejection::JsonRejection;
use axum::body::Bytes;
use axum::http::{StatusCode, Uri};
use http::header::HeaderMap;

use tracing::error;

use hofvarpnir::Hof;

#[derive(Serialize, Deserialize)]
struct WebserverConfig {
    debug_addr: Option<serde_json::Value>,
    db_path: PathBuf,
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

    if let Some(addr_conf) = web_config.debug_addr.as_ref() {
        tokio::spawn(bind_server(addr_conf.clone(), db_path.clone()));
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
/tags/search          search by tags (query string is a list of tag=value, tag=1&tag=2 means `tag in [1, 2]` and tag=&tag2= means `has tag 1 and tag 2`
</pre>");
    resp.push_str("  </body>\n");
    resp.push_str("</html>\n");
    (StatusCode::OK, Html(resp))
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
        write!(html,"  {}: {}, checked {}", replica.who, replica.replica, replica.last_check_ts);
        if replica.valid {
            write!(html, " (valid)");
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

    let results = match ctx.dbctx.db.select_by_tags(&tag_list) {
        Ok(results) => results,
        Err(e) => {
            error!("select by tags error: {}", e);
            return (StatusCode::BAD_REQUEST, Html("<html><body>bad request, no biscuits</body></html>".to_string()))
        }
    };

//    println!("results: {:?}", results);

    let mut html = String::new();
    html.push_str("<html>\n");
    html.push_str("  <body>\n");
    html.push_str(&format!("  <h2>results: {}</h2>\n", results.len()));
    for result in results.iter() {
        let desc = match ctx.dbctx.db.describe_file(*result) {
            Ok(desc) => desc,
            Err(e) => {
                error!("tag search error: {}", e);
                return (StatusCode::BAD_REQUEST, Html("<html><body>bad request, no biscuits</body></html>".to_string()));
            }
        };

        html.push_str(&format!("    <p>file {}</p>\n", result));
        html.push_str("<pre>");
        write!(html, "  sha256: {}\n", desc.sha256.as_ref().map(|x| x.as_str()).unwrap_or("<null>"));
        write!(html, "replicas:\n");
        for replica in desc.replicas.iter() {
            write!(html, "  {}: {}, checked {}", replica.who, replica.replica, replica.last_check_ts);
            if replica.valid {
                write!(html, " (valid)");
            }
            html.push_str("\n");
        }
        write!(html, "tags:\n");
        for tag in desc.tags.iter() {
            writeln!(html, "  {}: {}, from {}", tag.name, tag.value, tag.source);
        }
        html.push_str("</pre>");
    }
    html.push_str("  </body>\n");
    html.push_str("</html>\n");

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
}

async fn make_app_server(db_path: &PathBuf) -> Router {
    Router::new()
        .route("/", get(handle_tags_index))
        .route("/help", get(handle_help))
        .route("/file/:id", get(handle_describe_file))
        .route("/tags/search", get(handle_search_tags))
        .fallback(fallback_get)
        .with_state(WebserverState {
            dbctx: Arc::new(Hof::new(db_path))
        })
}

async fn bind_server(conf: serde_json::Value, db_path: PathBuf) -> std::io::Result<()> {
    let server = make_app_server(&db_path).await.into_make_service();

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

use actix_http::{
    header::{HeaderMap, HeaderValue},
    StatusCode, error::PayloadError,
};
use actix_web::error;
use async_recursion::async_recursion;
use itertools::Itertools;
use lazy_static::lazy_static;
use log::{error, info};
use serde::{Deserialize, Serialize};
use std::{
    io::{BufRead, BufReader, Read},
    sync::Arc, process::ExitStatusError,
};

use actix_multipart::form::{tempfile::TempFile, MultipartForm};

use tokio::{
    runtime::Builder,
    sync::{OnceCell, RwLock},
};

use crate::remove_file;

lazy_static! {
    pub static ref SEMAPHORE: Arc<async_weighted_semaphore::Semaphore> = Arc::new(async_weighted_semaphore::Semaphore::new(2));
}

// lazy_static! {
//     pub static ref ARBITER: Arbiter = SyncArbiter::start(threads, factory);
// }

lazy_static! {
    pub static ref CWD: String = std::env::current_exe()
        .unwrap()
        .ancestors()
        .nth(3)
        .unwrap()
        .to_str()
        .unwrap()
        .to_owned();
}

lazy_static! {
    pub static ref THUMBNAIL_CACHE: OnceCell<Arc<tokio::sync::RwLock<Vec<ThumbnailCache>>>> =
        OnceCell::new();
}
pub async fn init_cache() -> Arc<tokio::sync::RwLock<Vec<ThumbnailCache>>> {
    Arc::new(ThumbnailCache::cache_init().await)
}

lazy_static! {
    pub static ref THREAD_POOL: tokio::runtime::Runtime = {
        Builder::new_multi_thread()
            .worker_threads(6)
            .event_interval(2)
            .max_io_events_per_tick(1)
            .max_blocking_threads(2)
            .enable_all()
            .build()
            .unwrap()
    };
}

lazy_static! {
    pub static ref PROCESS_QUEUE: RwLock<ProcessQueue> = RwLock::new(ProcessQueue::new());
}

#[derive(Debug, MultipartForm)]
pub struct UploadForm {
    #[multipart(rename = "file-input")]
    pub files: Vec<TempFile>,
}

#[derive(Deserialize, Serialize)]
pub struct RickViewConfig<'a> {
    prefix: &'a str,
    namespace: &'a str,
    kb_file: &'a str,
    examples: Vec<String>,
    title: &'a str,
    subtitle: &'a str,
    show_inverse: bool,
    base: &'a str,
    large: bool,
    endpoint: &'a str,
    namespaces: NameSpaces<'a>,
}

#[derive(Deserialize, Serialize)]
struct NameSpaces<'a> {
    c4o: &'a str,
    co: &'a str,
    data: &'a str,
    dcterms: &'a str,
    doco: &'a str,
    document: &'a str,
    frbr: &'a str,
    owl: &'a str,
    po: &'a str,
    prof: &'a str,
    rdfs: &'a str,
    owlequiv: &'a str,
}

#[derive(Debug, Clone)]
pub struct FileData {
    pub pdf_path: String,
    pub docx_path: String,
}

#[derive(Debug)]
pub struct ProcessQueue {
    pub running_que: Vec<Process>,
    waiting_que: Vec<Process>,
}

#[derive(Debug, Clone)]
pub struct Process {
    pub paths: FileData,
    pub sender: tokio::sync::mpsc::Sender<Option<ExitStatusError>>,
    pub semaphore: Arc<async_weighted_semaphore::SemaphoreGuard<'static>>,
}

impl ProcessQueue {
    pub async fn qued_pdf_to_docx(
        pdf_path: String,
        docx_path: String,
        semaphore: Arc<async_weighted_semaphore::SemaphoreGuard<'static>>,
        tx: tokio::sync::mpsc::Sender<Option<ExitStatusError>>,
    ) -> std::result::Result<(), std::io::Error> {
        info!("pdf path :{pdf_path}\t docx path: {docx_path}");
        let mut child = tokio::process::Command::new("python")
            .arg("./pdf2docx/use.py")
            .arg(&pdf_path)
            .arg(&docx_path)
            .stdout(std::process::Stdio::piped())
            .spawn()?;

        let exit_status = child.wait().await?;

        if !exit_status.success() {
            error!("Error occured at pdf_to_docx conversion: {exit_status}");

            remove_file(&[&pdf_path]);

            tx.send(Some(exit_status.exit_ok().err().unwrap())).await.unwrap();

            drop(semaphore);

            Ok(())
        } else {
            let mut headers = HeaderMap::new();

            headers.insert(
                actix_http::header::CONTENT_TYPE,
                HeaderValue::from_str("text/turtle").unwrap(),
            );

            tx.send(None).await.unwrap();

            drop(semaphore);

            Ok(())
        }
    }

    fn new() -> Self {
        ProcessQueue {
            running_que: Vec::new(),
            waiting_que: Vec::new(),
        }
    }

    pub async fn push(&mut self, process: Process) {
        if self.running_que.len() < 2 {
            self.running_que.push(process);
            info!("pushed to running que");
        } else {
            info!("pushed to waiting que");
            self.waiting_que.push(process);
            self.check().await
        }
        self.execute().await
    }

    async fn execute<'a>(&mut self) {
        info!("execute called");

        if self.running_que.len().gt(&0) && self.running_que.len().lt(&2) {
            for _ in self.running_que.clone().iter() {
                let process = self.running_que.remove(0);
                let pdf_path = process.paths.pdf_path.clone();
                let docx_path = process.paths.docx_path.clone();
                let tx = process.sender.clone();
                let semaphore = process.semaphore.clone();
                THREAD_POOL.spawn(Self::qued_pdf_to_docx(pdf_path, docx_path, semaphore, tx));
            }
        }
    }

    #[async_recursion]
    async fn check(&mut self) -> () {
        match self.waiting_que.clone().into_iter().next() {
            Some(process) if self.running_que.len().lt(&2) => {
                info!("waiting que >0, running que < 2 ");
                self.running_que.push(process);
                self.waiting_que.remove(0);
                self.check().await;
            }
            _ => {}
        }
    }
}

#[derive(serde::Serialize)]
pub struct ConfigSchema<'a> {
    pub location: &'a str,
    pub label: &'a str,
    pub slug: u64,
    pub doc_id_for_hashing: &'a str,
    pub jurisdiction: &'a str,
}

#[derive(Serialize, Deserialize)]
pub struct Index {
    pub index: String,
}

#[derive(serde::Deserialize, serde::Serialize)]
pub struct RDFSchemaUpper {
    results: Bindings,
}

#[derive(serde::Deserialize, serde::Serialize, Default)]
struct Bindings {
    bindings: Vec<RDFSchema>,
}

#[derive(serde::Deserialize, serde::Serialize)]
struct RDFSchema {
    #[serde(alias = "o")]
    obj: InnerRDFSchema,
    #[serde(alias = "p")]
    pred: InnerRDFSchema,
    #[serde(alias = "s")]
    sub: InnerRDFSchema,
}

#[derive(serde::Deserialize, Default, Serialize)]
struct InnerRDFSchema {
    #[serde(rename(deserialize = "type"))]
    mode: String,
    value: String,
}

#[derive(Debug, serde::Deserialize, serde::Serialize)]
pub struct ListJson {
    pub item: Vec<String>,
}

#[derive(Debug, Clone, Default)]
pub struct ThumbnailCache {
    pub items: Vec<ThumbnailCacheInner>,
}

#[derive(Debug, Clone, Default)]
pub struct ThumbnailCacheInner {
    pub path: String,
    pub contents: Vec<u8>,
}

impl ThumbnailCache {
    async fn cache_init() -> tokio::sync::RwLock<Vec<ThumbnailCache>> {
        let thumbnail_vec = tokio::sync::RwLock::new(Vec::new());
        let thumbnails = std::fs::read_dir(std::path::PathBuf::from(
            CWD.to_string() + "/upload/thumbnails/",
        ))
        .unwrap();

        for thumbnail in thumbnails {
            let thumbnail_path = thumbnail.as_ref().unwrap().path().to_owned();
            let thumbnail_bytes = tokio::fs::read(thumbnail_path.clone()).await.unwrap();

            let thumbnail_cache_inner = ThumbnailCacheInner {
                path: thumbnail_path
                    .to_str()
                    .unwrap()
                    .strip_prefix(&(CWD.to_string() + "/"))
                    .unwrap()
                    .to_string(),
                contents: thumbnail_bytes,
            };

            thumbnail_vec.write().await.push(ThumbnailCache {
                items: vec![thumbnail_cache_inner],
            });
        }

        thumbnail_vec
    }
}

#[derive(thiserror::Error, Debug)]
pub enum HttpError {
    #[error("HTTP Error {source:?}")]
    Reqwest {
        #[from]
        source: reqwest::Error,
    },
    #[error("SerdeJson Error {source:?}")]
    SerdeJson {
        #[from]
        source: serde_json::Error,
    },
    #[error("Standard Input/Output Error {source:?}")]
    Io {
        #[from]
        source: std::io::Error,
    },
    #[error("External Syscall Error {source:?}")]
    Syscall {
        #[from]
        source: std::process::ExitStatusError,
    },
    #[error("String may not be formatted as UTF8 {source:?}")]
    UTF8 {
        #[from]
        source: std::string::FromUtf8Error,
    },
    #[error("Error Converting Thumbnail {source:?}")]
    CairoError {
        #[from]
        source: cairo::Error,
    },
    #[error("Error involving Payload {source:?}")]
    PayLoadError {
        #[from]
        source: PayloadError,
    },
    #[error("Channel has been closed")]
    ChannelClosed,
}

impl From<cairo::IoError> for HttpError {
    fn from(_err: cairo::IoError) -> Self {
        HttpError::CairoError { source: cairo::Error::WriteError } 
    }
}

impl error::ResponseError for HttpError {
    fn error_response(&self) -> actix_web::HttpResponse {
        actix_web::HttpResponse::build(self.status_code())
            .insert_header(actix_web::http::header::ContentType::html())
            .body(self.to_string())
    }

    fn status_code(&self) -> StatusCode {
        match self {
            HttpError::Reqwest { source } => {
                if source.is_body() || source.is_decode() {
                    StatusCode::UNPROCESSABLE_ENTITY
                } else if source.is_timeout() {
                    StatusCode::REQUEST_TIMEOUT
                } else if source.is_connect() {
                    StatusCode::SERVICE_UNAVAILABLE
                } else {
                    StatusCode::BAD_REQUEST
                }
            }

            HttpError::Io { source } => {
                if let Some(error) = source.raw_os_error() {
                    StatusCode::try_from(error as u16).unwrap()
                } else {
                    StatusCode::INTERNAL_SERVER_ERROR
                }
            }

            HttpError::Syscall { source } => {
                match StatusCode::try_from(source.code().unwrap() as u16) {
                    Ok(status_code) => status_code,
                    Err(_) => StatusCode::UNPROCESSABLE_ENTITY,
                }
            }

            HttpError::SerdeJson { source } => match source.classify() {
                serde_json::error::Category::Io => StatusCode::INTERNAL_SERVER_ERROR,
                serde_json::error::Category::Syntax => StatusCode::BAD_REQUEST,
                serde_json::error::Category::Data => StatusCode::UNPROCESSABLE_ENTITY,
                serde_json::error::Category::Eof => StatusCode::UNPROCESSABLE_ENTITY,
            },
            HttpError::UTF8 { source } => {
                source.utf8_error().status_code();
                StatusCode::BAD_REQUEST
            }
            HttpError::ChannelClosed { .. } => StatusCode::INTERNAL_SERVER_ERROR,
            HttpError::CairoError { .. } => StatusCode::INTERNAL_SERVER_ERROR,
            HttpError::PayLoadError { source } => source.status_code(),
        }
    }
}

impl RickViewConfig<'_> {
    pub fn serialize(index: i32) -> Result<(), std::io::Error> {
        let rdf_file = format!("./datasets/nsw/{index}.ttl");
        let mut prefix_injection_buffer = BufReader::new(std::fs::File::open(&rdf_file)?);

        let mut buffer = String::new();

        for _ in 0..=13 {
            prefix_injection_buffer.read_line(&mut buffer)?;
        }

        buffer.push_str("@prefix owlequiv: <https://www.w3.org/2000/01/owl-equiv/> .\n");

        prefix_injection_buffer.read_to_string(&mut buffer)?;

        buffer = buffer.replace("_:", "owlequiv:");

        std::fs::write("./RickView/bin/data/surroundaustralia/example.ttl", &buffer).and_then(
            |_result| {
                let blank_node_buffer = BufReader::new(std::fs::File::open(&rdf_file)?);
                let node_array = blank_node_buffer
                    .lines()
                    .filter_map(|line| {
                        let nodes: Vec<_> = line.as_ref().unwrap().split_whitespace().collect();
                        if let Some(node) = nodes.first() {
                            if node.starts_with("data:") || node.starts_with('_') {
                                let node = node.replace(',', "");
                                Some(node)
                            } else {
                                None
                            }
                        } else {
                            None
                        }
                    })
                    .unique()
                    .map(|node| {
                        let node = node.replace("_:", "www.w3.org/2000/01/owl-equiv/");
                        if node.contains("data:") {
                            node.replace("data:", "data.surroundaustralia.com/cadastre-3d/")
                        } else {
                            node
                        }
                    })
                    .sorted()
                    .collect();

                let config_header = RickViewConfig {
                    prefix: "",
                    namespace: r"https://",
                    kb_file: "./data/surroundaustralia/example.hdt",
                    examples: node_array,
                    title: "Surround Australia Augmented Search Graph Lookup",
                    subtitle: "Introducing Enlightenment Through Interconnected Knowledge",
                    show_inverse: true,
                    base: "/",
                    large: true,
                    endpoint: "https://127.0.0.1:8000/sparql",
                    namespaces: NameSpaces {
                        c4o: "http://purl.org/spar/c4o/",
                        co: "http://purl.org/co/",
                        data: "https://data.surroundaustralia.com/cadastre-3d/",
                        dcterms: "http://purl.org/dc/terms/",
                        doco: "http://purl.org/spar/doco/",
                        document: "https://data.surroundaustralia.com/dataset/document/",
                        frbr: "http://purl.org/spar/frbr/",
                        owl: "http://www.w3.org/2002/07/owl#",
                        po: "http://purl.org/spar/po/",
                        prof: "http://www.w3.org/ns/dx/prof/",
                        rdfs: "http://www.w3.org/2000/01/rdf-schema#",
                        owlequiv: "https://www.w3.org/2000/01/owl-equiv/",
                    },
                };
                let config_header = toml::to_string_pretty(&config_header).unwrap();
                std::fs::write("./RickView/bin/data/config.toml", config_header)
            },
        )
    }
}

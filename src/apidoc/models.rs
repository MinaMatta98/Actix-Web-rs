use crate::startup::PROCESS_QUE;
use crate::{absorb_with_graph, create_thumbnail, remove_file, CWD, FILE_CACHE, THREAD_POOL};
use itertools::Itertools;
use rand::prelude::*;
use rocket::http::{ContentType, Status};
use rocket::request::{self, FromRequest};
use rocket::response::Redirect;
use rocket::response::{content::Html, NamedFile, Responder};
use rocket::{Outcome, Request};
use rocket_contrib::json::JsonValue;
use schemars::JsonSchema;
use scraper::*;
use serde::Deserialize;
use serde::Serialize;
use std::cell::RefCell;
use std::collections::{HashMap, VecDeque};
use std::fs;
use std::io::Cursor;
use std::io::{BufRead, BufReader, Read};
use std::net::SocketAddr;
use std::rc::Rc;
use std::sync::atomic::AtomicBool;
use std::sync::mpsc::SyncSender;
use std::sync::{Arc, Mutex, RwLock};
// use thiserror::Error;
use anyhow::Context;
use futures::stream::StreamExt;
use futures::{self, select, Future, FutureExt};
use tokio::time;

#[derive(Responder)]
pub enum ServerResponse<'a> {
    // NamedFile(NamedFile),
    NamedFile(NamedFile),
    Err(rocket::response::Result<'a>),
    Html(std::io::Result<Html<String>>),
}

#[derive(Debug, Clone)]
pub struct FileCacheSorter {
    pub dir: Vec<FileCacheFields>,
}

#[derive(Debug, Clone)]
pub struct FileCacheFields {
    pub dir_entry: String,
    pub contents: Vec<FileCache>,
}

#[derive(Debug, Clone, Default)]
pub struct FileCache {
    pub name: String,
    pub contents: Vec<u8>,
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

#[derive(Responder, serde::Serialize, serde::Deserialize, FromForm)]
pub struct Index {
    pub index: String,
}

#[derive(Responder)]
pub enum ResIO<'a> {
    Res(std::io::Result<rocket::response::Response<'a>>),
}

#[derive(Responder, serde::Serialize, serde::Deserialize)]
pub enum JsonText {
    JsonValue(JsonValue),
    String(String),
}

#[derive(Debug, serde::Deserialize, serde::Serialize)]
pub struct ListJson {
    pub item: Vec<String>,
}

#[derive(Debug, serde::Deserialize, serde::Serialize)]
pub struct ReCaptchaResponse {
    success: bool,
    challenge_ts: String,
    hostname: String,
    #[serde(rename = "error-codes")]
    error_codes: Option<String>,
}

#[derive(FromForm, serde::Serialize, serde::Deserialize)]
pub struct FormData {
    recaptcha_response: String,
    name: String,
    email: String,
    message: String, // Add other form fields here
}

#[derive(serde::Serialize)]
pub struct ConfigSchema<'a> {
    pub location: &'a str,
    pub label: &'a str,
    pub slug: u64,
    pub doc_id_for_hashing: &'a str,
    pub jurisdiction: &'a str,
}

#[derive(serde::Deserialize, serde::Serialize, JsonSchema)]
pub struct RDFSchemaUpper {
    results: Bindings,
}

#[derive(serde::Deserialize, serde::Serialize, Default, JsonSchema)]
pub struct Bindings {
    bindings: Vec<RDFSchema>,
}

#[derive(serde::Deserialize, serde::Serialize, JsonSchema)]
pub struct RDFSchema {
    #[serde(alias = "o")]
    obj: InnerRDFSchema,
    #[serde(alias = "p")]
    pred: InnerRDFSchema,
    #[serde(alias = "s")]
    sub: InnerRDFSchema,
}

#[derive(serde::Deserialize, Default, Serialize, JsonSchema)]
struct InnerRDFSchema {
    #[serde(rename(deserialize = "type"))]
    mode: String,
    value: String,
}

#[derive(Debug)]
pub enum ThumbnailError {
    GlibError(cairo::glib::Error),
    NoPagesError,
    CairoError(cairo::Error),
    CairoIoError(cairo::IoError),
    IoError(std::io::Error),
}

impl From<cairo::glib::Error> for ThumbnailError {
    fn from(err: cairo::glib::Error) -> Self {
        ThumbnailError::GlibError(err)
    }
}

impl From<cairo::Error> for ThumbnailError {
    fn from(status: cairo::Error) -> Self {
        ThumbnailError::CairoError(status)
    }
}

impl From<cairo::IoError> for ThumbnailError {
    fn from(err: cairo::IoError) -> Self {
        ThumbnailError::CairoIoError(err)
    }
}

impl From<std::io::Error> for ThumbnailError {
    fn from(err: std::io::Error) -> Self {
        ThumbnailError::IoError(err)
    }
}

pub struct HtmlFilter;

#[derive(Serialize, Deserialize)]
pub struct FilteredHtmlItems {
    pub link: String,
    pub search_string: String,
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
    #[error("Error: {source:?}")]
    OptSource {
        #[from]
        source: anyhow::Error,
    },
}

pub struct ProcessQueue {
    pub running_process_list: Vec<Process>,
    pub waiting_process_list: Vec<Process>,
}

#[derive(Debug, Clone)]
pub struct Process {
    pub pdf_path: String,
    pub docx_path: String,
    pub counter: usize,
    // pub thumbnails: rocket::State<'a, Mutex<Vec<ThumbnailCache>>>,
    pub graph_name: Option<String>,
    pub dataset_path: Option<String>,
    pub pdf_thumbnail_path: Option<String>,
    pub file_location: String,
    pub config_location: String,
    pub socket: RocketSocket,
}

impl ProcessQueue {
  async fn pdf_conversion(
        pdf_path: String,
        docx_path: String,
        // thumbnails: &mut rocket::State<Mutex<Vec<ThumbnailCache>>>,
        graph_name: Option<String>,
        dataset_path: Option<String>,
        pdf_thumbnail_path: Option<String>,
        file_location: String,
        config_location: String,
        socket: RocketSocket,
        tx: std::sync::mpsc::Sender<bool>,
    ) -> Future: std::result::Result<Redirect, HttpError> {
        let output = std::process::Command::new("python")
            .arg("./pdf2docx/use.py")
            .arg(&pdf_path)
            .arg(&docx_path)
            .status();
        println!("output is {:?}", output);
        if !output.unwrap().success() {
            // println!("Error occured at pdf_to_docx conversion: {output}");
            crate::remove_file(&[pdf_path.as_str()]);
            // Err(std::io::Error::new(
            //     std::io::ErrorKind::InvalidData,
            //     output.to_string(),
            // ))?;

            // let req = Request::example(rocket::http::Method::Get, "/augment.html", |request| {
            //     request.set_method(rocket::http::Method::Get);
            //     request.set_remote(socket.socket);
            // });
            tx.send(false).unwrap();
            PROCESS_QUE.write().unwrap().running_process_list.remove(0);

            // PROCESS_QUE.write().unwrap().execute();
            Ok(Redirect::to("/augment.html?failure"))
        } else {
            tx.send(true).unwrap();
            PROCESS_QUE.write().unwrap().running_process_list.remove(0);

            // PROCESS_QUE.write().unwrap().execute();
            let mut headers = HashMap::new();
            headers.insert("Content-Type".to_string(), "text/turtle".to_string());
            crate::docx_to_rdf(&config_location, &file_location).unwrap_or_else(|error| {
                remove_file(&[pdf_path.as_str()]);
                println!("{error}")
            });
            absorb_with_graph(
                Some(ResponseHeader { headers }),
                None,
                Some(&graph_name.unwrap()),
                Some(&dataset_path.unwrap()),
            )?;
            create_thumbnail(
                std::path::Path::new(&pdf_path),
                std::path::Path::new(&pdf_thumbnail_path.unwrap()),
            )
            .unwrap();
            Ok(Redirect::to("/augment.html?sucess"))
            // .map_err(|e| HttpError::Io {
            //     source: std::io::Error::new(std::io::ErrorKind::InvalidData, "Not Supported"),
            // })
        }
    }

    pub fn new() -> Self {
        ProcessQueue {
            running_process_list: Vec::new(),
            waiting_process_list: Vec::new(),
        }
    }

    pub fn push(&mut self, process: Process) -> Result<Redirect, ()> {
        self.waiting_process_list.push(process);
        self.execute()
    }

    pub fn execute(&mut self) -> std::result::Result<Redirect, ()> {
        while self.running_process_list.len() < 2 && !self.waiting_process_list.is_empty() {
            self.running_process_list
                .push(self.waiting_process_list.remove(0));
        }

        let (tx, rx) = std::sync::mpsc::channel();
        for process in self.running_process_list.iter_mut() {
            if process.counter == 0 {
                process.counter += 1;
                let pdf_path = process.pdf_path.clone();
                let docx_path = process.docx_path.clone();
                let graph_name = process.graph_name.clone();
                let dataset_path = process.dataset_path.clone();
                let pdf_thumbnail_path = process.pdf_thumbnail_path.clone();
                let file_location = process.file_location.clone();
                let config_location = process.config_location.clone();
                let socket = process.socket.clone();

                select! {
                Ok(redirect) = THREAD_POOL.spawn(|| {
                    Self::pdf_conversion(
                        pdf_path,
                        docx_path,
                        // &mut process.thumbnails,
                        graph_name,
                        dataset_path,
                        pdf_thumbnail_path,
                        file_location,
                        config_location,
                        socket,
                        tx,
                    );
                }).await => {

                }

                }

                break;
            }
            // Redirect::to(uri)
        }
        Self::receive(rx)
    }

   async fn check(&mut self) {
        while self.running_process_list.len() < 2 && !self.waiting_process_list.is_empty() {
            self.running_process_list
                .push(self.waiting_process_list.remove(0));
        }
    }

    pub fn receive(mut rx: std::sync::mpsc::Receiver<bool>) -> std::result::Result<Redirect, ()> {
        // loop {
        //     select! {
        //     Some(value) = rx.next().fuse() => {
        //             match value {
        //         true => Ok::<rocket::response::Redirect, ()>(Redirect::to("/augment.html?success")),
        //         false => Ok::<rocket::response::Redirect, ()>(Redirect::to("/augment.html?failure")),
        //             };
        //         },
        //     _ = tokio::time::sleep(tokio::time::Duration::from_millis(50)).fuse() => (),
        //     }
        // }
        // match rx.try_recv() {
        //     Ok(val) => match val {
        //         true => Ok(Redirect::to("/augment.html?success")),
        //         false => Ok(Redirect::to("/augment.html?failure")),
        //     },
        //     Err(e) => {
        //         println!("Error line chosen");
        //         std::thread::yield_now();
        //         Self::receive(rx)
        //     }
        // }
        match rx.recv().unwrap() {
            true => Ok(Redirect::to("/augment.html?success")),
            false => Ok(Redirect::to("/augment.html?failure")),
        }
        // }
    }
}

impl Default for ProcessQueue {
    fn default() -> Self {
        Self::new()
    }
}

impl<'r> Responder<'r> for HttpError {
    fn respond_to(self, request: &Request) -> rocket::response::Result<'r> {
        match self {
            HttpError::Reqwest { source } => {
                if source.is_body() || source.is_decode() {
                    Status::UnprocessableEntity.respond_to(request)
                } else if source.is_timeout() {
                    Status::RequestTimeout.respond_to(request)
                } else if source.is_connect() {
                    Status::ServiceUnavailable.respond_to(request)
                } else {
                    Status::BadRequest.respond_to(request)
                }
            }
            HttpError::SerdeJson { source } => match source.classify() {
                serde_json::error::Category::Io => Status::InternalServerError.respond_to(request),
                serde_json::error::Category::Syntax => Status::BadRequest.respond_to(request),
                serde_json::error::Category::Data => {
                    Status::UnprocessableEntity.respond_to(request)
                }
                serde_json::error::Category::Eof => Status::UnprocessableEntity.respond_to(request),
            },
            HttpError::Io { source } => {
                if let Some(error) = source.raw_os_error() {
                    Status::from_code(error as u16).respond_to(request)
                } else {
                    Status::NotFound.respond_to(request)
                }
            }
            HttpError::Syscall { source } => {
                Status::from_code(source.code().unwrap() as u16).respond_to(request)
            }
            HttpError::OptSource { source } => {
                println!("{:?}", source.root_cause().source());
                Status::InternalServerError.respond_to(request)
            }
        }
    }
}

//Implementation Section
impl FileCacheSorter {
    pub fn rocket_response(
        file_dir: &std::path::Path,
        file_name: &str,
    ) -> std::result::Result<rocket::Response<'static>, HttpError> {
        let mut response = rocket::response::Response::build();
        response.header(
            ContentType::from_extension(file_name.split('.').last().unwrap_or_default())
                .unwrap_or_default(),
        );

        let dir = FILE_CACHE
            .dir
            .iter()
            .find(|dir| dir.dir_entry == file_dir.to_str().unwrap_or_default());

        match dir {
            Some(dir) => {
                match dir
                    .contents
                    .iter()
                    .find(|file| file.name.clone() == file_name)
                {
                    Some(file) => {
                        match String::from_utf8(file.contents.clone()) {
                            Ok(body) => response.sized_body(Cursor::new(body)),
                            Err(_) => response.sized_body(Cursor::new(file.contents.clone())),
                        };
                        response.status(Status::Ok);
                    }
                    None => {
                        return Err(std::io::Error::new(
                            std::io::ErrorKind::NotFound,
                            format!("Directory has been located, but {file_name} not found"),
                        ))?;
                    }
                }
            }
            None => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::NotFound,
                    format!("Directory {} does not exist", file_dir.display()),
                ))?;
            }
        }
        response.ok()
    }
}

pub trait ResponseMerge {
    fn merge(&mut self, file_dir: &std::path::Path, file_name: &str) -> Result<(), HttpError>;
}

impl ResponseMerge for std::result::Result<rocket::Response<'static>, HttpError> {
    fn merge(&mut self, file_dir: &std::path::Path, file_name: &str) -> Result<(), HttpError> {
        match self {
            Ok(result) => {
                let body = result.take_body().expect("Error merging body");
                let mut appenable_content = FILE_CACHE
                    .dir
                    .iter()
                    .find(|dir| {
                        dir.dir_entry
                            == file_dir
                                .to_str()
                                .ok_or(HttpError::Io {
                                    source: std::io::Error::new(
                                        std::io::ErrorKind::NotFound,
                                        "File not found",
                                    ),
                                })
                                .unwrap()
                    })
                    .context("could not merge within intended directory")?
                    .contents
                    .iter()
                    .find(|content| content.name.clone() == file_name)
                    .context("Could not find file in FileCache")?
                    .contents
                    .clone();

                if file_name == "augment-file-present.html" {
                    let mut rng = rand::thread_rng();

                    let entries = std::fs::read_dir("./upload")?;

                    let mut file_paths: Vec<std::path::PathBuf> = entries
                        .map(|entry| {
                            entry
                                .map_err(|e| std::io::Error::new(std::io::ErrorKind::NotFound, e))
                                .unwrap()
                                .path()
                        })
                        .filter(|path| path.is_file())
                        .collect();

                    file_paths.shuffle(&mut rng);
                    let rand_file = file_paths.first().context("Could not open pdf file")?;
                    let parent = rand_file
                        .parent()
                        .context("Cannot Navigate Parent Directory")?
                        .display();
                    appenable_content = String::from_utf8(appenable_content)
                        .context("String does not conform to UTF-8 encoding")?
                        .replace(
                            "{id}",
                            rand_file
                                .display()
                                .to_string()
                                .replace(&(parent.to_string() + "/"), "")
                                .split('.')
                                .next()
                                .unwrap(),
                        )
                        .into_bytes();
                }

                let mut buff: Vec<u8> = Vec::new();

                body.map(|mut body| body.read_to_end(&mut buff));

                for bytes in appenable_content.iter() {
                    buff.push(bytes.to_owned());
                }

                result.set_sized_body(Cursor::new(buff));
                Ok(())
            }
            Err(e) => Err(std::io::Error::new(
                std::io::ErrorKind::NotFound,
                e.to_string(),
            ))?,
        }
    }
}

impl ThumbnailCache {
    pub fn cache_init() -> Mutex<Vec<ThumbnailCache>> {
        let thumbnail_vec = Mutex::new(Vec::new());
        let thumbnails = std::fs::read_dir(std::path::PathBuf::from(
            CWD.to_string() + "/upload/thumbnails/",
        ))
        .unwrap();
        thumbnails.into_iter().for_each(|thumbnail| {
            let thumbnail_bytes = std::fs::read(thumbnail.as_ref().unwrap().path()).unwrap();

            let thumbnail_path = thumbnail.unwrap().path();
            thumbnail_vec.lock().unwrap().push(ThumbnailCache {
                items: {
                    vec![ThumbnailCacheInner {
                        path: thumbnail_path
                            .to_str()
                            .unwrap()
                            .strip_prefix(&(CWD.to_string() + "/"))
                            .unwrap()
                            .to_string(),
                        contents: thumbnail_bytes,
                    }]
                },
            })
        });
        thumbnail_vec
    }
}

impl HtmlFilter {
    /// The implementation of this struct results in the filtration of webpages, such that the
    /// search function of the website remains dynamic.
    ///
    /// * `directory`: This is the source directory of the files which are to be scraped for
    /// information and headers for links
    pub fn filter_html_directory(directory: &str, search: &str) -> HashMap<String, String> {
        let mut map: HashMap<String, String> = HashMap::new();

        for entry in fs::read_dir(directory).unwrap() {
            let entry = entry.unwrap();
            let path = entry.path();
            if path.is_file()
                && path.extension().unwrap() == "html"
                && entry.file_name() != "notfound.html"
            {
                let file_contents = fs::read_to_string(&path).unwrap();
                let fragment = scraper::Html::parse_fragment(&file_contents);
                let h1_selector = Selector::parse("h2").unwrap();
                fragment.select(&h1_selector).for_each(|val| {
                    val.text()
                        .map(|text| text.to_string())
                        .filter(|value| value.to_lowercase().contains(&search.to_lowercase()))
                        .for_each(|val| {
                            map.insert(val, entry.file_name().to_str().unwrap().to_string());
                        });
                })
            }
        }
        map
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

#[derive(Debug)]
/// This struct is implemented as a nuance. Rocket requires an impelementation of FromRequest for
/// their headers.
///
/// * `headers`: This variable returns the headers within the REST API GET request
pub struct ResponseHeader {
    pub headers: HashMap<String, String>,
}

#[derive(Debug, Clone)]
pub struct RocketSocket {
    pub socket: SocketAddr,
}

impl<'a, 'r> FromRequest<'a, 'r> for ResponseHeader {
    type Error = ();
    fn from_request(request: &'a Request<'r>) -> request::Outcome<ResponseHeader, ()> {
        let mut headers_map = HashMap::new();
        for header in request.headers().iter() {
            headers_map.insert(header.name().to_string(), header.value().to_string());
        }
        Outcome::Success(ResponseHeader {
            headers: headers_map,
        })
    }
}

impl<'a, 'r> FromRequest<'a, 'r> for RocketSocket {
    type Error = ();
    fn from_request(request: &'a Request<'r>) -> request::Outcome<RocketSocket, ()> {
        Outcome::Success(RocketSocket {
            socket: request.remote().unwrap(),
        })
    }
}

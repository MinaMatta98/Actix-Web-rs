use crate::apidoc::models::{
    FileCache, FileCacheFields, FileCacheSorter, ProcessQueue, ThumbnailCache,
};
use lazy_static::lazy_static;
use port_killer::kill;
use std::{process::Command, sync::RwLock};
// use reqwest::Client;
use rayon::{ThreadPool, ThreadPoolBuilder};
use rocket::{config::Environment, http::Method};
use rocket_cors::{AllowedHeaders, AllowedOrigins, CorsOptions};
use spinners::{Spinner, Spinners};
use walkdir::WalkDir;

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
    pub static ref THUMBNAIL_VEC: RwLock<ThumbnailCache> = RwLock::new(ThumbnailCache::default());
}

lazy_static! {
    pub static ref THREAD_POOL: ThreadPool =
        ThreadPoolBuilder::new().num_threads(2).build().unwrap();
}

lazy_static! {
    pub static ref PROCESS_QUE: std::sync::RwLock<ProcessQueue> =
        std::sync::RwLock::new(ProcessQueue::default());
}

lazy_static! {
    pub static ref FILE_CACHE: FileCacheSorter = {
        let recurse_dir = vec![
            WalkDir::new(CWD.to_owned() + "/src/"),
            WalkDir::new(CWD.to_owned() + "/static/"),
        ];

        let mut file_cache = FileCacheSorter { dir: Vec::new() };

        for dir in recurse_dir {
            let dir_vec = dir
                .into_iter()
                .filter_entry(|dir| dir.path().is_dir())
                .collect::<Vec<_>>();
            dir_vec.into_iter().for_each(|dir| {
                let dir = dir.unwrap();

                file_cache.dir.push(FileCacheFields {
                    dir_entry: String::from(
                        ("/".to_owned()
                            + dir
                                .path()
                                .strip_prefix(CWD.to_string())
                                .unwrap()
                                .to_str()
                                .unwrap())
                        .as_str(),
                    ),
                    contents: dir
                        .into_path()
                        .read_dir()
                        .unwrap()
                        .map(|entry| {
                            let entry = entry.unwrap();

                            (entry.path().is_file() && entry.path().to_str().unwrap() != "")
                                .then(|| FileCache {
                                    name: entry.file_name().to_string_lossy().trim().to_string(),

                                    contents: std::fs::read(entry.path()).unwrap_or_default(),
                                })
                                .unwrap_or_default()
                        })
                        .collect(),
                });
            });
        }
        file_cache
    };
}

pub static ENV: Environment = Environment::Development;

pub fn server_setup() {
    set_env();

    let mut sp = Spinner::new(Spinners::BluePulse, "Server Setup Initiating: ".into());

    kill(8000).expect("Rocket is not currently running and will be initiated");
    kill(8080).expect("RickView is not currently running and will be initiated");
    kill(7878).expect("Oxigraph Server is not currently running and will be initiated");

    load_server("./rickview", "RickView", "./RickView/bin/").unwrap();
    load_server(
        "./oxigraph_server --location ./graph-data serve",
        "Oxigraph Server",
        "./server/oxigraph/bin/",
    )
    .unwrap();

    tokio::runtime::Runtime::new().unwrap().block_on(async {
        let _ = Box::pin(
            reqwest::Client::new()
                .get("https://localhost:7878/")
                .send()
                .await,
        );
    });

    sp.stop();
}

pub fn create_cors() -> rocket_cors::Cors {
    CorsOptions::default()
        .allowed_origins(AllowedOrigins::all())
        .allowed_headers(AllowedHeaders::all())
        .send_wildcard(true)
        .allowed_methods(
            vec![Method::Get, Method::Post]
                .into_iter()
                .map(From::from)
                .collect(),
        )
        .to_cors()
        .unwrap()
}

pub fn create_rocket_config() -> rocket::Config {
    rocket::Config::build(ENV)
        .address("127.0.0.1")
        .port(8000)
        .workers(4)
        .read_timeout(20)
        .write_timeout(2)
        .finalize()
        .unwrap()
}

pub fn set_env() {
    std::env::set_current_dir(std::env::current_exe().unwrap().ancestors().nth(3).unwrap())
        .unwrap();
}

fn load_server(
    command: &str,
    process_name: &str,
    process_path: &str,
) -> std::result::Result<(), std::io::Error> {
    std::env::set_current_dir(process_path).unwrap();
    let child = Command::new("sh").arg("-c").arg(command).spawn();
    match child {
        Ok(child) => Ok(println!(
            "Starting {process_name} Server with PID: {:?}",
            child.id()
        )),
        Err(e) => Err(e),
    }
    .unwrap();
    set_env();
    Ok(())
}

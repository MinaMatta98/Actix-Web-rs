#![feature(
    let_chains,
    async_closure,
    exit_status_error,
    io_error_more,
    try_trait_v2_yeet
)]
use crate::models::{
    ConfigSchema, FileData, Index, ListJson, RickViewConfig, ThumbnailCacheInner, SEMAPHORE,
};
use actix_http::header::{HeaderMap, HeaderValue};
use actix_http::StatusCode;
use actix_multipart::form::tempfile::TempFileConfig;
// use async_weighted_semaphore::AcquireFutureArc;
use actix_web::web::{self, Redirect};
use actix_web::{get, post, App, HttpRequest, HttpResponse, HttpServer, Responder, Result};
use log::{error, info, warn};
use reqwest::Client;
use std::io::{Error, ErrorKind};
// use futures_util::{StreamExt, S}
// use futures::stream::{once, StreamExt};
// use futures::{StreamExt, Stream, stream::};
// use acti_web_actors::ws;
use actix::prelude::*;
use actix_web_actors::ws;

pub mod models;
use models::{HttpError, RDFSchemaUpper, ThumbnailCache, PROCESS_QUEUE, THUMBNAIL_CACHE};

struct ConversionActor;

impl Actor for ConversionActor {
    type Context = ws::WebsocketContext<Self>;
}

// async fn qued_pdf_to_docx(
//     pdf_path: String,
//     docx_path: String,
//     semaphore: async_weighted_semaphore::SemaphoreGuardArc,
//     // actor: &mut ConversionActor
//     // tx: std::sync::mpsc::Sender<bool>,
// ) -> std::result::Result<(), std::io::Error> {
//     info!("pdf path :{pdf_path}\t docx path: {docx_path}");
//     let mut child = std::process::Command::new("python")
//         .arg("./pdf2docx/use.py")
//         .arg(&pdf_path)
//         .arg(&docx_path)
//         .stdout(std::process::Stdio::piped())
//         .spawn()?;

//     let exit_status = child.wait().unwrap();

//     if !exit_status.success() {
//         error!("Error occured at pdf_to_docx conversion: {exit_status}");

//         remove_file(&[&pdf_path]);

//         // tx.send(false).unwrap();
//         drop(semaphore);

//         Ok(())
//     } else {
//         let mut headers = HeaderMap::new();

//         headers.insert(
//             actix_http::header::CONTENT_TYPE,
//             HeaderValue::from_str("text/turtle").unwrap(),
//         );

//         // tx.send(true).unwrap();

//         drop(semaphore);

//         Ok(())
//     }
// }

impl StreamHandler<Result<ws::Message, ws::ProtocolError>> for ConversionActor {
    fn handle(&mut self, msg: Result<ws::Message, ws::ProtocolError>, ctx: &mut Self::Context) {
        match msg {
            Ok(ws::Message::Ping(msg)) => ctx.pong(&msg),
            Ok(ws::Message::Text(text)) => ctx.text(text),
            Ok(ws::Message::Binary(bin)) => {
                let fut = async move {
                    let timestamp = std::time::SystemTime::now()
                        .duration_since(std::time::SystemTime::UNIX_EPOCH)
                        .unwrap()
                        .as_secs();

                    info!("here");
                    let pdf_path = format!("upload/{}{}", timestamp, ".pdf");
                    let pdf_thumbnail_path = format!("upload/thumbnails/{}{}", timestamp, ".png");
                    let docx_path = format!("./converted/{}{}", timestamp, ".docx");
                    let dataset_name = format!("{}{}", timestamp, ".ttl");
                    let dataset_path = format!("datasets/nsw/{dataset_name}");
                    let graph_name =
                        format!("{}{}", "https://surroundaustralia.com/graph/", timestamp);

                    std::fs::write(&pdf_path, &bin).unwrap();

                    let mut absolte_conversion_location = std::env::current_dir()
                        .unwrap()
                        .join("converted/")
                        .display()
                        .to_string();

                    absolte_conversion_location.push_str(&(timestamp.to_string() + ".docx"));

                    let config_string = ConfigSchema {
                        location: &absolte_conversion_location,
                        label: "Minimal Doc",
                        slug: timestamp,
                        doc_id_for_hashing: "minidoc",
                        jurisdiction: "nsw",
                    };

                    let config_string = serde_json::to_string_pretty(&config_string).unwrap();

                    let config_location = format!(
                        "./semantic-extractor-of-documents/configs/{}{}",
                        timestamp, ".json"
                    );

                    tokio::fs::write(&config_location, config_string)
                        .await
                        .expect("Error creating config file");

                    let file_location = format!("./converted/{}{}", timestamp, ".docx");

                    let paths = FileData {
                        pdf_path,
                        docx_path,
                    };
                    pdf_to_docx(
                        paths,
                        dataset_path,
                        graph_name,
                        pdf_thumbnail_path,
                        config_location,
                        file_location,
                    )
                    .await
                };
                let fut = actix::fut::wrap_future::<_, Self>(fut);
                fut.map(|result, _actor, ctx| match result {
                    Ok(_) => {
                        ctx.text("success");
                        info!("Success Response Sent to Client");
                    }
                    Err(_) => {
                        ctx.text("error");
                        info!("Error Response Sent to Client");
                    }
                })
                .spawn(ctx);
                ctx.text("starting conversion");
            }
            _ => println!("other {:?}", msg.unwrap()),
        }
    }
}

#[get("/ws")]
async fn conversion_handler(req: HttpRequest, stream: web::Payload) -> Result<HttpResponse> {
    let resp = ws::WsResponseBuilder::new(ConversionActor {}, &req, stream)
        .frame_size(104857600)
        .start();
    info!("{:?}", resp);
    resp
}

#[get("/")]
async fn index(_req: HttpRequest) -> Redirect {
    Redirect::to("./src/index.html")
}

#[get("/list")]
async fn upload_list() -> Result<impl Responder, HttpError> {
    let thumbnail_list = std::fs::read_dir("./upload/thumbnails")
        .unwrap()
        .map(|dir| dir.unwrap().path().to_str().unwrap().to_string())
        .collect();

    let list = ListJson {
        item: thumbnail_list,
    };

    Ok::<std::string::String, HttpError>(serde_json::to_string(&list)?)
}

#[get("/thumbnails/{id}")]
async fn thumbnails(
    req: HttpRequest,
    path: web::Path<String>,
) -> impl Responder {
    use actix_web::http::header::ContentType;
    let response_body = THUMBNAIL_CACHE.get().unwrap().read().await;

    let response_body: Vec<Vec<_>> = response_body
        .iter()
        .map(|thumbnail| {
            thumbnail
                .items
                .iter()
                .filter(|item| {
                    item.path.clone() == "upload/thumbnails/".to_string() + &path.to_string()
                })
                .collect()
        })
        .collect();

    let mut response_vec = Vec::new();
    response_body.into_iter().for_each(|item| {
        item.into_iter().for_each(|item| {
            match item.contents.is_empty() {
                false => {
                    let mut response = HttpResponse::Ok();
                    response.insert_header(ContentType::png());
                    response_vec.push(response.body(item.contents.clone()));
                }
                true => {
                    let response = HttpResponse::NotFound();
                    response_vec.push(response.respond_to(&req))
                }
            };
        });
    });
    response_vec.pop()
}

async fn empty_cache(file: &str) {
    let mut write_lock = THUMBNAIL_CACHE.get().unwrap().write().await;
    let index_val: usize = write_lock
        .iter()
        .position(|items| {
            items
                .items
                .iter()
                .any(|items| items.path == "upload/thumbnails/".to_owned() + file + ".png")
        })
        .unwrap();

    write_lock.remove(index_val);
}

#[post("/view")]
async fn serve_rdf<'a>(data: web::Form<Index>) -> Result<impl Responder> {
    use port_killer::kill;
    use sysinfo::{ProcessExt, System, SystemExt};

    let sys = System::new();

    let mut response = HttpResponse::Ok();

    kill(8080).expect("Nothing running on port 8080");

    if sys.processes_by_name("rickview").count() > 0 {
        sys.processes_by_name("rickview").for_each(|server| {
            server.tasks.iter().for_each(|task| {
                sys.process(task.0.to_owned()).unwrap().kill();
            });
            server.kill();
        });
    };

    let mut local_index: i32 = 0;
    let val = Index {
        index: data.index.clone(),
    };

    match val.index.parse::<i32>() {
        Ok(val) => local_index += val,
        Err(e) => {
            error!(
                "Couldn't parse string to i32, where string is {}. {e}",
                data.index
            );
            response.insert_header(("Location", "/augment.html?failure"));
            return Ok(response.status(StatusCode::SEE_OTHER).finish());
        }
    };
    async {
        match RickViewConfig::serialize(local_index) {
            Ok(_) => {
                std::env::set_current_dir("./RickView/bin")
                    .map(async move |_result| -> std::result::Result<(), HttpError> {
                        tokio::process::Command::new("rdf2hdt")
                            .arg("./data/surroundaustralia/example.ttl")
                            .arg("./data/surroundaustralia/example.hdt")
                            .status()
                            .await?;

                        while tokio::process::Command::new("./rickview")
                            .stdout(std::process::Stdio::piped())
                            .spawn()?
                            .stdout
                            .is_none()
                        {
                            std::thread::sleep(std::time::Duration::from_millis(30));
                        }
                        Ok(())
                    })?
                    .await?;

                std::env::set_current_dir(
                    std::env::current_exe().unwrap().ancestors().nth(3).unwrap(),
                )?;

                response.status(StatusCode::SEE_OTHER);
                response.insert_header(("Location", "/augment.html?success"));
                Ok(response.finish())
            }
            Err(_) => {
                response.status(StatusCode::UNPROCESSABLE_ENTITY);
                response.status(StatusCode::SEE_OTHER);
                response.insert_header(("Location", "/augment.html?failure"));
                Ok(response.finish())
            }
        }
    }
    .await
}

#[get("/pdf/{id}")]
async fn pdf(path: web::Path<String>) -> Result<impl Responder> {
    use actix_web::http::header::ContentType;

    let binding = format!("./upload/{path}.pdf");

    let pdf_path = std::path::Path::new(&binding).to_owned();

    std::fs::metadata(&pdf_path)?;

    let pdf_file = tokio::fs::read(&pdf_path).await?;

    Ok(HttpResponse::Ok()
        .content_type(ContentType(mime_guess::mime::APPLICATION_PDF))
        .status(StatusCode::OK)
        .body(pdf_file))
}

#[get("/{path:.*}")]
async fn static_files(
    req: HttpRequest,
    path: web::Path<String>,
) -> Result<impl Responder, HttpError> {
    use rand::prelude::*;
    use tokio::io::*;

    let mut path = path.clone();

    match path.as_str() {
        "augment.html" | "favicon.ico" => path = "./src/".to_owned() + &path,
        "sparql" => path = "./src/sparql.html".to_owned(),
        _ => (),
    }

    let path_for_ext = path.to_string();
    let extension = path_for_ext
        .split('.')
        .last()
        .ok_or_else(|| HttpError::Io {
            source: std::io::Error::new(ErrorKind::InvalidData, "Invalid Address"),
        })?;

    let mime = mime_guess::from_ext(extension)
        .first()
        .ok_or_else(|| HttpError::Io {
            source: std::io::Error::new(ErrorKind::InvalidFilename, "Invalid Filename"),
        })?;

    let mut buffer: Vec<_> = if extension == "html" {
        tokio::fs::read("./src/navbar.html")
            .await?
            .into_iter()
            .chain(std::fs::read(path.as_str())?.into_iter())
            .collect()
    } else {
        std::fs::read(path.as_str())?
    };

    if path.as_str() == "./src/augment.html" {
        // let upload_path = std::path::Path::new("./upload").read_dir().unwrap();
        let upload_path = std::fs::read_dir("./upload")?;

        match upload_path.into_iter().count() > 1 {
            true => {
                let mut internal_buffer = Vec::new();
                let mut file = tokio::io::BufReader::new(
                    tokio::fs::File::open("./src/augment-file-present.html").await?,
                );
                file.read_to_end(&mut internal_buffer).await?;
                let file = String::from_utf8(internal_buffer)?;
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
                let rand_file = file_paths.first().unwrap();
                let parent = rand_file.parent().unwrap().display();
                let file = file
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
                for bytes in file {
                    buffer.push(bytes)
                }
            }
            false => {
                let mut file = tokio::io::BufReader::new(
                    tokio::fs::File::open("./src/drag-and-drop.html").await?,
                );
                file.read_to_end(&mut buffer).await?;

                let mut file = tokio::io::BufReader::new(
                    tokio::fs::File::open("./src/augment-none.html").await?,
                );
                file.read_to_end(&mut buffer).await?;
            }
        }
    }
    let mut response = HttpResponse::Ok();
    response
        .insert_header((
            "Content-Type",
            (mime.to_string() + &';'.to_string() + " charset=utf-8"),
        ))
        .insert_header((
            actix_http::header::CACHE_CONTROL,
            actix_http::header::HeaderValue::from_static("no-cache"),
        ));
    Ok(response.body(buffer).respond_to(&req))
}

// #[post("/submit")]
// async fn upload(
//     MultipartForm(form_data): MultipartForm<UploadForm>,
// ) -> Result<impl Responder, HttpError> {
//     let timestamp = std::time::SystemTime::now()
//         .duration_since(std::time::SystemTime::UNIX_EPOCH)
//         .unwrap()
//         .as_secs();

//     let pdf_path = format!("upload/{}{}", timestamp, ".pdf");
//     let pdf_thumbnail_path = format!("upload/thumbnails/{}{}", timestamp, ".png");
//     let docx_path = format!("./converted/{}{}", timestamp, ".docx");
//     let dataset_name = format!("{}{}", timestamp, ".ttl");
//     let dataset_path = format!("datasets/nsw/{dataset_name}");
//     let graph_name = format!("{}{}", "https://surroundaustralia.com/graph/", timestamp);

//     for files in form_data.files.into_iter() {
//         match files.content_type.unwrap() != mime_guess::mime::APPLICATION_PDF {
//             true => return Ok(Redirect::to("/augment.html?failure").see_other()),
//             false => (),
//         };

//         files.file.persist(pdf_path.clone()).unwrap();
//     }

//     let mut absolte_conversion_location = std::env::current_dir()?
//         .join("converted/")
//         .display()
//         .to_string();

//     absolte_conversion_location.push_str(&(timestamp.to_string() + ".docx"));

//     let config_string = ConfigSchema {
//         location: &absolte_conversion_location,
//         label: "Minimal Doc",
//         slug: timestamp,
//         doc_id_for_hashing: "minidoc",
//         jurisdiction: "nsw",
//     };

//     let config_string = serde_json::to_string_pretty(&config_string)?;

//     let config_location = format!(
//         "./semantic-extractor-of-documents/configs/{}{}",
//         timestamp, ".json"
//     );

//     tokio::fs::write(&config_location, config_string)
//         .await
//         .expect("Error creating config file");

//     let file_location = format!("./converted/{}{}", timestamp, ".docx");
//     let (tx, mut rx) = tokio::sync::mpsc::channel(1);

//     let paths = FileData {
//         pdf_path,
//         docx_path,
//     };

//     tokio::spawn(async move {
//         pdf_to_docx(
//             paths,
//             dataset_path,
//             graph_name,
//             pdf_thumbnail_path,
//             config_location,
//             file_location,
//             tx, // semaphore,
//         )
//         .await
//     });

//     match rx.recv().await {
//         Some(boolean) => match boolean {
//             true => Ok(Redirect::to("/augment.html?success").see_other()),
//             false => Ok(Redirect::to("/augment.html?failure").see_other()),
//         },
//         None => Err(HttpError::ChannelClosed),
//     }
// }

#[post("/remove/{file}")]
/// This function is intended to remove very specific server-side injested files.
async fn remove(
    file: web::Path<String>,
    // thumbnail_cache: web::Data<std::sync::Arc<tokio::sync::RwLock<Vec<ThumbnailCache>>>>,
) -> Redirect {
    let vec = [
        "./upload/".to_owned() + &file + ".pdf",
        "./datasets/nsw/".to_owned() + &file + ".ttl",
        "./datasets/manifests/prov-".to_owned() + &file + ".ttl",
        "./converted/".to_owned() + &file + ".docx",
        "./upload/thumbnails/".to_owned() + &file + ".png",
    ];

    vec.into_iter()
        .filter(|file| std::path::Path::exists(std::path::Path::new(file)))
        .for_each(|file| match std::fs::remove_file(&file) {
            Ok(_) => info!("Successfully deleted {file}"),
            Err(e) => warn!("Error occured at remove file: {e}"),
        });

    empty_cache(&file).await;
    Redirect::to("/augment.html?removed").see_other()
}

async fn create_thumbnail(
    pdf_path: &std::path::Path,
    out_path: &std::path::Path,
    // thumbnail_cache: web::Data<std::sync::Arc<tokio::sync::RwLock<Vec<ThumbnailCache>>>>,
) -> std::result::Result<(), HttpError> {
    use cairo::{Format, ImageSurface};
    use poppler::PopplerDocument;
    {
        let doc = PopplerDocument::new_from_file(pdf_path, "").unwrap();

        let page = doc.get_page(0).ok_or(std::io::Error::new(
            ErrorKind::InvalidData,
            "Invalid Pdf for conversion",
        ))?;

        let input_dimensions = page.get_size();
        let output_dimensions = (input_dimensions.0 / 5.0, input_dimensions.1 / 5.0);
        let surface = ImageSurface::create(
            Format::Rgb24,
            output_dimensions.0 as i32,
            output_dimensions.1 as i32,
        )?;
        // surface.set_device_scale(0.07, 0.1);
        let ctxt = cairo::Context::new(&surface)?;
        ctxt.scale(
            output_dimensions.0 / input_dimensions.0,
            output_dimensions.1 / input_dimensions.1,
        );
        ctxt.set_source_surface(&surface, 0.0, 0.0)?;
        ctxt.set_source_rgb(1.0, 1.0, 1.0);
        ctxt.paint()?;
        page.render(&ctxt);

        let mut f = std::fs::File::create(out_path)?;
        surface.write_to_png(&mut f)?;
    }

    THUMBNAIL_CACHE
        .get()
        .unwrap()
        .write()
        .await
        .push(ThumbnailCache {
            items: {
                vec![ThumbnailCacheInner {
                    path: out_path.to_str().unwrap().to_string(),
                    contents: tokio::fs::read(out_path).await?,
                }]
            },
        });

    Ok(())
}

async fn absorb_with_graph(
    headers: Option<&HeaderMap>,
    data: Option<web::Payload>,
    graph: Option<&str>,
    file: Option<&str>,
) -> std::result::Result<String, HttpError> {
    if let Some(header) = headers && data.is_some() {
        match header.get("Content-Type").unwrap().to_str().unwrap() {
            "*/*" => Ok(
                format!(
                    "{}{:?}",
                    "Content-Type Header Not Returned",
                    header.get("Accept")
                )
            ),
            _ => {
                Ok(external_curl(headers, data, graph, None).await?)
            }
        }
    } else {
        match graph.is_some() && file.is_some() {
            true => {
                // let future = Box::pin(external_curl(headers, None, graph, file));
            Ok(external_curl(headers, None, graph, file).await?)
            }
            false => Err(Error::new(
                ErrorKind::Unsupported,
                "Parameters for post request are not satisfied.",
            ))
            ?,
        }
    }
}

async fn docx_to_rdf(
    config_location: &str,
    file_name: &str,
) -> std::result::Result<(), std::io::Error> {
    let output = tokio::process::Command::new("python")
        .arg("./semantic-extractor-of-documents/semext.py")
        .arg("-c")
        .arg(config_location)
        .arg("-o")
        .arg("./datasets/")
        .arg("-p")
        .arg("./datasets/manifests/")
        .status()
        .await?;

    if !output.success() {
        let file_prefix = config_location
            .split('/')
            .last()
            .unwrap()
            .split('.')
            .next()
            .unwrap();

        let docx_location = format!("./converted/{file_prefix}.docx");
        let pdf_location = format!("./upload/{file_prefix}.pdf");

        let file_locations = [
            pdf_location.as_str(),
            docx_location.as_str(),
            config_location,
        ];

        error!("Error occured at docx to rdf conversion: {output}");

        remove_file(&file_locations);

        Err(Error::new(ErrorKind::InvalidData, output.to_string()))?
    } else {
        Ok(info!("Successful conversion of {file_name} to a graph"))
    }
}

#[post("/sparql")]
async fn api(headers: HttpRequest, data: web::Payload) -> std::result::Result<String, HttpError> {
    // let accept = headers.headers.keys();
    match headers.headers().get("Accept").unwrap().to_str().unwrap() {
        "*/*" => {
            format!(
                "{}{:?}",
                "Accept Header Not Returned",
                headers.headers().get("Accept")
            );
            match headers
                .headers()
                .get("Content-Type")
                .unwrap()
                .to_str()
                .unwrap()
            {
                "*/*" => Ok(format!(
                    "{}{:?}",
                    "Content-Type Header Not Returned",
                    headers.headers().get("Accept")
                )),
                _ => Ok("Content-Type Header returned".to_owned()),
            }
        }
        _ => Ok(external_curl(Some(headers.headers()), Some(data), None, None).await?),
    }
}

#[post("/sparql/absorb")]
async fn absorb(headers: HttpRequest, data: web::Payload) -> Result<impl Responder, HttpError> {
    absorb_with_graph(Some(headers.headers()), Some(data), Some("default"), None).await
}

async fn external_curl<'a>(
    headers: Option<&HeaderMap>,
    mut data: Option<web::Payload>,
    graph_name: Option<&str>,
    file_name: Option<&str>,
) -> std::result::Result<String, HttpError> {
    use futures::StreamExt;
    start_graph_db().await.expect("Critical Server-side Error: Checking the service status of the graph and starting it has failed.");
    let mut post_request_url = String::new();
    if graph_name.is_some() {
        match graph_name.unwrap() {
            "default" => post_request_url += "http://localhost:7878/store?default",
            _ => {
                post_request_url += &format!(
                    "{}{}",
                    "http://localhost:7878/store?graph=",
                    graph_name.unwrap()
                );
            }
        }
    } else {
        post_request_url += "http://localhost:7878/query?default";
    }
    let mut client = Client::new().post(post_request_url);

    let buffer = match file_name.is_some() {
        true => {
            let file_path = std::env::current_dir()
                .unwrap()
                .join(file_name.as_ref().unwrap());
            tokio::fs::read(file_path.display().to_string()).await?
        }
        false => {
            let mut bytes_vec = web::BytesMut::new();
            while let Some(bytes) = data.as_mut().unwrap().next().await {
                let bytes = bytes?;
                bytes_vec.extend_from_slice(&bytes);
            }
            bytes_vec.to_vec()
        }
    };

    let headers = headers.expect("Headers not sent");
    headers
        .into_iter()
        .for_each(|(header, content)| client = client.try_clone().unwrap().header(header, content));

    let result = client.body(String::from_utf8(buffer)?).send().await?;

    if graph_name.is_some() {
        Ok(result.text().await?)
    } else {
        let result = result.json::<RDFSchemaUpper>().await?;
        Ok(serde_json::to_string_pretty(&result).unwrap() + &'\n'.to_string())
    }
}

async fn start_graph_db() -> std::result::Result<(), std::io::Error> {
    use sysinfo::{System, SystemExt};

    let sys = System::new_all();

    let process = sys.processes_by_name("oxigraph_server");

    if process.count() > 0 {
        Ok(info!("\n"))
    } else {
        std::env::set_current_dir("./server/oxigraph/bin").unwrap();
        let command = "./oxigraph_server --location ./graph-data serve";
        match tokio::process::Command::new("sh")
            .arg("-c")
            .arg(command)
            .spawn()
        {
            Ok(output) => {
                set_env();
                Ok(info!(
                    "{}{}",
                    "Command started successfully with ID:",
                    output.id().unwrap()
                ))
            }
            Err(e) => {
                set_env();
                Err(Error::new(
                    ErrorKind::ConnectionAborted,
                    format!("Command failed to start: {e}"),
                ))
            }
        }
    }
}

async fn pdf_to_docx(
    paths: FileData,
    dataset_path: String,
    graph_name: String,
    pdf_thumbnail_path: String,
    config_location: String,
    file_location: String,
) -> std::result::Result<(), HttpError> {
    tokio::spawn(async move {
        let (tx, mut rx) = tokio::sync::mpsc::channel::<Option<std::process::ExitStatusError>>(1);

        let semaphore = std::sync::Arc::new(SEMAPHORE.acquire(1).await.unwrap());

        let pdf_path = paths.pdf_path.clone();

        PROCESS_QUEUE
            .write()
            .await
            .push(models::Process {
                paths,
                sender: tx, // dataset_path,
                semaphore,  // pdf_thumbnail_path,
            })
            .await;

        match rx.recv().await.ok_or_else(|| HttpError::ChannelClosed)? {
            // ExitStatus => {
            None => match docx_to_rdf(&config_location, &file_location).await {
                Ok(_) => {
                    let mut headers = HeaderMap::new();
                    headers.insert(
                        actix_http::header::CONTENT_TYPE,
                        HeaderValue::from_str("text/turtle").unwrap(),
                    );
                    tokio::task::LocalSet::new().spawn_local(async move {
                        absorb_with_graph(
                            Some(&headers),
                            None,
                            Some(&graph_name),
                            Some(&dataset_path),
                        )
                        .await
                        .unwrap();
                    });
                    info!("Creating Thumbnail");
                    create_thumbnail(
                        std::path::Path::new(&pdf_path),
                        std::path::Path::new(&pdf_thumbnail_path),
                    )
                    .await?;
                    Ok(())
                    // sender.send(true).await.unwrap();
                }
                Err(_) => {
                    empty_cache(&pdf_thumbnail_path).await;
                    Err(HttpError::ChannelClosed)
                }
            },
            Some(e) => Err(HttpError::Syscall { source: e }),
            // sender.send(false).await.unwrap(),
        }
    })
    .await
    .unwrap()
}

fn remove_file(paths: &[&str]) {
    for path in paths.iter() {
        match std::fs::remove_file(path) {
            Ok(_) => info!("Successfully deleted the file at: {path}"),
            Err(e) => info!("Error occured at remove: {e}"),
        }
    }
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    use actix_multipart::form::MultipartFormConfig;
    use actix_web::middleware::{Logger, NormalizePath};
    use port_killer::kill;
    set_env();

    kill(8000).expect("Starting Actix");

    kill(7878).expect("Starting Oxigraph");

    lazy_static::initialize(&PROCESS_QUEUE);

    THUMBNAIL_CACHE.get_or_init(models::init_cache).await;

    start_graph_db().await.unwrap();

    env_logger::init_from_env(env_logger::Env::new().default_filter_or("debug"));

    HttpServer::new(move || {
        App::new()
            .app_data(TempFileConfig::default().directory("./upload"))
            .app_data(
                MultipartFormConfig::default()
                    .total_limit(52_00000)
                    .memory_limit(52_00000),
            )
            .wrap(Logger::new("%r %U").log_target("actix"))
            .wrap(NormalizePath::new(
                actix_web::middleware::TrailingSlash::Trim,
            ))
            .service(serve_rdf)
            .service(conversion_handler)
            .service(api)
            .service(absorb)
            .service(remove)
            .service(index)
            .service(pdf)
            // .service(upload)
            .service(
                web::scope("/upload")
                    .service(upload_list)
                    .service(thumbnails),
            )
            .service(static_files)
    })
    .workers(4)
    .bind(("127.0.0.1", 8000))?
    .run()
    .await
}

fn set_env() {
    std::env::set_current_dir(std::env::current_exe().unwrap().ancestors().nth(3).unwrap())
        .unwrap();
}

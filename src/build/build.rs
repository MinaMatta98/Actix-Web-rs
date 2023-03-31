#![feature(fn_traits)]
use git2::Repository;
use pkg_config::Config;
use reqwest::Client;
use std::process::Command;
use std::{env::current_dir, io::Write};
use sysinfo::{ProcessExt, System, SystemExt};
use zip::ZipArchive;

pub struct Dependancies<'a> {
    pub path: &'a str,
    pub url: &'a str,
    pub name: &'a str,
}

fn main() -> std::result::Result<(), std::io::Error> {
    // println!("cargo:rerun-if-changed=/lib/libpoppler.so");
    // println!("cargo:rerun-if-changed=./pdf2docx")
    // format!("cargo:rerun-if-changed=./server");
    // println!("cargo:rerun-if-changed=\"build_rs/build.rs\"");
    set_env();

    pull_git_dependancy(
        "./pdf2docx/",
        "https://github.com/dothinking/pdf2docx.git",
        "pdf2docx",
        Some(|| {
            set_env();
            std::env::set_current_dir("./pdf2docx/").unwrap();
            // println!("Installing python dependancies via pip");
            Command::new("pip3")
                .arg("install")
                .arg("-r")
                .arg("requirements.txt")
                .status()
                .unwrap();
            std::env::set_current_dir("../").unwrap();

            let use_py = "
                        from pdf2docx import Converter
                        import os
                        import sys
                        pdf_input_path = sys.argv[1]
                        docx_output_path = sys.argv[2]
                        pdf_file = f\"{os.getcwd()}/{pdf_input_path}\"
                        docx_file = f\"{os.getcwd()}/{docx_output_path}\"
                        # convert pdf to docx
                        cv = Converter(pdf_file)
                        try:
                        \tcv.convert(docx_file, multi_processing=True)  # all pages by default
                        except Exception as e:
                        \tprint(\"An error occurred:\", str(e))
                        \tcv.close()
                        \tsys.exit(1)
                        else:
                        \tprint(\"Success\")
                        \tcv.close()
                        \tsys.exit(0)";
            let mut file_string = String::new();
            for line in use_py.lines() {
                if line.contains('\t') {
                    file_string.push_str(&("    ".to_string() + line.trim() + &'\n'.to_string()))
                } else {
                    file_string.push_str(&(line.trim().to_string() + &'\n'.to_string()))
                }
            }
            std::fs::write("./pdf2docx/use.py", file_string).unwrap();
        }),
    )
    .unwrap();

    let config = Config::new();
    match config.probe("poppler") {
        Ok(_) => (),
        // println!("Poppler found at {:?}", poppler),
        Err(_) => {
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap();
            match runtime.block_on(get_ext_deps(
                "https://poppler.freedesktop.org/poppler-21.12.0.tar.xz",
                "./poppler-21.12.0",
                "poppler",
            )) {
                Ok(runtime) => Ok(runtime),
                Err(e) => Err(e),
            }
            .unwrap();
        }
    }
    match config.probe("rdf2hdt") {
        Ok(_) => println!("C++ HDT Library Found"),
        Err(_) => {
            pull_git_dependancy(
                "./hdt-cpp/",
                "https://github.com/rdfhdt/hdt-cpp",
                "hdt-cpp",
                Some(|| {
                    set_env();
                    std::env::set_current_dir("./hdt-cpp/")
                        .map(|_dir| {
                            let command_vec = vec!["./autogen.sh", "./configure"];
                            for command in command_vec {
                                Command::new(command).output().unwrap();
                            }
                            let command_vec = vec!["make -j2", "make install"];

                            for command in command_vec {
                                let command_vec: Vec<&str> = command.split_whitespace().collect();
                                println!("running {}", command_vec[0]);
                                Command::new(command_vec[0])
                                    .arg(command_vec[1])
                                    .output()
                                    .unwrap();
                            }

                            std::env::set_current_dir("../").unwrap();
                        })
                        .unwrap();
                }),
            )
            .unwrap();
        }
    }

    match check_server_presence(
        "./server/oxigraph",
        "cd ./server/oxigraph/bin/ && ./oxigraph_server --location ./graph-data serve",
        "Oxigraph",
        "oxigraph_server",
    ) {
        Ok(success) => success,
        Err(e) => return Err(e),
    };

    match check_server_presence(
        "./RickView",
        "cd ./RickView/bin/ && ./rickview",
        "RickView",
        "rickview",
    ) {
        Ok(success) => success,
        Err(e) => return Err(e),
    };

    // Bootstrap
    let dependancies = vec![Dependancies {
        path: "./src/bootstrap-5.2.3-dist/",
        url: "https://github.com/twbs/bootstrap/releases/download/v5.2.3/bootstrap-5.2.3-dist.zip",
        name: "Bootstrap",
    },
    // Font-awesome Icons
    Dependancies {
        path: "/src/fontawesome-free-6.2.1-web/",
        url: "https://use.fontawesome.com/releases/v6.2.1/fontawesome-free-6.2.1-web.zip",
        name: "Fontawesome-Icons",
    }];

    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();

    dependancies.iter().for_each(|depenancy| {
        // println!("Retrieving {}", depenancy.name);
        match runtime.block_on(check_path(depenancy.path, depenancy.url, depenancy.name)) {
            Ok(runtime) => Ok(runtime),
            Err(e) => Err(e),
        }
        .unwrap();
    });
    create_directories().unwrap();
    Ok(())
}

fn pull_git_dependancy(
    path: &str,
    url: &str,
    _name: &str,
    function: Option<fn()>,
) -> Result<(), git2::Error> {
    let path = std::path::Path::new(path);
    match std::path::Path::exists(path) {
        true => Ok(()),
        false => {
            // println!("Currently fetching external dependancy: {}", name);
            match Repository::clone(url, path) {
                Ok(_) => {
                    function.unwrap().call(());
                    Ok(())
                }
                Err(e) => Err(e),
            }
        }
    }
}

fn check_server_presence(
    folder: &str,
    _command: &str,
    process_name: &str,
    installation_name: &str,
) -> Result<(), std::io::Error> {
    let server_path = std::path::Path::new(folder);
    match std::path::Path::exists(server_path) {
        true => {
            println!(
                "{} Server present at: {}",
                &process_name,
                &server_path.display()
            );
            let sys = System::new_all();
            let process = sys.processes_by_name(installation_name);
            if process.count() > 0 {
                sys.processes_by_name(installation_name)
                    .for_each(|process| {
                        println!("Killing {process_name} Server.");
                        process.kill();
                    });
            };
            Ok(())

            // match Command::new("sh").arg("-c").arg(command).spawn() {
            //     Ok(child) => Ok({
            //         println!("Starting {process_name} Server with PID: {:?}", child.id());
            //     }),
            //     Err(e) => return Err(e),
            // }
        }
        false => {
            println!("Retrieving {process_name} Server");
            Command::new("cargo")
                .arg("install")
                .arg("--root")
                .arg(folder)
                .arg(installation_name)
                .spawn()
                .unwrap()
                .wait()
                .unwrap();
            Ok(())
        }
    }
}

async fn check_path(path: &str, url: &str, _name: &str) -> Result<(), std::io::Error> {
    let path = std::path::Path::new(path);

    match std::path::Path::exists(path) {
        true => Ok(()),
        // Ok(println!("{name} present in application directory")),
        false => {
            let mut response = tokio::spawn(Client::new().get(url).send().await.unwrap().bytes())
                .await
                .unwrap();

            let result_binary: Vec<_> = response.as_mut().unwrap().clone().into_iter().collect();

            let file_path = "./src/".to_string()
                + path
                    .to_str()
                    .unwrap()
                    .to_string()
                    .split('/')
                    .nth(2)
                    .unwrap()
                + ".zip";

            let file_path = std::path::Path::new(&file_path);
            let mut file = std::fs::File::create(file_path).unwrap();
            std::fs::File::write_all(&mut file, &result_binary).and_then(move |_| {
                let file = std::fs::File::open(file_path).unwrap();
                Ok(ZipArchive::new(file))
                    .map(|archive| {
                        // println!("Extracting {name} into {:?}", path);
                        archive
                            .unwrap()
                            .extract(path.to_str().unwrap().split('/').nth(1).unwrap())
                    })
                    .and_then(|_result| std::fs::remove_file(file_path))
            })
        }
    }
}

fn create_directories() -> std::io::Result<()> {
    set_env();
    let dir_path = vec![
        "./datasets/",
        "./datasets/nsw",
        "./datasets/nsw/edg",
        "./upload",
        "./upload/thumbnails",
        "./converted/",
        "./semantic-extractor-of-documents/configs",
        "./RickView/bin/data/",
        "./RickView/bin/data/surroundaustralia",
    ];

    let new_dirs: Vec<_> = dir_path
        .iter()
        .filter(|path| match !std::path::Path::new(path).exists() {
            false => {
                // println!("Directory exists: {}", path);
                false
            }
            true => true,
        })
        .collect();

    new_dirs
        .iter()
        .for_each(|dir| match std::fs::create_dir(dir) {
            Ok(_) => println!("Directory created: {dir}"),
            Err(e) => Err(e).unwrap(),
        });

    Ok(())
}

pub fn set_env() {
    // println!("{:?}", std::env::current_exe().unwrap().ancestors().nth(5));
    std::env::set_current_dir(std::env::current_exe().unwrap().ancestors().nth(5).unwrap())
        .unwrap_or_else(|_dir| {
            std::env::set_current_dir(
                std::env::current_exe()
                    .unwrap()
                    .to_str()
                    .unwrap()
                    .strip_suffix("/target/debug/my_project")
                    .unwrap(),
            )
            .unwrap()
        });
}

async fn get_ext_deps(
    url: &str,
    path: &str,
    name: &str,
) -> std::result::Result<(), std::io::Error> {
    let mut response = tokio::spawn(Client::new().get(url).send().await.unwrap().bytes())
        .await
        .unwrap();

    let result_binary: Vec<_> = response.as_mut().unwrap().clone().into_iter().collect();

    let file_path = path.to_owned() + ".tar.xz";

    let file_path = std::path::Path::new(&file_path);
    let mut file = std::fs::File::create(file_path).unwrap();
    std::fs::File::write_all(&mut file, &result_binary)
        .map(move |_| {
            // let file = std::fs::File::open(file_path).unwrap();
            decompress::decompress(
                file_path,
                std::path::Path::new("."),
                &decompress::ExtractOpts::default(),
            )
            .unwrap();

            {
                std::env::set_current_dir(path).unwrap();
                std::fs::create_dir(current_dir().unwrap().to_str().unwrap().to_owned() + "/build")
                    .unwrap();
                std::env::set_current_dir("build").unwrap();

                std::process::Command::new("cmake")
                    .arg("..")
                    .spawn()
                    .unwrap()
                    .wait()
                    .map(|_child| std::process::Command::new("make").spawn().unwrap().wait())
                    .map(|_child| {
                        std::process::Command::new("make")
                            .arg("install")
                            .spawn()
                            .unwrap()
                            .wait()
                            .unwrap();
                        set_env()
                    })
            }
        })
        .unwrap()
        .unwrap_or_else(|_| panic!("failed to install {name}"));
    std::fs::remove_file(file_path)
}

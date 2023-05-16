# Readme

This is a web server built with the Actix Web Framework for Rust. It serves HTML files with an included navbar, as well as other types of files such as PDFs and images. It also includes routes for handling file deletion and redirecting to a "permission denied" page.

You can run the server with the command:

`
cargo run --release
`

# Dependancies
This repository is self building, for all but one dependancy, poppler and poppler-glib. However, there is still reliance on C++ headers and gcc/g++/msvc. To install these dependancies on Ubuntu, run the following terminal command:
```
sudo apt-get update

sudo apt-get install -y g++ autoconf libnss3-dev make build-essential \
cmake libcairo2-dev libjpeg-dev libpng-dev libtiff-dev libfontconfig1-dev \
pkg-config libglib2.0-dev libnss3 libgif-dev libblkid-dev e2fslibs-dev \
libboost-all-dev libaudit-dev libpoppler-dev libpoppler-glib8
```
N.B: If you run a non Debian based distribution, you will need to swap `apt` out with your package manager, and also need to change the packages to match the package name of your distribution. For example, if you use Arch Linux, this would be `pacman` and `libpoppler-dev` would instead be called `poppler`.

# Features
This project delivers and utilizes the following RUST frameworks and libraries:

* [Actix-web](https://actix.rs/)
* [Tokio-RS](https://tokio.rs/)
* [Futures-rs](https://docs.rs/futures/)

In doing so, the project demonstrates implementing a back-end system with a schedular that can process two specialized requests at a time and push remaining requests to the end of the que. **Note that thousands of GET and POST requests can be processed per second**

This is achieved via tokio-runtimes, non-blocking semaphores and yielding back to the executor.

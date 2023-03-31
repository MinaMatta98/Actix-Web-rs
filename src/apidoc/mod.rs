use html_parser::Dom;
use okapi::openapi3::{MediaType, Responses};
use rocket_okapi::gen::OpenApiGenerator;
use rocket_okapi::response::OpenApiResponder;
use rocket_okapi::swagger_ui::SwaggerUIConfig;
use rocket_okapi::Result as OkapiResult;
pub mod models;
use models::*;

fn media_type(
    content_type: &str,
    file_location: &str,
    req_parser: bool,
    req_example: bool,
) -> MediaType {
    let mut media_type = MediaType {
        encoding: okapi::Map::new(),
        ..Default::default()
    };
    media_type.encoding.insert(
        "Content-Type".to_string(),
        okapi::openapi3::Encoding {
            content_type: Some(content_type.to_string()),
            ..Default::default()
        },
    );
    if req_example {
        let _ = media_type.example.insert(match req_parser {
            true => serde_json::from_str(
                &Dom::parse(&std::fs::read_to_string(file_location).unwrap())
                    .unwrap()
                    .to_json()
                    .unwrap(),
            )
            .unwrap(),
            false => {
                serde_json::from_str(&std::fs::read_to_string(file_location).unwrap()).unwrap()
            }
        });
    }
    media_type
}

impl<'a> OpenApiResponder<'a> for ServerResponse<'a> {
    fn responses(
        _generator: &mut rocket_okapi::gen::OpenApiGenerator,
    ) -> rocket_okapi::Result<okapi::openapi3::Responses> {
        use okapi::openapi3::{RefOr, Response as OpenApiReponse};

        let mut responses = okapi::Map::new();
        responses.insert(
            "404".to_string(),
            RefOr::Object(OpenApiReponse {
                description: "\
                A route that does not exist was requested.\
                "
                .to_string(),
                ..Default::default()
            }),
        );
        responses.insert(
            "403".to_string(),
            RefOr::Object(OpenApiReponse {
                description: "\
        This response is given when you request a source with inappropriate privileges. \
        "
                .to_string(),
                ..Default::default()
            }),
        );
        responses.insert(
            "200".to_string(),
            RefOr::Object(OpenApiReponse {
                description: "\
                File delivery endpoint subject to {file} route_string. \
                "
                .to_string(),
                content: {
                    let mut content_map = okapi::Map::new();
                    content_map.insert(
                        "text/html".to_string(),
                        media_type("text/html", "./src/index.html", true, true),
                    );
                    content_map.insert(
                        "text/css".to_string(),
                        media_type("text/css", "./static/container.json", false, true),
                    );
                    content_map.insert(
                        "application/javascript".to_string(),
                        media_type("application/javascript", "./static/drag.json", false, true),
                    );
                    content_map
                },
                ..Default::default()
            }),
        );
        Ok(okapi::openapi3::Responses {
            responses,
            ..Default::default()
        })
    }
}

impl<'a> OpenApiResponder<'a> for JsonText {
    fn responses(
        _generator: &mut rocket_okapi::gen::OpenApiGenerator,
    ) -> rocket_okapi::Result<okapi::openapi3::Responses> {
        use okapi::openapi3::{RefOr, Response as OpenApiReponse};

        let mut responses = okapi::Map::new();
        responses.insert(
            "411".to_string(),
            RefOr::Object(OpenApiReponse {
                description: "\
                Invalid Header formatting. Content-Type for querrying is generally 'application/sparql-query' and the Accept header 'application/sparql-results+json'.\
                "
                .to_string(),
                ..Default::default()
            }),
        );
        responses.insert(
            "403".to_string(),
            RefOr::Object(OpenApiReponse {
                description: "\
        This response is given when you request a source with inappropriate privileges. \
        "
                .to_string(),
                ..Default::default()
            }),
        );
        responses.insert(
            "200".to_string(),
            RefOr::Object(OpenApiReponse {
                description: "\
                File delivery endpoint subject to {file} route_string. \
                "
                .to_string(),
                content: {
                    let mut content_map = okapi::Map::new();
                    content_map.insert(
                        "text/turtle".to_string(),
                        media_type("text/turtle", "", false, false),
                    );
                    content_map.insert(
                        "application/n-triples".to_string(),
                        media_type("application/n-tripples", "", false, false),
                    );
                    content_map
                },
                ..Default::default()
            }),
        );
        Ok(okapi::openapi3::Responses {
            responses,
            ..Default::default()
        })
    }
}

impl<'r> OpenApiResponder<'r> for ResIO<'r> {
    fn responses(_generator: &mut OpenApiGenerator) -> OkapiResult<Responses> {
        use okapi::openapi3::{RefOr, Response as OpenApiResponse};

        let mut responses = okapi::Map::new();

        let ok_response = OpenApiResponse {
            description: "The requested PDF file.".to_string(),
            content: {
                let mut content_map = okapi::Map::new();
                content_map.insert(
                    "application/pdf".to_string(),
                    media_type("application/pdf", "", false, false),
                );
                content_map
            },
            ..Default::default()
        };

        let not_found_response = OpenApiResponse {
            description: "The requested PDF file was not found.".to_string(),
            ..Default::default()
        };

        responses.insert("200".to_string(), RefOr::Object(ok_response));
        responses.insert("404".to_string(), RefOr::Object(not_found_response));

        Ok(Responses {
            responses,
            ..Default::default()
        })
    }
}

pub fn get_docs() -> SwaggerUIConfig {
    use rocket_okapi::swagger_ui::UrlObject;

    SwaggerUIConfig {
        url: "/openapi/openapi.json".to_string(),
        urls: vec![UrlObject::new("/", "/openapi.json")],
        ..Default::default()
    }
}

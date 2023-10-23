// tp - wik-dps-tp01
// 18/10/2023
// Alexandre Pajak

use actix_web::{get, web, App, HttpRequest, HttpResponse, HttpServer, Responder, Result};
use serde::{Serialize};
use std::collections::HashMap;
use std::env;

#[derive(Serialize)]
pub struct Response {
    pub message: String,
}

#[get("/ping")]
async fn ping(req: HttpRequest) -> impl Responder {
    // Extract the headers from the request
    let headers = req.headers();

    // Convert the headers to a HashMap
    let headers_map: HashMap<String, String> = headers
        .iter()
        .map(|(key, value)| (key.as_str().to_string(), value.to_str().unwrap_or("").to_string()))
        .collect();

    // Convert the HashMap to a JSON object
    let headers_json = serde_json::to_string(&headers_map).unwrap();

    HttpResponse::Ok()
        .content_type("application/json")
        .body(headers_json)
}


async fn not_found() -> Result<HttpResponse> {
    let response = Response {
        message: "".to_string(),
    };
    Ok(HttpResponse::NotFound().json(response))
}


#[actix_web::main]
async fn main() -> std::io::Result<()> {
    // Read the PING_LISTEN_PORT environment variable or use a default value (e.g., 8080)
    let listen_port = env::var("PING_LISTEN_PORT")
        .unwrap_or("8080".to_string())
        .parse::<u16>()
        .expect("Invalid port number");

    HttpServer::new(|| App::new()
        .service(ping)
        .default_service(web::route().to(not_found)))
        .bind(("0.0.0.0", listen_port))?
        .run()
        .await
}
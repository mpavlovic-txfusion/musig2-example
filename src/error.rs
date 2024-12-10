use serde::Serialize;
use warp;

#[derive(Debug)]
pub struct CustomError(pub String);

impl warp::reject::Reject for CustomError {}

#[derive(Debug, Serialize)]
pub struct ErrorResponse {
    pub error: String,
}

pub async fn handle_rejection(
    err: warp::Rejection,
) -> Result<impl warp::Reply, std::convert::Infallible> {
    let code;
    let message;

    if err.is_not_found() {
        code = warp::http::StatusCode::NOT_FOUND;
        message = "Not Found";
    } else if let Some(e) = err.find::<CustomError>() {
        code = warp::http::StatusCode::BAD_REQUEST;
        message = e.0.as_str();
    } else {
        eprintln!("unhandled error: {:?}", err);
        code = warp::http::StatusCode::INTERNAL_SERVER_ERROR;
        message = "Internal Server Error";
    }

    Ok(warp::reply::with_status(
        warp::reply::json(&ErrorResponse {
            error: message.to_string(),
        }),
        code,
    ))
}

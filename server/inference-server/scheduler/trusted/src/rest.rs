use bytes::Bytes;
use log::*;
use warp::Filter;

use crate::telemetry::TelemetryEventProps;
use crate::{
    client_communication::{run_inference, Exchanger},
    telemetry,
};


#[derive(Debug, Clone)]
enum RunModelError {
    ModelNotFound,
    Internal,
}
impl warp::reject::Reject for RunModelError {}

async fn run_model(exchanger: Exchanger, bytes: Bytes) -> Result<impl warp::Reply, warp::Rejection> {
    let input_fact = &*exchanger.input_fact.lock().unwrap();
    let datum = &*exchanger.datum_type.lock().unwrap();
    let res = if let Some(model) = &*exchanger.model.lock().unwrap() {
        match run_inference(&model, bytes.to_vec(), &input_fact, &datum) {
            Ok(output) => {
                info!("Inference done successfully, sending encrypted result to the client");
                http::Response::builder().status(200).body(
                    output
                        .into_iter()
                        .flat_map(|el| el.to_be_bytes())
                        .collect::<Vec<u8>>(),
                ).unwrap()
            }
            Err(_) => {
                error!("Error while running the inference");
                return Err(warp::reject::custom(RunModelError::Internal))
            }
        }
    } else {
        error!("Model not loaded, cannot run inference");
        return Err(warp::reject::custom(RunModelError::ModelNotFound))
    };

    telemetry::add_event(TelemetryEventProps::RunModel {});

    Ok(res)
}

pub(crate) async fn setup(exchanger: &Exchanger, identity: (&str, &str)) -> anyhow::Result<()> {
    let exchanger = exchanger.clone();
    let routes = warp::path!("run_model")
        .and(warp::get())
        .and(warp::any().map(move || exchanger.clone()))
        .and(warp::body::bytes())
        .and_then(run_model);

    info!("Starting REST api at port {}", 3030);
    warp::serve(routes)
        .tls()
        .cert(identity.0)
        .key(identity.1)
        .run(([0, 0, 0, 0], 3030))
        .await;

    Ok(())
}

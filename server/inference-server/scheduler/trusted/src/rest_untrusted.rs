use log::*;
use warp::Filter;
use serde::{Serialize, Deserialize};

use std::sync::Arc;
use crate::{
    dcap_quote_provider::DcapQuoteProvider
};
use common::untrusted_local_app_client::UntrustedLocalAppClient;

#[derive(Debug, Clone)]
enum GetQuoteError {
    Unimplemented,
    Internal,
}
impl warp::reject::Reject for GetQuoteError {}

#[derive(Clone, PartialEq, Serialize, Deserialize)]
pub struct GetQuoteReply {
    /// Raw binary SGX Quote as described in https://download.01.org/intel-sgx/latest/dcap-latest/linux/docs/Intel_SGX_ECDSA_QuoteLibReference_DCAP_API.pdf
    pub quote: Vec<u8>,
    pub collateral: Option<SgxCollateral>,
    /// Enclave certificate in DER format
    pub enclave_held_data: Vec<u8>,
}
#[derive(Clone, PartialEq, Serialize, Deserialize)]
pub struct SgxCollateral {
    pub version: u32,
    /// pck_crl_issuer_chain is currently unused by the client
    /// Intel sgx_qve_verify_quote function also doesn't use it for anything besides
    /// some check on issuing/expiration dates
    pub pck_crl_issuer_chain: String,
    pub root_ca_crl: String,
    pub pck_crl: String,
    pub tcb_info_issuer_chain: String,
    pub tcb_info: String,
    /// qe_identity_issuer_chain is unused by the client
    /// Intel sgx_qve_verify_quote function uses it
    /// but the C++ verification app use the tcbSigningCert (tcb_info_issuer_chain)
    /// for both TCB verification and QE identity check
    /// This might be because Intel use the same certificate chain for both
    pub qe_identity_issuer_chain: String,
    pub qe_identity: String,
    pub pck_certificate: String,
    pub pck_signing_chain: String,
}

async fn get_quote(quote_provider: Arc<DcapQuoteProvider>) -> Result<impl warp::Reply, warp::Rejection> {
    if cfg!(SGX_MODE = "SW") {
        Err(warp::reject::custom(GetQuoteError::Unimplemented))?
    }

    let quote = quote_provider.get_quote().unwrap();

    let mut untrusted = UntrustedLocalAppClient::connect("http://127.0.0.1:50053")
        .await
        .unwrap();
    let collateral = untrusted
        .get_collateral_from_quote(quote.clone())
        .await
        .map_err(|_e| warp::reject::custom(GetQuoteError::Internal))?
        .into_inner();

    let reply = GetQuoteReply {
        collateral: Some(SgxCollateral {
            version: collateral.version, // version = 1.  PCK Cert chain is in the Quote.
            pck_crl_issuer_chain: collateral.pck_crl_issuer_chain.into(),
            root_ca_crl: collateral.root_ca_crl.into(), // Root CA CRL
            pck_crl: collateral.pck_crl.into(),         // PCK Cert CRL
            tcb_info_issuer_chain: collateral.tcb_info_issuer_chain.into(),
            tcb_info: collateral.tcb_info.into(), // TCB Info structure
            qe_identity_issuer_chain: collateral.qe_identity_issuer_chain.into(),
            qe_identity: collateral.qe_identity.into(), // QE Identity Structure
            pck_certificate: collateral.pck_certificate, //PEM encoded PCK certificate
            pck_signing_chain: collateral.pck_signing_chain, // PEM encoded PCK signing chain such that (pck_certificate || pck_signing_chain) == pck_cert_chain
        }),
        quote,
        enclave_held_data: quote_provider.enclave_held_data.clone(),
    };

    Ok(warp::reply::json(&reply))
}

pub(crate) async fn setup(quote_provider: Arc<DcapQuoteProvider>, identity: (&[u8], &[u8])) -> anyhow::Result<()> {
    let routes = warp::path!("get_quote")
        .and(warp::get())
        .and(warp::any().map(move || quote_provider.clone()))
        .and_then(get_quote);

    info!("Starting REST untrusted api at port {}", 3031);
    warp::serve(routes)
        .tls()
        .cert(identity.0)
        .key(identity.1)
        .run(([0, 0, 0, 0], 3031))
        .await;

    Ok(())
}

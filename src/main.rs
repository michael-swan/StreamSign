use futures::{Future, Stream, StreamExt};
use actix_web::{web, error, App, Error, HttpResponse, Responder, HttpServer};
use ring::{digest, rand, signature};
use std::io::Write;
use ring::signature::{Ed25519KeyPair, KeyPair};
use std::borrow::Borrow;
use actix_web::body::Body;
use hex::{ToHex, FromHex};
use actix::prelude::*;
use actix::*;
use actix::Addr;
use std::io;
use std::cmp::min;
use serde_json::json;
use std::time::{SystemTime, UNIX_EPOCH};
use serde::Serialize;
use std::mem::transmute;

fn get_now() -> (u64, u32) {
    let now = SystemTime::now();
    let duration_since_epoch = now
        .duration_since(UNIX_EPOCH)
        .expect("SystemTime must be later than UNIX_EPOCH");
    (duration_since_epoch.as_secs(), duration_since_epoch.subsec_nanos())
}

async fn index(signature_actor: web::Data<Addr<SigActor>>, mut body: web::Payload) -> impl Responder
{
    let mut ctxt = digest::Context::new(&digest::SHA512);
    while let Some(item) = body.next().await {
        ctxt.update(item.unwrap().as_ref());
    }
    let (now_sec, now_nsec) = get_now();
    ctxt.update(unsafe { &transmute::<u64, [u8; 8]>(now_sec.to_be()) });
    ctxt.update(unsafe { &transmute::<u32, [u8; 4]>(now_nsec.to_be()) });
    let digest = Vec::from(ctxt.finish().as_ref());
    let msg: NewSignatureMsg = NewSignatureMsg { data: digest };
    let NewSignatureResp(signature) = signature_actor.get_ref().send(msg).await.unwrap();
    let hex_signature = hex::encode(signature.as_slice());
    HttpResponse::Ok().body(json!({
        "time": format!("{:016x}{:08x}", now_sec, now_nsec),
        "signature": hex_signature
    }))
}

async fn check(signature_actor: web::Data<Addr<SigActor>>, mut body: web::Payload) -> impl Responder
{
    let mut signature: Vec<u8> = Vec::new();
    let mut time: Vec<u8> = Vec::new();
    let mut body_ctxt = digest::Context::new(&digest::SHA512);
    while let Some(item) = body.next().await {
        let item_val = item.unwrap();
        let mut buf = item_val.as_ref();
        if signature.len() < 128 {
            let max_read = min(128 - signature.len(), buf.len());
            signature.append(&mut Vec::from(&buf[0..max_read]));
            buf = &buf[max_read..];
        }
        if time.len() < 32 {
            let max_read = min(32 - time.len(), buf.len());
            time.append(&mut Vec::from(&buf[0..max_read]));
            buf = &buf[max_read..];
        }
        if buf.len() > 0 {
            body_ctxt.update(buf);
        }
    }
    if signature.len() != 128 {
        return HttpResponse::Ok().body("Signature too short.");
    }
    let signature = hex::decode(signature).unwrap();
    if time.len() != 32 {
        return HttpResponse::Ok().body("Time too short.");
    }
    let time = hex::decode(time).unwrap().as_slice();
    // let secs: u64 = unsafe { transmute(&time[0..8]).to_be() };
    // let nsecs: u64 = unsafe { transmute(&time[8..16]).to_be() };

    // let nsecs = hex::decode(time[16..32]).unwrap();
    let msg = CheckSignatureMsg {
        signature,
        data: Vec::from(body_ctxt.finish().as_ref())
    };
    let CheckSignatureResp(signature_matches) = signature_actor.send(msg).await.unwrap();
    HttpResponse::Ok().body(signature_matches.to_string())
}

// Signature Actor //
struct SigActor
{
    key_pair: Ed25519KeyPair,
    public_key: signature::UnparsedPublicKey<Vec<u8>>
}

impl SigActor {
    fn new(key_pair: Ed25519KeyPair) -> Self {
        let public_key = signature::UnparsedPublicKey::new(
            &signature::ED25519,
            Vec::from(key_pair.public_key().as_ref()));
        SigActor {
            key_pair,
            public_key
        }
    }
}

impl Actor for SigActor {
    type Context = Context<Self>;

    fn started(&mut self, ctx: &mut Context<Self>) {
        println!("Actor is alive");
    }

    fn stopped(&mut self, ctx: &mut Context<Self>) {
        println!("Actor is stopped");
    }
}

#[derive(Message)]
#[rtype(result = "NewSignatureResp")]
struct NewSignatureMsg {
    data: Vec<u8>
}

#[derive(MessageResponse)]
struct NewSignatureResp(Vec<u8>);

impl Handler<NewSignatureMsg> for SigActor {
    type Result = NewSignatureResp;

    fn handle(&mut self, msg: NewSignatureMsg, ctxt: &mut Context<Self>) -> Self::Result {
        NewSignatureResp(Vec::from(self.key_pair.sign(msg.data.as_slice()).as_ref()))
    }
}

#[derive(Message)]
#[rtype(result = "CheckSignatureResp")]
struct CheckSignatureMsg {
    signature: Vec<u8>,
    data: Vec<u8>
}

#[derive(MessageResponse)]
struct CheckSignatureResp(bool);

impl Handler<CheckSignatureMsg> for SigActor {
    type Result = CheckSignatureResp; // MessageResult<CheckSignatureMsg>;

    fn handle(&mut self, msg: CheckSignatureMsg, ctxt: &mut Context<Self>) -> Self::Result {
        CheckSignatureResp(self.public_key.verify(msg.data.as_slice(), msg.signature.as_slice()).is_ok())
    }
}

#[actix_rt::main]
async fn main() -> std::result::Result<(), std::io::Error> {
    println!("main()");
    let rng = rand::SystemRandom::new();
    let pkcs8_bytes = signature::Ed25519KeyPair::generate_pkcs8(&rng).unwrap();
    let pkcs8_bytes_ref = Vec::from(pkcs8_bytes.as_ref());
    let key_pair = signature::Ed25519KeyPair::from_pkcs8(pkcs8_bytes_ref.as_slice()).unwrap();
    let signature_actor = SigActor::new(key_pair).start();
    HttpServer::new(move || {
        App::new().data(signature_actor.clone())
            .service(
                web::resource("/new").route(
                    web::post().to(index)))
            .service(
                web::resource("/check").route(
                    web::post().to(check)))
    })
        .bind("127.0.0.1:8000")?
        .run()
        .await
}
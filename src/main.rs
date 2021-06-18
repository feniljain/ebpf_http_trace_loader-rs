use redbpf::load::Loader;
use std::{env, io};
use tokio::signal;
use std::net::IpAddr;

use ebpf_http_trace::ebpf_http_trace::{MapData, RequestInfo};

#[tokio::main]
async fn main() -> Result<(), io::Error> {
    let args: Vec<String> = env::args().collect();
    if args.len() != 3 {
        eprintln!("usage: bpf_example_program [NETWORK_INTERFACE] [FILENAME]");
        return Err(io::Error::new(io::ErrorKind::Other, "invalid arguments"));
    }

    let interface = args[1].clone();
    let file = args[2].clone();
    let mut loader = Loader::load_file(&file).expect("error loading probe");
    tokio::spawn(async move {
        while let Some((_, events)) = loader.events.next().await {
            for event in events {
                let event = unsafe { &*(event.as_ptr() as *const MapData<RequestInfo>) };
                let info = &event.data;
                let payload = String::from_utf8_lossy(event.payload());
                let req_line = payload.split("\r\n").next().unwrap();
                let ip = IpAddr::from(info.saddr.to_ne_bytes());
                println!("{} - {}", ip, req_line);
            }
        }
    });

    signal::ctrl_c().await;
    Ok(())
}

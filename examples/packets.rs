#![allow(unused_imports)]
use anyhow::Result;
use libbpf_rs::{
    Link, MapCore, MapFlags, MapHandle, MapType, PrintLevel, set_print,
    skel::{OpenSkel, SkelBuilder},
};
use std::{
    io::{Read, Write},
    mem::MaybeUninit,
    net::SocketAddr,
    ops::{Deref, DerefMut},
    os::{
        fd::{AsFd, AsRawFd, IntoRawFd},
        unix::fs::OpenOptionsExt,
    },
};

include!(concat!(env!("OUT_DIR"), "/monitor.skel.rs"));

fn main() -> Result<()> {
    bpflog::try_init()?;

    let mut open_obj = MaybeUninit::uninit();
    let skel_builder = MonitorSkelBuilder::default();
    let open_skel = skel_builder.open(&mut open_obj)?;
    // if tracing::event_enabled!(Level::TRACE) {
    //     open_skel.progs.verdict.set_log_level(1);
    // }

    let skel = open_skel.load()?;
    let sock_map_fd = skel.maps.sock_map.as_fd().as_raw_fd();

    let cgroup_fd = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY)
        .open("/sys/fs/cgroup")?
        .into_raw_fd();

    let sockops = skel.progs.monitor_sockets.attach_cgroup(cgroup_fd)?;
    skel.progs.verdict.attach_sockmap(sock_map_fd)?;

    let address: SocketAddr = "127.0.0.1:9999".parse().unwrap();
    let listener = std::net::TcpListener::bind(address)?;
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let mut stream = stream.unwrap();
            let mut buf = Vec::new();
            stream.read_to_end(&mut buf).expect("read_to_end");

            let text = String::from_utf8_lossy(&buf);
            println!("{}", text);
            stream.shutdown(std::net::Shutdown::Both).expect("shutdown");
        }
    });

    let mut stream = std::net::TcpStream::connect(address)?;
    stream.write_all(b"Hello, World!")?;
    stream.shutdown(std::net::Shutdown::Both)?;

    drop(sockops);
    drop(skel);

    Ok(())
}

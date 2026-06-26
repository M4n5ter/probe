use std::{
    net::TcpListener,
    thread,
    time::Duration,
};

fn main() {
    let target = std::env::args()
        .nth(1)
        .expect("managed MITM backend test fixture requires a listen address");
    let listener =
        TcpListener::bind(&target).expect("managed MITM backend test fixture should bind target");
    listener
        .set_nonblocking(true)
        .expect("managed MITM backend test fixture listener should become nonblocking");

    loop {
        match listener.accept() {
            Ok((stream, _peer)) => drop(stream),
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                thread::sleep(Duration::from_millis(20));
            }
            Err(error) => panic!("managed MITM backend test fixture accept failed: {error}"),
        }
    }
}

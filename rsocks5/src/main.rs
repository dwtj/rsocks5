extern crate mio;

use mio::*;
use mio::tcp::{TcpListener, TcpStream};

const SERVER: Token = Token(0);
const CLIENT: Token = Token(1);

struct MyHandler(TcpListener);

impl Handler for MyHandler {
    type Timeout = ();
    type Message = ();

    fn ready(&mut self, event_loop: &mut EventLoop<MyHandler>,
             token: Token, _: EventSet) {
        match token {
            SERVER => {
                let MyHandler(ref mut server) = *self;
                // Accept and drop the socket immediately; this closes the
                // socket and notifies the client of the EOF.
                let _ = server.accept();
            }
            CLIENT => {
                // The server just shuts down the socket, so let's just shut
                // down the event loop.
                // XXX the next line causes the program to immediately exit
                event_loop.shutdown();
            }
            _ => unreachable!("unexpected token"),
        }
    }
}

fn main() {
    let addr = "127.0.0.1:13265".parse().unwrap();
    let server = TcpListener::bind(&addr).unwrap();
    let mut event_loop = EventLoop::new().unwrap();
    event_loop.register(&server, SERVER).unwrap();
    let sock = TcpStream::connect(&addr).unwrap();
    event_loop.register(&sock, CLIENT).unwrap();
    event_loop.run(&mut MyHandler(server)).unwrap();
}

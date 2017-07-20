use bytes::{Buf, BufMut, IntoBuf};
use futures::{Async, Future, Poll};
use hyper::Uri;
use hyper::client::{HttpConnector, Service};
use hyper_tls::{HttpsConnector, MaybeHttpsStream};
use native_tls::TlsConnector;
use tokio_core::reactor;
use tokio_io::{AsyncRead, AsyncWrite};
use tokio_tls::{TlsConnectorExt, TlsStream};
use winauth::windows::NtlmSspiBuilder;
use winauth::NextBytes;
use httparse;
use base64;

use std::error::Error;
use std::io::{self, Cursor, Read, Write};
use std::sync::Arc;
use std::str;

/// The header and prefix value in the NTLM challenge header sent 
/// back by an NTLM proxy.
/// The whitespace at the end is significant. Do not remove it.
const NTLM_CHLG_HDR_PREFIX: &'static str = "Proxy-Authenticate: NTLM ";

/// A future that resolves to a connection.
pub type Connecting = Box<Future<Item=ConnectionType, Error=io::Error>>;

/// A `Connector` capable of authenticating to NTLM proxies on Windows.
pub struct NtlmProxyConnector {
    https: HttpsConnector<HttpConnector>,
    proxy_addr: Uri,
    tls: Arc<TlsConnector>,
}

type HttpStream = <HttpConnector as Service>::Response;
type HttpsStream = MaybeHttpsStream<HttpStream>;

pub enum ConnectionType {
    Normal(HttpsStream),
    Proxied(TlsStream<MaybeHttpsStream<HttpStream>>),
}

/// Handles the process of establishing a tunnel through an NTLM proxy.
///
/// Note that the `conn` and `state` fields are stored in `Option` so that we can
/// use `Option::take()` to move ownership of their contents later. In each of the
/// `Tunnel`'s methods that return `StateTransition`, `state` will be `None`, so
/// don't bother trying to read it.
struct Tunnel<T> {
    buf: Cursor<Vec<u8>>,
    conn: Option<T>, // Stored in an option so we can .take() ownership of it later.
    state: Option<TunnelState>,
    host: String,
    port: u16,
}

#[derive(Debug)]
struct NtlmChallenge(pub String);

/// Represents the states of the tunnel establishing process.
///
/// We expect the states to transition from `WritingInitial` to `ReadingChallenge` to `WritingResponse`.
/// The `Failure` state should be jumped to as soon as an error occurs.
///
/// In order to complete the NTLM authentication process, the SSPI context has to be passed between the
/// `ReadingChallenge` and `WritingResponse` states. Neglecting to pass the same context will cause auth to fail.
enum TunnelState {
    WriteInitial,
    ReadChallenge(Box<NextBytes>),
    WriteResponse(NtlmChallenge, Box<NextBytes>),
    ReadConfirm,
    Done,
    Failure(io::Error),
}

/// Represents the outcomes of attempting to do a state transition from one `TunnelState` to the next.
///
/// Each `TunnelState` may perform some asynchronous operations that may not have completed by the
/// time the transition function (defined as a method of the `Tunnel` type) executes. In such a
/// scenario, we would like for the `Tunnel` future's `poll()` method to be able to propagate the
/// `Async::NotReady` status from the state transition function.
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
enum StateTransition {
    Continue,
    NotReady,
    Error,
}

impl NtlmProxyConnector {
    /// Constructs a new `NtlmProxyConnector` capable of handling TLS through a proxy given its address.
    pub fn new(tls: TlsConnector, proxy_uri: Uri, handle: &reactor::Handle) -> NtlmProxyConnector {
        let mut http = HttpConnector::new(4, handle);
        http.enforce_http(false);
        let https = HttpsConnector::from((http, tls.clone()));
        let tls = Arc::new(tls);

        println!("Constructed NtlmProxyConnector");
        NtlmProxyConnector {
            https: https,
            proxy_addr: proxy_uri,
            tls: tls,
        }
    }
}

impl Service for NtlmProxyConnector {
    type Request = Uri;
    type Response = ConnectionType;
    type Error = io::Error;
    type Future = Connecting;

    fn call(&self, uri: Uri) -> Self::Future {
        match uri.scheme() {
            Some("https") => {
                println!("Got an HTTPS request");
                let host = uri.host().unwrap().to_owned();
                let port = uri.port().unwrap_or(443);
                let tls = self.tls.clone();
                let host_copy = host.to_owned();
                Box::new(self.https
                    .call(self.proxy_addr.clone())
                    .and_then(move |conn| Tunnel::new(conn, host_copy, port))
                    .and_then(move |tunn| tls.connect_async(host.as_str(), tunn)
                              .map_err(|_| io::Error::new(io::ErrorKind::ConnectionAborted,
                                                          "tunnel failed to connect")))
                    .map(ConnectionType::Proxied))
            },
            _ => {
                println!("Got an HTTP request");
                Box::new(self.https
                    .call(self.proxy_addr.clone())
                    .map(ConnectionType::Normal))
            },

        }
    }
}

impl<T> Tunnel<T> 
    where T: AsyncRead + AsyncWrite
{
    /// Constructs a new `Tunnel` that will attempt to tunnel through a specified proxy.
    pub fn new(conn: T, host: String, port: u16) -> Self {
        let empty_buf = String::new().into_bytes();
        Tunnel {
            buf: empty_buf.into_buf(),
            conn: Some(conn),
            state: Some(TunnelState::WriteInitial),
            host: host,
            port: port,
        }
    }

    fn begin_ntlm_handshake(&mut self) -> StateTransition {
        let mut sspi = match NtlmSspiBuilder::new().build() {
            Ok(ntlm_ctx) => ntlm_ctx,
            Err(err) => {
                self.state = Some(TunnelState::Failure(
                    io::Error::new(io::ErrorKind::Other, err.description().to_owned())));
                return StateTransition::Error;
            }
        };
        println!("In begin_ntlm_handshake, created NTLM context");
        let negotiate_bytes = match sspi.next_bytes(None) {
            Ok(Some(bytes)) => bytes,
            Ok(None) => {
                self.state = Some(TunnelState::Failure(
                    io::Error::new(io::ErrorKind::Other, String::from("failed to read NTLM initial bytes"))));
                return StateTransition::Error;
            },
            Err(error) => {
                self.state = Some(TunnelState::Failure(
                    io::Error::new(io::ErrorKind::Other, error.description().to_owned())));
                return StateTransition::Error;
            }
        };
        let negotiation = base64::encode(&*negotiate_bytes);
        println!("Got initial NTLM handshake bytes {}", negotiation);
        let request_content = format!(
            "CONNECT {host}:{port} HTTP/1.1\r\nHost: {host}:{port}\r\nProxy-Authorization: NTLM {neg}\r\n\r\n",
            host=self.host,
            port=self.port,
            neg=negotiation);
        self.buf = request_content.into_bytes().into_buf();
        let bytes_written = match self.conn.as_mut().unwrap().write_buf(&mut self.buf) {
            Ok(Async::Ready(written)) => written,
            Ok(Async::NotReady) => {
                self.state = Some(TunnelState::WriteInitial);
                return StateTransition::NotReady;
            },
            Err(error) => {
                self.state = Some(TunnelState::Failure(
                    io::Error::new(io::ErrorKind::Other,
                                   error.description().to_owned())));
                return StateTransition::Error;
            }
        };
        if !self.buf.has_remaining_mut() && bytes_written > 0 {
            println!("Successfully wrote first request");
            self.state = Some(TunnelState::ReadChallenge(Box::new(sspi)));
            println!("Updated state");
            self.buf.get_mut().truncate(0);
            StateTransition::Continue
        } else {
            println!("Failed to write first request");
            self.state = Some(TunnelState::Failure(
                io::Error::new(io::ErrorKind::UnexpectedEof, String::from("unexpected EOF while tunneling"))));
            StateTransition::Error
        }
    }

    fn read_challenge(&mut self, ntlm_ctx: Box<NextBytes>) -> StateTransition {
        println!("Attempting to read challenge");
        let bytes_read = match self.conn.as_mut().unwrap().read_buf(&mut self.buf.get_mut()) {
            Ok(Async::Ready(bytes_read)) => bytes_read,
            Ok(Async::NotReady) => { 
                println!("Not ready to read bytes");
                self.state = Some(TunnelState::ReadChallenge(ntlm_ctx));
                return StateTransition::NotReady;
            },
            Err(error) => {
                println!("Encountered error reading bytes {:?}", error);
                self.state = Some(TunnelState::Failure(
                    io::Error::new(io::ErrorKind::Other,
                                   error.description().to_owned())));
                return StateTransition::Error;
            }
        };
        let read = &self.buf.get_ref()[..].to_owned();
        println!("Read {} bytes", bytes_read);
        if bytes_read == 0 {
            self.state = Some(TunnelState::Failure(
                io::Error::new(io::ErrorKind::UnexpectedEof, String::from("unexpected EOF while tunneling"))));
            return StateTransition::Error;
        }
        if read.len() <= 12 {
            self.state = Some(TunnelState::Failure(
                io::Error::new(io::ErrorKind::InvalidData, String::from("did not read enough bytes"))));
            return StateTransition::Error;
        }
        // Handle the case where we are talking to an NTLM proxy and have completely read its
        // response. If we haven't read the whole response, the tunnel should remain in its current
        // state so that we come back to this method and read more bytes.
        //
        // If we find that the response contains a regular status 200, then we don't have to do
        // any more work and can move straight to the final `Done` state.
        let end = b"\r\n\r\n";
        if read.starts_with(b"HTTP/1.0 407") || read.starts_with(b"HTTP/1.1 407") {
            println!("Read status 407");
            let mut headers = [httparse::EMPTY_HEADER; 32]; // Just have to hope the response has <= 32 headers.
            let mut response = httparse::Response::new(&mut headers);
            let finished = response.parse(read)
                .map(|result| result.is_complete() && finished_reading_http(&mut response, read))
                .unwrap_or(false);
            if finished {
            //if finished_reading_http(&read) {
                println!("Read challenge response");
                println!("{}", String::from_utf8_lossy(read));
                let res = String::from_utf8_lossy(read);
                let parts: Vec<&str> = res.split(NTLM_CHLG_HDR_PREFIX).collect();
                if parts.len() < 2 {
                    self.state = Some(TunnelState::Failure(
                        io::Error::new(io::ErrorKind::Other, String::from("Proxy-Authenticate header not found"))));
                    return StateTransition::Error;
                }
                let parts: Vec<&str> = parts[1].split("\r\n").collect();
                let challenge = NtlmChallenge(parts[0].trim().to_owned());
                println!("Got challenge {:?}", challenge);
                self.state = Some(TunnelState::WriteResponse(challenge, ntlm_ctx));
                println!("Successfully parsed NTLM challenge");
                StateTransition::Continue
            } else {
                // Else (do nothing to) stay in the current state to read more.
                self.state = Some(TunnelState::ReadChallenge(ntlm_ctx));
                println!("Going to try to read to end of 407 response");
                StateTransition::Continue
            }
        } else if read.starts_with(b"HTTP/1.0 200") || read.starts_with(b"HTTP/1.1 200") {
            println!("Read status 200");
            if read.ends_with(end) {
                println!("Looks like we don't need to do NTLM handshake");
                self.state = Some(TunnelState::Done);
                StateTransition::Continue
            } else {
                // Else (do nothing to) stay in the current state to read more.
                self.state = Some(TunnelState::ReadChallenge(ntlm_ctx));
                println!("Going to try to read to end of 200 response");
                StateTransition::Continue
            }
        } else {
            println!("Error reading challenge response");
            self.state = Some(TunnelState::Failure(
                io::Error::new(io::ErrorKind::ConnectionRefused, String::from("unsuccessful tunnel setup"))));
            StateTransition::Error
        }
    }

    fn respond_to_challenge(&mut self, ch: NtlmChallenge, mut ntlm_ctx: Box<NextBytes>) -> StateTransition {
        let challenge = ch.0;
        let decoded = match base64::decode(challenge.as_str()) {
            Ok(bytes) => bytes,
            Err(_) => {
                self.state = Some(TunnelState::Failure(
                    io::Error::new(io::ErrorKind::Other, format!("got invalid challenge: {}", challenge))));
                return StateTransition::Error;
            }
        };
        println!("Decoded challenge");
        let auth_response = match ntlm_ctx.as_mut().next_bytes(Some(&decoded)) {
            Ok(Some(auth)) => auth,
            Ok(None) => {
                self.state = Some(TunnelState::Failure(
                    io::Error::new(io::ErrorKind::Other, String::from("failed to process response to challenge"))));
                return StateTransition::Error;
            },
            Err(err) => {
                self.state = Some(TunnelState::Failure(
                    io::Error::new(io::ErrorKind::Other, err.description().to_owned())));
                return StateTransition::Error;
            }
        };
        let challenge_response = base64::encode(&*auth_response);
        println!("Produced response to challenge {:?}", challenge_response);
        let response = format!(
            "CONNECT {host}:{port} HTTP/1.1\r\nHost: {host}:{port}\r\nProxy-Authorization: NTLM {res}\r\n\r\n",
            host=self.host,
            port=self.port,
            res=challenge_response);
        self.buf = response.into_bytes().into_buf();
        let bytes_written = match self.conn.as_mut().unwrap().write_buf(&mut self.buf) {
            Ok(Async::Ready(written)) => written,
            Ok(Async::NotReady) => {
                self.state = Some(TunnelState::WriteResponse(NtlmChallenge(challenge), ntlm_ctx));
                return StateTransition::NotReady;
            },
            Err(error) => {
                self.state = Some(TunnelState::Failure(
                    io::Error::new(io::ErrorKind::Other,
                                   error.description().to_owned())));
                return StateTransition::Error;
            }
        };
        if !self.buf.has_remaining_mut() && bytes_written > 0 {
            println!("Successfully wrote challenge response");
            self.state = Some(TunnelState::ReadConfirm);
            self.buf.get_mut().truncate(0);
            StateTransition::Continue
        } else {
            println!("Failed to write challenge response");
            self.state = Some(TunnelState::Failure(
                io::Error::new(io::ErrorKind::UnexpectedEof, String::from("unexpected EOF while tunneling"))));
            StateTransition::Error
        }
    }

    fn verify_handshake_completed(&mut self) -> StateTransition {
        let bytes_read = match self.conn.as_mut().unwrap().read_buf(&mut self.buf.get_mut()) {
            Ok(Async::Ready(read)) => read,
            Ok(Async::NotReady) => {
                self.state = Some(TunnelState::ReadConfirm);
                return StateTransition::NotReady;
            },
            Err(error) => {
                self.state = Some(TunnelState::Failure(
                    io::Error::new(io::ErrorKind::Other,
                                   error.description().to_owned())));
                return StateTransition::Error;
            }
        };
        let read = &self.buf.get_ref()[..].to_owned();
        if bytes_read == 0 {
            self.state = Some(TunnelState::Failure(
                io::Error::new(io::ErrorKind::UnexpectedEof, String::from("unexpected EOF while tunneling"))));
            return StateTransition::Error;
        }
        if read.len() <= 12 {
            self.state = Some(TunnelState::Failure(
                io::Error::new(io::ErrorKind::InvalidData, String::from("did not read enough bytes"))));
            return StateTransition::Error;
        }
        println!("verify_handshake_completed read {}", String::from_utf8_lossy(read));
        if read.starts_with(b"HTTP/1.0 200") || read.starts_with(b"HTTP/1.1 200") {
            println!("Verified that the handshake completed");
            self.state = Some(TunnelState::Done);
            StateTransition::Continue
        } else {
            println!("Handshake verification failed");
            self.state = Some(TunnelState::Failure(
                io::Error::new(io::ErrorKind::ConnectionRefused, String::from("proxy did not accept challenge response"))));
            StateTransition::Error
        }
    }
}

impl<T> Future for Tunnel<T>
    where T: AsyncRead + AsyncWrite
{
    type Item = T;
    type Error = io::Error;

    /// Handles state transitions for authenticating to an NTLM proxy.
    fn poll(&mut self) -> Poll<Self::Item, Self::Error> {
        loop {
            println!("At top of tunnel.poll");
            if self.state.is_none() {
                println!("Tunnel state is none");
                return Ok(Async::NotReady);
            }
            // Note about state transitions:
            // Be careful with how the tunnel is used after calling self.state.take().
            // At this point the tunnel's state will be None, so trying to read the state in
            // any of the state transition functions below probably won't work how you'd expect.
            let state_trans_status = match self.state.take().unwrap() {
                TunnelState::WriteInitial                  => self.begin_ntlm_handshake(),
                TunnelState::ReadChallenge(ntlm_ctx)       => self.read_challenge(ntlm_ctx),
                TunnelState::WriteResponse(chal, ntlm_ctx) => self.respond_to_challenge(chal, ntlm_ctx),
                TunnelState::ReadConfirm                   => self.verify_handshake_completed(),
                TunnelState::Done                          => { return Ok(Async::Ready(self.conn.take().unwrap())); },
                TunnelState::Failure(error)                => { return Err(error); },
            };
            // If the transition status is `Error`, then the tunnel will have entered `TunnelState::Failure`,
            // so we don't need to handle that here (it gets handled above).
            // Likewise, if the status is `Continue`, we can just let the loop go ahead and run again.
            if state_trans_status == StateTransition::NotReady {
                println!("Tunnel is not ready");
                return Ok(Async::NotReady);
            }
        }
    }
}

impl Read for ConnectionType {
    #[inline]
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        match *self {
            ConnectionType::Normal(ref mut stream)  => stream.read(buf),
            ConnectionType::Proxied(ref mut stream) => stream.read(buf),
        }
    }
}

impl Write for ConnectionType {
    #[inline]
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        match *self {
            ConnectionType::Normal(ref mut stream)  => stream.write(buf),
            ConnectionType::Proxied(ref mut stream) => stream.write(buf),
        }
    }

    #[inline]
    fn flush(&mut self) -> io::Result<()> {
        match *self {
            ConnectionType::Normal(ref mut stream)  => stream.flush(),
            ConnectionType::Proxied(ref mut stream) => stream.flush(),
        }
    }
}

impl AsyncRead for ConnectionType {
    unsafe fn prepare_uninitialized_buffer(&self, buf: &mut [u8]) -> bool {
        match *self {
            ConnectionType::Normal(ref stream)  => stream.prepare_uninitialized_buffer(buf),
            ConnectionType::Proxied(ref stream) => stream.prepare_uninitialized_buffer(buf),
        }
    }

    fn read_buf<B: BufMut>(&mut self, buf: &mut B) -> Poll<usize, io::Error> {
        match *self {
            ConnectionType::Normal(ref mut stream)  => stream.read_buf(buf),
            ConnectionType::Proxied(ref mut stream) => stream.read_buf(buf),
        }
    }
}

impl AsyncWrite for ConnectionType {
    fn shutdown(&mut self) -> Poll<(), io::Error> {
        match *self {
            ConnectionType::Normal(ref mut stream)  => stream.shutdown(),
            ConnectionType::Proxied(ref mut stream) => stream.shutdown(),
        }
    }

    fn write_buf<B: Buf>(&mut self, buf: &mut B) -> Poll<usize, io::Error> {
        match *self {
            ConnectionType::Normal(ref mut stream)  => stream.write_buf(buf),
            ConnectionType::Proxied(ref mut stream) => stream.write_buf(buf),
        }
    }
}

/// Determine, after parsing the status and headers of a response, whether we have read
/// the entire body of the response, whose length is given by the `Content-Length` header.
fn finished_reading_http(response: &mut httparse::Response, read_bytes: &[u8]) -> bool {
    let mut content_length: Option<usize> = None;
    for header in response.headers.iter() {
        if header.name == "Content-Length" {
            content_length = Some(String::from_utf8_lossy(header.value).parse().unwrap());
        }
    }
    match (beginning_of_body(read_bytes), content_length) {
        (Some(index), Some(length)) => read_bytes.len() - index == length,
        _ => false,
    }
}

/// Finds the index at which the body of an HTTP response begins.
fn beginning_of_body(read_bytes: &[u8]) -> Option<usize> {
    let last_offset = read_bytes.len() - 4;
    for i in 0..last_offset {
        if &read_bytes[i..i+4] == b"\r\n\r\n" {
            return Some(i + 4);
        }
    }
    None
}

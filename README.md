# Hyper NTLM Connector

An implementation of Hyper's Connector trait that can authenticate to proxies using NTLM and works with or without TLS.

## Example

```rust
extern crate ntlm_connector;
extern crate futures;
extern crate hyper;
extern crate native_tls;
extern crate tokio_core;

use std::io::{self, Write};
use ntlm_connector::NtlmProxyConnector;
use futures::{Future, Stream};
use hyper::{Client, Method, Request};
use native_tls::TlsConnector;
use tokio_core::reactor::Core;

fn main () {
  let mut core = Core::new().unwrap();
  let handle = core.handle();
  let tls_connector = TlsConnector::builder().unwrap().build().unwrap();
  let proxy = "http://proxy.address".parse().unwrap();
  let connector = NtlmProxyConnector::new(tls_connector, proxy, &handle);

  let client = Client::configure()
      .connector(connector)
      .build(&handle);
  let uri_https = "https://web.site".parse().unwrap();
  let req_https = Request::new(Method::Get, uri_https);
  
  let work = client.request(req_https).and_then(|res| {
      res.body().for_each(|chunk| {
          io::stdout()
              .write_all(&chunk)
              .map(|_| ())
              .map_err(From::from)
      })
  });

  println!("Making request");
  let work_result = core.run(work);
  println!("Work result: {:?}", work_result);
  match work_result {
      Ok(result) => println!("Successfully retrieved a result, {:?}", result),
      Err(error) => println!("Got an error: {:?}", error),
  };
}
```

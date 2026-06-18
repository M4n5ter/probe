use std::{
    ffi::c_void,
    net::{SocketAddr, TcpStream},
    os::fd::AsRawFd,
    path::{Path, PathBuf},
    ptr::NonNull,
    time::Duration,
};

use super::{
    api::DynSslApi,
    error::{DynSslError, io_error},
};

const IO_TIMEOUT: Duration = Duration::from_secs(5);

pub(crate) struct DynSslClient {
    api: DynSslApi,
}

impl DynSslClient {
    pub(crate) fn load(libssl_path: &Path) -> Result<Self, DynSslError> {
        Ok(Self {
            api: DynSslApi::load(libssl_path)?,
        })
    }

    pub(crate) fn libssl_path(&self) -> &Path {
        self.api.path()
    }

    pub(crate) fn exchange(
        &self,
        server_addr: SocketAddr,
        request: &[u8],
        post_write_delay: Duration,
    ) -> Result<DynSslExchangeReport, DynSslError> {
        let stream = TcpStream::connect(server_addr)
            .map_err(|source| io_error("connect to TLS server", source))?;
        stream
            .set_read_timeout(Some(IO_TIMEOUT))
            .map_err(|source| io_error("set TLS socket read timeout", source))?;
        stream
            .set_write_timeout(Some(IO_TIMEOUT))
            .map_err(|source| io_error("set TLS socket write timeout", source))?;
        stream
            .set_nodelay(true)
            .map_err(|source| io_error("set TCP_NODELAY", source))?;

        let context = SslContext::new(&self.api)?;
        let mut connection = SslConnection::connect(&self.api, &context, &stream)?;
        connection.write_all(request)?;
        if !post_write_delay.is_zero() {
            std::thread::sleep(post_write_delay);
        }
        let _ = connection.shutdown();
        Ok(DynSslExchangeReport {
            request_bytes: request.len(),
            libssl_path: self.api.path().to_path_buf(),
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct DynSslExchangeReport {
    pub(crate) request_bytes: usize,
    pub(crate) libssl_path: PathBuf,
}

struct SslContext<'api> {
    api: &'api DynSslApi,
    ptr: NonNull<c_void>,
}

impl<'api> SslContext<'api> {
    fn new(api: &'api DynSslApi) -> Result<Self, DynSslError> {
        let method = unsafe { (api.tls_client_method())() };
        let ptr = unsafe { (api.ssl_ctx_new())(method) };
        let ptr = NonNull::new(ptr).ok_or(DynSslError::NullPointer {
            action: "create SSL_CTX",
        })?;
        Ok(Self { api, ptr })
    }
}

impl Drop for SslContext<'_> {
    fn drop(&mut self) {
        unsafe { (self.api.ssl_ctx_free())(self.ptr.as_ptr()) };
    }
}

struct SslConnection<'api> {
    api: &'api DynSslApi,
    ptr: NonNull<c_void>,
}

impl<'api> SslConnection<'api> {
    fn connect(
        api: &'api DynSslApi,
        context: &SslContext<'api>,
        stream: &TcpStream,
    ) -> Result<Self, DynSslError> {
        let ptr = unsafe { (api.ssl_new())(context.ptr.as_ptr()) };
        let ptr = NonNull::new(ptr).ok_or(DynSslError::NullPointer {
            action: "create SSL",
        })?;
        let connection = Self { api, ptr };
        let set_fd = unsafe { (api.ssl_set_fd())(connection.ptr.as_ptr(), stream.as_raw_fd()) };
        if set_fd != 1 {
            return Err(DynSslError::OpenSsl {
                action: "associate SSL with socket fd",
            });
        }
        let connected = unsafe { (api.ssl_connect())(connection.ptr.as_ptr()) };
        if connected != 1 {
            return Err(DynSslError::OpenSsl {
                action: "perform TLS client handshake",
            });
        }
        Ok(connection)
    }

    fn write_all(&mut self, mut bytes: &[u8]) -> Result<(), DynSslError> {
        while !bytes.is_empty() {
            let mut written = 0usize;
            let ok = unsafe {
                (self.api.ssl_write_ex())(
                    self.ptr.as_ptr(),
                    bytes.as_ptr().cast::<c_void>(),
                    bytes.len(),
                    &mut written,
                )
            };
            if ok != 1 || written == 0 {
                return Err(DynSslError::OpenSsl {
                    action: "write TLS request",
                });
            }
            bytes = &bytes[written..];
        }
        Ok(())
    }

    fn shutdown(&mut self) -> Result<(), DynSslError> {
        let shutdown = unsafe { (self.api.ssl_shutdown())(self.ptr.as_ptr()) };
        if shutdown < 0 {
            return Err(DynSslError::OpenSsl {
                action: "shutdown TLS connection",
            });
        }
        Ok(())
    }
}

impl Drop for SslConnection<'_> {
    fn drop(&mut self) {
        unsafe { (self.api.ssl_free())(self.ptr.as_ptr()) };
    }
}

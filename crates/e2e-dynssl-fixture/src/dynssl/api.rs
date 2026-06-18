use std::{
    ffi::{c_int, c_void},
    path::{Path, PathBuf},
};

use libloading::Library;

use super::error::DynSslError;

type TlsClientMethod = unsafe extern "C" fn() -> *const c_void;
type SslCtxNew = unsafe extern "C" fn(*const c_void) -> *mut c_void;
type SslCtxFree = unsafe extern "C" fn(*mut c_void);
type SslNew = unsafe extern "C" fn(*mut c_void) -> *mut c_void;
type SslFree = unsafe extern "C" fn(*mut c_void);
type SslSetFd = unsafe extern "C" fn(*mut c_void, c_int) -> c_int;
type SslConnect = unsafe extern "C" fn(*mut c_void) -> c_int;
type SslWriteEx = unsafe extern "C" fn(*mut c_void, *const c_void, usize, *mut usize) -> c_int;
type SslShutdown = unsafe extern "C" fn(*mut c_void) -> c_int;

pub(super) struct DynSslApi {
    path: PathBuf,
    _library: Library,
    tls_client_method: TlsClientMethod,
    ssl_ctx_new: SslCtxNew,
    ssl_ctx_free: SslCtxFree,
    ssl_new: SslNew,
    ssl_free: SslFree,
    ssl_set_fd: SslSetFd,
    ssl_connect: SslConnect,
    ssl_write_ex: SslWriteEx,
    ssl_shutdown: SslShutdown,
}

impl DynSslApi {
    pub(super) fn load(path: &Path) -> Result<Self, DynSslError> {
        let library = unsafe { Library::new(path) }.map_err(|source| DynSslError::LoadLibrary {
            path: path.to_path_buf(),
            reason: source.to_string(),
        })?;
        Ok(Self {
            path: path.to_path_buf(),
            tls_client_method: load_symbol(
                &library,
                path,
                b"TLS_client_method\0",
                "TLS_client_method",
            )?,
            ssl_ctx_new: load_symbol(&library, path, b"SSL_CTX_new\0", "SSL_CTX_new")?,
            ssl_ctx_free: load_symbol(&library, path, b"SSL_CTX_free\0", "SSL_CTX_free")?,
            ssl_new: load_symbol(&library, path, b"SSL_new\0", "SSL_new")?,
            ssl_free: load_symbol(&library, path, b"SSL_free\0", "SSL_free")?,
            ssl_set_fd: load_symbol(&library, path, b"SSL_set_fd\0", "SSL_set_fd")?,
            ssl_connect: load_symbol(&library, path, b"SSL_connect\0", "SSL_connect")?,
            ssl_write_ex: load_symbol(&library, path, b"SSL_write_ex\0", "SSL_write_ex")?,
            ssl_shutdown: load_symbol(&library, path, b"SSL_shutdown\0", "SSL_shutdown")?,
            _library: library,
        })
    }

    pub(super) fn path(&self) -> &Path {
        &self.path
    }

    pub(super) fn tls_client_method(&self) -> TlsClientMethod {
        self.tls_client_method
    }

    pub(super) fn ssl_ctx_new(&self) -> SslCtxNew {
        self.ssl_ctx_new
    }

    pub(super) fn ssl_ctx_free(&self) -> SslCtxFree {
        self.ssl_ctx_free
    }

    pub(super) fn ssl_new(&self) -> SslNew {
        self.ssl_new
    }

    pub(super) fn ssl_free(&self) -> SslFree {
        self.ssl_free
    }

    pub(super) fn ssl_set_fd(&self) -> SslSetFd {
        self.ssl_set_fd
    }

    pub(super) fn ssl_connect(&self) -> SslConnect {
        self.ssl_connect
    }

    pub(super) fn ssl_write_ex(&self) -> SslWriteEx {
        self.ssl_write_ex
    }

    pub(super) fn ssl_shutdown(&self) -> SslShutdown {
        self.ssl_shutdown
    }
}

fn load_symbol<T: Copy>(
    library: &Library,
    path: &Path,
    raw_symbol: &'static [u8],
    symbol: &'static str,
) -> Result<T, DynSslError> {
    let loaded =
        unsafe { library.get::<T>(raw_symbol) }.map_err(|source| DynSslError::ResolveSymbol {
            path: path.to_path_buf(),
            symbol,
            reason: source.to_string(),
        })?;
    Ok(*loaded)
}

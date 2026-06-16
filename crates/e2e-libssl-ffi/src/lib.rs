use std::{
    ffi::c_int,
    os::fd::{AsRawFd, BorrowedFd},
};

use foreign_types::ForeignType;
use openssl::{error::ErrorStack, ssl::Ssl};

unsafe extern "C" {
    fn SSL_set_fd(ssl: *mut openssl_sys::SSL, fd: c_int) -> c_int;
}

pub fn associate_ssl_fd(ssl: &mut Ssl, fd: BorrowedFd<'_>) -> Result<(), ErrorStack> {
    let result = unsafe { SSL_set_fd(ssl.as_ptr(), fd.as_raw_fd()) };
    if result == 1 {
        Ok(())
    } else {
        Err(ErrorStack::get())
    }
}

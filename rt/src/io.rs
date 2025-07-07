use std::{
    fmt,
    mem::MaybeUninit,
    ops::DerefMut,
    pin::Pin,
    task::{Context, Poll},
};

trait Read {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: ReadBufCursor<'_>,
    ) -> Poll<Result<(), std::io::Error>>;
}

trait Write {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<Result<usize, std::io::Error>>;

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), std::io::Error>>;
    fn poll_shutdown(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<(), std::io::Error>>;
    fn is_write_vectored(&self) -> bool {
        false
    }
    fn poll_write_vectored(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &[std::io::IoSlice<'_>],
    ) -> Poll<Result<usize, std::io::Error>> {
        let buf = bufs
            .iter()
            .find(|b| !b.is_empty())
            .map_or(&[][..], |b| &**b);
        self.poll_write(cx, buf)
    }
}

pub struct ReadBuf<'a> {
    raw: &'a mut [MaybeUninit<u8>],
    init: usize,
    filled: usize,
}
#[derive(Debug)]
struct ReadBufCursor<'a> {
    buf: &'a mut ReadBuf<'a>,
}

impl<'data> ReadBuf<'data> {
    #[inline]
    pub fn new(raw: &'data mut [u8]) -> Self {
        let len = raw.len();
        Self {
            raw: unsafe { &mut *(raw as *mut [u8] as *mut [MaybeUninit<u8>]) },
            init: len,
            filled: 0,
        }
    }
    #[inline]
    pub fn uninit(raw: &'data mut [MaybeUninit<u8>]) -> Self {
        Self {
            raw,
            init: 0,
            filled: 0,
        }
    }
    #[inline]
    pub fn filled(&self) -> &[u8] {
        unsafe { &*(&self.raw[0..self.filled] as *const [MaybeUninit<u8>] as *const [u8]) }
    }
    #[inline]
    pub fn unfilled<'cursor>(&'cursor mut self) -> ReadBufCursor<'cursor> {
        ReadBufCursor {
            buf: unsafe {
                std::mem::transmute::<&'cursor mut ReadBuf<'data>, &'cursor mut ReadBuf<'cursor>>(
                    self,
                )
            },
        }
    }

    #[inline]
    fn remaining(&self) -> usize {
        self.capacity() - self.filled
    }

    #[inline]
    fn capacity(&self) -> usize {
        self.raw.len()
    }
}

impl fmt::Debug for ReadBuf<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ReadBuf")
            .field("filled", &self.filled)
            .field("init", &self.init)
            .field("capacity", &self.capacity())
            .finish()
    }
}

impl ReadBufCursor<'_> {
    unsafe fn as_mut(&mut self) -> &mut [MaybeUninit<u8>] {
        &mut self.buf.raw[self.buf.filled..]
    }

    unsafe fn advance(&mut self, n: usize) {
        self.buf.filled = self.buf.filled.checked_add(n).expect("buffer overflow");
        self.buf.init = self.buf.init.max(self.buf.filled);
    }

    fn remaining(&self) -> usize {
        self.buf.remaining()
    }

    fn put_slice(&mut self, src: &[u8]) {
        assert!(self.remaining() >= src.len(), "src must be <= remaining");

        let amt = src.len();
        let end = self.buf.filled + amt;
        unsafe {
            self.buf
                .raw
                .as_mut_ptr()
                .cast::<u8>()
                .copy_from_nonoverlapping(src.as_ptr(), amt);
        }

        if self.buf.init < end {
            self.buf.init = end;
        }

        self.buf.filled = end;
    }
}
macro_rules! deref_async_read {
    () => {
        fn poll_read(
            mut self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            buf: ReadBufCursor<'_>,
        ) -> Poll<std::io::Result<()>> {
            Pin::new(&mut **self).poll_read(cx, buf)
        }
    };
}

impl<T: ?Sized + Read + Unpin> Read for Box<T> {
    deref_async_read!();
}

impl<T: ?Sized + Read + Unpin> Read for &mut T {
    deref_async_read!();
}

impl<P> Read for Pin<P>
where
    P: DerefMut,
    P::Target: Read,
{
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: ReadBufCursor<'_>,
    ) -> Poll<Result<(), std::io::Error>> {
        Pin::as_deref_mut(self).poll_read(cx, buf)
    }
}

macro_rules! deref_async_write {
    () => {
        fn poll_write(
            mut self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            buf: &[u8],
        ) -> Poll<std::io::Result<usize>> {
            Pin::new(&mut **self).poll_write(cx, buf)
        }

        fn poll_write_vectored(
            mut self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            bufs: &[std::io::IoSlice<'_>],
        ) -> Poll<std::io::Result<usize>> {
            Pin::new(&mut **self).poll_write_vectored(cx, bufs)
        }

        fn is_write_vectored(&self) -> bool {
            (**self).is_write_vectored()
        }
        fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
            Pin::new(&mut **self).poll_flush(cx)
        }
        fn poll_shutdown(
            mut self: Pin<&mut Self>,
            cx: &mut Context<'_>,
        ) -> Poll<std::io::Result<()>> {
            Pin::new(&mut **self).poll_shutdown(cx)
        }
    };
}

impl<T: ?Sized + Write + Unpin> Write for Box<T> {
    deref_async_write!();
}
impl<T: ?Sized + Write + Unpin> Write for &mut T {
    deref_async_write!();
}
impl<P> Write for Pin<P>
where
    P: DerefMut,
    P::Target: Write,
{
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        Pin::as_deref_mut(self).poll_write(cx, buf)
    }

    fn poll_write_vectored(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &[std::io::IoSlice<'_>],
    ) -> Poll<std::io::Result<usize>> {
        Pin::as_deref_mut(self).poll_write_vectored(cx, bufs)
    }

    fn is_write_vectored(&self) -> bool {
        (**self).is_write_vectored()
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::as_deref_mut(self).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::as_deref_mut(self).poll_shutdown(cx)
    }
}

use pyo3::types::{PyAnyMethods, PyBytes, PyTuple};
use pyo3::{intern, Bound, PyAny, PyResult};
use std::io::{self, Read, Write};

/// Wrapper to implement the `Read` trait around a Python
/// object that contains a `.read()` function.
pub(crate) struct Stream<'a> {
    pub(crate) reader: Bound<'a, PyAny>,
}

impl Stream<'_> {
    /// Read the specified number of bytes out of the object
    fn read_bytes(&self, len: usize) -> PyResult<Vec<u8>> {
        let func: Bound<'_, PyAny> =
            self.reader.getattr(intern!(self.reader.py(), "read"))?;
        // In Python this is effectively calling `reader.read(len)`
        let args: Bound<PyTuple> = PyTuple::new(self.reader.py(), vec![len])?;
        let bytes: Bound<PyAny> = func.call1(args)?;
        let bytes = bytes.downcast::<PyBytes>()?;
        bytes.extract()
    }
}

impl Read for Stream<'_> {
    fn read(&mut self, mut buf: &mut [u8]) -> std::io::Result<usize> {
        let bytes = self.read_bytes(buf.len()).map_err(|err| {
            // The PyErr could be a type error (e.g. no "read" method) or an
            // actual I/O failure if the read() call failed, let's just treat
            // all of them as "other" for simplicity.
            io::Error::other(err.to_string())
        })?;
        buf.write(bytes.as_slice())
    }
}

use std::fmt;

/// Keylo's errors. Messages are shown to people as-is (after "keylo: ").
#[derive(Debug)]
pub enum Error {
    /// A plain, user-facing problem.
    Keylo(String),
    NotFound(String),
    Exists(String),
    /// The identity check failed or was canceled, or a key doesn't allow it.
    AccessDenied(String),
    Io(std::io::Error),
}

pub type Result<T> = std::result::Result<T, Error>;

impl Error {
    pub fn msg(message: impl Into<String>) -> Self {
        Error::Keylo(message.into())
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Keylo(m) | Error::AccessDenied(m) => f.write_str(m),
            Error::NotFound(name) => write!(f, "No secret named '{name}'."),
            Error::Exists(name) => write!(f, "A secret named '{name}' already exists."),
            Error::Io(e) => write!(f, "{e}"),
        }
    }
}

impl std::error::Error for Error {}

impl From<std::io::Error> for Error {
    fn from(e: std::io::Error) -> Self {
        Error::Io(e)
    }
}

/// Shorthand: `bail!("...")` returns an [`Error::Keylo`].
#[macro_export]
macro_rules! bail {
    ($($arg:tt)*) => { return Err($crate::Error::Keylo(format!($($arg)*))) };
}

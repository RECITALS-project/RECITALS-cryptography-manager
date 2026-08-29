# Exceptions

Every failure in the package raises a subclass of `CryptographyManagerError`,
which the workflow maps onto a status and an HTTP code. The one exception is
`BackendImportError`, raised when an optional backend is unavailable.

::: cryptography_manager.exceptions

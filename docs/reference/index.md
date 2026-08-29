# API Reference

Every page in this section is generated from the source: the signatures come
from the type annotations and the prose from the Google-style docstrings, so
the reference cannot describe a function the code no longer has.

The package is layered, and the reference follows that layering.

| Section | Module | Responsibility |
| --- | --- | --- |
| [Adapters](adapters.md) | `cryptography_manager.adapters` | Wrap a cryptographic backend behind one interface. Speak plain Python types, not request models. |
| [Core](core.md) | `cryptography_manager.core` | Dispatch, the request workflow, privacy budget accounting and the audit trail. |
| [Service layer](service.md) | `cryptography_manager.api`, `.main` | The HTTP envelope, token verification and the ASGI application. |
| [Configuration](config.md) | `cryptography_manager.config` | YAML configuration and environment-derived settings. |
| [Exceptions](exceptions.md) | `cryptography_manager.exceptions` | The error hierarchy every layer raises into. |

A request travels through them in that order: the service layer validates the
envelope and the token, the core workflow checks the budget and dispatches, and
an adapter does the cryptography.

# Adapters

An adapter wraps one cryptographic backend. It takes and returns plain Python
types rather than request models, so it can be unit-tested without the web
stack, and so a missing optional backend breaks only its own operation.

## Base interface

::: cryptography_manager.adapters.base

## Differential privacy

::: cryptography_manager.adapters.differential_privacy

## Encryption and key management

::: cryptography_manager.adapters.encryption

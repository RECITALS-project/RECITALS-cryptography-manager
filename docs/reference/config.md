# Configuration

Two separate mechanisms, deliberately kept apart. `Config` loads the YAML file
that describes cryptographic defaults — query plans, bounds, budget limits.
`Settings` reads deployment concerns from the environment: endpoints,
credentials, limits.

## YAML configuration

::: cryptography_manager.config.config

## Defaults

::: cryptography_manager.config.defaults

## Environment settings

::: cryptography_manager.config.settings

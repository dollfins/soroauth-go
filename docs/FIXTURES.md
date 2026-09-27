# Contract Fixtures

## Vector Schema Versioning

Every golden vector in `testdata/vectors/` carries an explicit `schema_version` field (currently `1`). Loaders check this version and reject any unknown or missing schema version rather than guessing or silently ignoring removed or reinterpreted fields. To bump the version, increment `schema_version` in both the generator and all vector JSON files.

## Social Recovery Account
A custom account supporting a fixed guardian set capable of rotating the signing key after a mandatory timelock.

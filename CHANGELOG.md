# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [v4.0.0] - 2026-04-19

### Breaking Changes

- `AbstractEncryptor::encrypt()` — output format changed from 4 parts to 6 parts: `<ENC>\0v1\0<salt-version>\0<b64-ct>\0<b64-mac>\0<b64-nonce>`. A `v1` format-version field is now inserted after the marker so future format revisions can be rolled out without ambiguity, and a `<salt-version>` field identifies which configured salt was used so multi-salt rotation works end-to-end
- `AbstractEncryptor::__construct()` — signature widened to `array|string $saltsByVersion, string $currentSaltVersion = AbstractEncryptor::DEFAULT_SALT_VERSION`. Passing a single salt string keeps working (coerced into a one-entry map keyed by `default`); passing an `array<string, string>` enables multi-salt mode. The previous `string $salt` signature is retained via the `array|string` union
- `AbstractEncryptor` — HMAC input is now a canonical length-prefixed concatenation (`pack('N', len) . value` for each of `version`, `saltVersion`, `algorithm`, `ciphertext`, `nonce`) instead of raw `algorithm . ciphertext . nonce`. This prevents MAC ambiguity between concatenated fields of variable length. Legacy ciphertexts remain verifiable because `decrypt()` routes 4-part payloads to the legacy HMAC formula
- Re-encrypting existing rows produces different ciphertext/MAC bytes. Any stored ciphertext written by a deterministic encryptor (`Aes256FixedEncryptor`) and used in a WHERE clause must be re-encrypted after upgrade — WHERE queries against legacy 4-part ciphertexts will no longer match values encrypted under v4

### Added

- Multi-salt configuration — first-class support for versioned salt rotation. The bundle config accepts a `salts` map keyed by version, plus `current_salt_version` to pick the active one. The encryptor derives per-version HKDF subkeys, stamps the current version into every new ciphertext, and selects the right subkey automatically on decrypt. Enables online (dual-salt) rotation with no plaintext window. Single-salt setups still use the shorthand `salt` option unchanged
- `AbstractEncryptor::DEFAULT_SALT_VERSION` — public constant (`'default'`) used as the implicit salt-version identifier when a single salt string is provided
- `AbstractEncryptor::FORMAT_VERSION_V1` — public constant exposing the current format version identifier (`'v1'`)
- `AbstractEncryptor::CURRENT_FORMAT_VERSION` — protected constant pointing at the active format version; overridable by subclasses that want to pin or bump the emitted format
- `AbstractEncryptor::computeMessageAuthenticationCode()` — v1 HMAC over canonical length-prefixed `(version, saltVersion, algorithm, ciphertext, nonce)` input
- `AbstractEncryptor::computeLegacyMessageAuthenticationCode()` — pre-v1 HMAC (`algorithm . ciphertext . nonce`); retained exclusively for decrypting data written before v4.0.0
- `Configuration` — new `salts` (map) and `current_salt_version` (scalar) nodes with validation: `salt` and `salts` are mutually exclusive; `current_salt_version` is required when `salts` is used and must reference a key in the map
- `README.md` — "Multi-salt configuration (for key rotation)" section explaining the versioned-salt config format
- `README.md` — "Format versioning" section documenting the v1 wire format (including the salt-version field), canonical HMAC input, and legacy compatibility
- `README.md` — "Upgrading from v3.x to v4.0.0" section with migration steps (decrypt existing rows → re-encrypt to produce v1 ciphertext) and the WHERE-clause caveat for deterministic encryptors
- `README.md` — expanded "Configuration" section with salt-generation guidance, clarified semantics for the `encryptors` and `enabled_types` options, and a note on multi-manager setups
- `README.md` — rewrote "Key rotation limitations" as "Secret rotation" covering built-in online rotation (dual-salt) and the offline maintenance-window procedure
- `README.md` — updated "Security considerations" to reflect per-salt subkey derivation, MAC canonical input including `salt-version`, and the new rotation semantics (dropping a salt makes rows previously written under it unreadable)

### Changed

- `AbstractEncryptor::decrypt()` — transparently reads both 6-part v1 and 4-part legacy payloads; legacy data remains readable without migration and is always decrypted under the currently active salt
- `AbstractEncryptor::looksEncrypted()` — updated to recognize both 4-part and 6-part shapes when guarding against double-encryption
- `PrecisionSoftDoctrineEncryptExtension` — emits two parameters (`precision_soft_doctrine_encrypt.salts_by_version` and `precision_soft_doctrine_encrypt.current_salt_version`) that the `AbstractEncryptor` parent service binds to constructor arguments. Shorthand `salt` is transparently expanded into a one-entry map

## [v3.2.0] - 2026-04-18

### Added

- `Contract\DeterministicEncryptorInterface` — marker interface for encryptors that produce identical ciphertext for identical plaintext. Implemented by `Aes256FixedEncryptor`. Required for `EntityService::setEncryptedParameter()`
- `Exception\NonDeterministicEncryptorException` — thrown by `EntityService::setEncryptedParameter()` when the field's encryptor does not implement `DeterministicEncryptorInterface`, preventing WHERE clauses that would never match
- `README.md` — "Security considerations" entry describing cipher (AES-256-CTR), key derivation (HKDF-SHA256 with per-purpose info strings), and authentication (HMAC-SHA256)
- `README.md` — custom encryptor example demonstrating how to implement `DeterministicEncryptorInterface` for WHERE-compatible encryptors

### Fixed

- `AbstractDatabaseCommand::processEntities()` — `database:decrypt` now actually decrypts. The `FakeEncryptor` swap was previously applied before the SELECT, so entity properties held ciphertext and were written back unchanged on flush. The swap is now scoped to the flush phase only, wrapped in a `finally` block to guarantee restoration
- `EntityService::hasEncryptedValue()` — identifier names, column names, and table names are now quoted via `AbstractPlatform::quoteSingleIdentifier()`, preventing SQL errors when any of them collide with reserved words
- `EntityService::hasEncryptedValue()` — returns `false` immediately when any identifier value is `null`, preventing `WHERE NULL` conditions for unsaved entities
- `AbstractDatabaseCommand::applyKeysetPagination()` — skips `null` identifier values instead of emitting null comparison conditions

### Changed

- `AbstractDatabaseCommand::getManager()` — return type narrowed from `ObjectManager` to `EntityManagerInterface`; throws `Exception` when the registered manager is not an `EntityManagerInterface` (covariant return; commands are ORM-only by contract)
- `EntityService::getEncryptedFields()` — result cached per `($managerName, $class)` pair to avoid repeated metadata factory lookups on every `getEncryptor()` / `hasEncryptor()` / `hasEncryption()` / `encrypt()` / `decrypt()` / `setEncryptedParameter()` call
- `EntityService` — constructor-promoted properties widened from `private readonly` to `protected readonly` for subclass extensibility
- `FakeEncryptor` — expanded internal docblock describing its role in `AbstractDatabaseCommand::resetEncryptorsToFake`
- `EncryptorFactory::__construct()` — added `@info` note explaining why `FakeEncryptor` is always registered regardless of `enabledEncryptors`
- `PrecisionSoftDoctrineEncryptBundle::registerTypes()` — added `\assert(\is_a($typeClass, Type::class, true))` before `Type::addType()` for static analyzer type refinement
- `phpstan-baseline.neon` — shrunk by ~60 entries after adding generic type annotations on `ClassMetadata<object>`, `EntityRepository<object>`, and `int<1, max>` on `AbstractEncryptor::getInitialVectorLength()`

## [v3.1.2] - 2026-04-14

### Fixed

- `EntityService::hasEncryptedValue()` now returns `false` immediately when any identifier value is `null`, preventing `WHERE NULL` conditions for unsaved entities
- `AbstractDatabaseCommand::applyKeysetPagination()` now skips `null` identifier values instead of emitting null comparison conditions

## [v3.1.1] - 2026-04-14

### Changed

- `AbstractDatabaseCommand::executeOperation()` — new template method consolidating the duplicated try/catch, confirmation prompt, and iteration loop previously repeated in `DatabaseDecryptCommand` and `DatabaseEncryptCommand`
- `AbstractDatabaseCommand::BATCH_SIZE` — extracted the magic number `50` from `processEntities()` into a class constant
- `DatabaseDecryptCommand::execute()` / `DatabaseEncryptCommand::execute()` — simplified to a single-line delegation to `executeOperation()`
- `AbstractType::$encryptor` — declared nullable (`?EncryptorInterface = null`) instead of relying on `isset()` for presence detection
- `AbstractType::convertToDatabaseValue()` / `convertToPHPValue()` — now access the encryptor through `getEncryptor()` (which calls `validate()`) instead of duplicating the `validate()` call and touching `$this->encryptor` directly
- `AbstractType::validate()` — `null === $this->encryptor` check replaces the `isset()` check
- `AbstractEncryptor::__debugInfo()` — relocated immediately after the constructor for declaration ordering consistency
- `composer.lock` — bumped `precision-soft/symfony-console` to `v4.2.1`, `precision-soft/symfony-phpunit` to `v3.2.1`, `phpstan/phpstan` to `2.1.47`

## [v3.1.0] - 2026-04-13

### Fixed

- `AbstractDatabaseCommand::processEntities()` — throw project `Exception` instead of generic `\RuntimeException`
- `AbstractEncryptor` — Yoda condition on `>` operator corrected (`static::MINIMUM_KEY_LENGTH > \strlen($salt)` → `\strlen($salt) < static::MINIMUM_KEY_LENGTH`)
- `AbstractEncryptor` — Yoda condition on `>=` operator corrected (`0 >= $initialVectorLength` → `$initialVectorLength <= 0`)

### Changed

- `AbstractEncryptor` — `$mac` renamed to `$messageAuthenticationCode`; `$info` parameter renamed to `$information`
- `AbstractEncryptor` — removed `final` from `getTypeName()`
- `AbstractEncryptor` — `resetEncryptorsToFake()`, `restoreEncryptors()`, `getQuestionText()` visibility widened from `private` to `protected`
- `EncryptorFactory::getType()` — `$dbalType` renamed to `$type`
- `AbstractType` — removed `final` from `getFullName()`, `getEncryptor()`, `setEncryptor()`, `convertToDatabaseValue()`, `convertToPHPValue()`
- `AbstractType` — `validate()` visibility widened from `private` to `protected`
- `FakeEncryptor` — removed `final` modifier
- `StopException` — removed `final` modifier
- `PrecisionSoftDoctrineEncryptBundle` — `registerTypes()` visibility widened from `private` to `protected`
- `EntityService` — `getEncryptedFields()`, `getFieldsForClassMetadata()` visibility widened from `private` to `protected`
- 2 Mockery-based test classes migrated to `AbstractTestCase` (EntityServiceExtendedTest, AbstractDatabaseCommandTest)

## [v3.0.2] - 2026-04-10

### Fixed

- `EntityService::hasEncryptedValue()` — marker check now includes null-byte glue (`ENCRYPTION_MARKER . GLUE`), fixing false positives when a plaintext value starts with `<ENC>`
- `AbstractDatabaseCommand::processEntities()` — add `is_numeric()` guard on COUNT query result; throw `RuntimeException` on non-numeric result
- `AbstractDatabaseCommand::processEntities()` — move encryptor swap/restore outside the batch loop into a single `finally` block; prevents premature restore after each batch iteration
- `DatabaseDecryptCommand` / `DatabaseEncryptCommand` — catch `Throwable` instead of `Exception` to capture all errors, including `RuntimeException`

### Added

- `AbstractEncryptor::__debugInfo()` — returns only algorithm name, preventing sensitive key material from leaking in debug/dump output
- `AbstractEncryptor::$initialVectorLengthCache` — caches `openssl_cipher_iv_length()` result to avoid repeated calls per encrypt/decrypt operation

### Changed

- `AbstractEncryptor::GLUE` — visibility widened from `protected` to `public`; accessible to `EntityService` and external code without class extension
- `EncryptorFactory` — PHPDoc `@param string[]` → `@param class-string[]` for `$enabledEncryptors`
- `composer.lock` — bumped `precision-soft/symfony-console` to `v4.1.2`, `precision-soft/symfony-phpunit` to `v3.1.1`

## [v3.0.1] - 2026-04-08

### Fixed

- `Configuration::getConfigTreeBuilder()` — removed duplicate salt length validation (already enforced at runtime by `AbstractEncryptor::MINIMUM_KEY_LENGTH`)

### Changed

- `AbstractEncryptor::getIvLength()` renamed to `getInitialVectorLength()` — zero-abbreviation naming consistency; affects subclasses that override this method
- `Configuration::getConfigTreeBuilder()` — simplified tree builder, removed redundant chained `->end()` calls on scalar prototype and array nodes

## [v3.0.0] - 2026-04-07

### Breaking Changes

- Dropped Doctrine DBAL 3 support — requires DBAL 4.*
- Removed `AbstractType::getName()` (DBAL 3 compatibility method)
- Rename `AES256Encryptor` to `Aes256Encryptor`, `AES256FixedEncryptor` to `Aes256FixedEncryptor` — CamelCase acronyms naming convention
- Rename `AES256Type` to `Aes256Type`, `AES256FixedType` to `Aes256FixedType` — type short names change from `AES256` to `Aes256` and `AES256fixed` to `Aes256fixed`
- `AbstractEncryptor` — switch to HKDF-derived encryption, MAC, and nonce keys (`hash_hkdf('sha256', ...)`) instead of raw salt; use `hash_hmac()` instead of `hash()` for MAC; remove `serialize()`/`unserialize()` wrapping around plaintext
- `Aes256FixedEncryptor::generateNonce()` — use HKDF-derived `$nonceKey` for HMAC key; rewrite deterministic nonce from cyclic character loop to `hash_hmac('sha256')` truncated to IV length
- `AbstractEncryptor::getTypeClass()` return type narrowed from `?string` to `string`
- `AbstractEncryptor::getTypeName()` return type narrowed from `?string` to `string`
- `EntityService::isEncrypted()` renamed to `hasEncryption()` — consistent boolean query naming convention
- `EntityService::isValueEncrypted()` renamed to `hasEncryptedValue()` — consistent boolean query naming convention
- Upgrade `precision-soft/symfony-console` from `2.*` to `^4.0`

### Fixed

- `Aes256Encryptor::generateNonce()` — add `false`/zero guard on `openssl_cipher_iv_length()` before `random_bytes()`
- `Aes256FixedEncryptor::generateNonce()` — add `false` guard on `openssl_cipher_iv_length()` before `substr()`
- `AbstractEncryptor::encrypt()` — strengthen double-encrypt guard: validate base64 content of ciphertext, MAC, and nonce parts before treating a value as already-encrypted (previously only checked part count)
- `AbstractType::convertToDatabaseValue()` / `convertToPHPValue()` — throw `Exception` when value is not a string, preventing silent type coercion
- `AbstractType::getSQLDeclaration()` — default to `VARCHAR(1000)` when no column length specified, preventing silent data truncation of encrypted values
- `AbstractDatabaseCommand` — read full original entity data from UnitOfWork before overriding encrypted fields with null, preventing unnecessary UPDATEs on non-encrypted columns; replace OFFSET pagination with keyset pagination to avoid consistency issues on large tables
- `DatabaseDecryptCommand` / `DatabaseEncryptCommand` — replace `PARTIAL e.{fields}` with `select('e')` (DBAL 4 compatibility); catch `Exception` instead of `Throwable`
- `EncryptorFactory` — always include `FakeEncryptor` even when `enabledEncryptors` filter is active
- `EntityService::hasEncryptedValue()` — add `is_string()` guard before `str_starts_with()` to prevent `TypeError` on non-string raw values
- `EntityService` — skip fields where `getTypeName()` returns `null` (`FakeEncryptor` compatibility)
- `PrecisionSoftDoctrineEncryptBundle` — add null container guards in `boot()` and `registerTypes()`
- `EntityService::hasEncryptor()` — explicit `true === isset()` instead of implicit boolean

### Added

- `AbstractEncryptor::getIvLength()` — extracted IV length retrieval with false/zero guard; throws `Exception` when `openssl_cipher_iv_length()` returns `false` or `0`
- `AbstractDatabaseCommand::processEntities()` — template method replacing duplicated `encrypt`/`decrypt` loops; manages progress bar, entity manager lifecycle, and encryptor swapping
- `AbstractDatabaseCommand::applyKeysetPagination()` — keyset pagination support for both single and composite primary keys
- `Configuration` — salt validation: minimum 32 characters enforced at bundle configuration time
- `EncryptorFactory` — `encryptorsByTypeName` lookup cache for O(1) encryptor resolution by type name
- PHPStan level 8 with baseline
- Test classes: `ConfigurationTest`, `PrecisionSoftDoctrineEncryptExtensionTest`, `EntityMetadataDtoTest`, `AbstractEncryptorCryptoTest`, `AbstractDatabaseCommandTest`, `Aes256EncryptorTest`, `AbstractTypeTest`, `ExceptionTest`, `EncryptorFactoryExtendedTest`, `EntityServiceExtendedTest`, `PrecisionSoftDoctrineEncryptBundleTest`

### Changed

- Upgrade from PHPUnit 9 to PHPUnit 11.5 via `precision-soft/symfony-phpunit: ^3.0`
- Replace `<coverage>` with `<source>`, `<listeners>` with `<extensions>` in `phpunit.xml.dist`
- Add `failOnRisky` and `failOnWarning` attributes to `phpunit.xml.dist`
- Replace `@dataProvider` PHPDoc annotations with `#[DataProvider]` attributes in `AbstractEncryptorCryptoTest`
- `AbstractEncryptor` — Yoda comparison on salt length check (`MINIMUM_KEY_LENGTH > strlen($salt)`)
- `AbstractEncryptor::decrypt()` — rename `$parts` to `$encryptedParts` for clarity
- `AbstractType::getSQLDeclaration()` — simplify `isset($column['length']) || null === $column['length']` → `isset($column['length'])`
- Replaced `squizlabs/php_codesniffer` with PHPStan for static analysis
- Descriptive variable names across all source and test files
- Standardized `.dev/` infrastructure (Dockerfile, docker-compose, pre-commit, utility.sh, .profile)
- Renamed `phpunit.xml` to `phpunit.xml.dist`
- Quote `$COMPOSER_DEV_MODE` variable in `composer.json` hook script

## [v2.2.4] - 2026-03-21

### Fixed

- README — correct repository clone URL

## [v2.2.3] - 2026-03-19

### Fixed

- README — fix formatting and usage examples

## [v2.2.2] - 2026-03-19

### Fixed

- `AES256FixedEncryptor::generateNonce()` — fix off-by-one nonce generation (cyclic loop was producing incorrect nonce length)

### Changed

- `AbstractEncryptor` — extracted shared `encrypt()` and `decrypt()` logic from `AES256Encryptor` and `AES256FixedEncryptor`; both encryptors now delegate entirely to the base class
- `AbstractEncryptor::getTypeClass()` declared `abstract`
- `AbstractEncryptor::generateNonce()` declared `abstract`
- `AES256Encryptor` / `AES256FixedEncryptor` — removed duplicated encrypt/decrypt/constructor logic; now only implement `getTypeClass()` and `generateNonce()`

## [v2.2.1] - 2026-03-19

### Added

- Test classes: `DatabaseDecryptCommandTest`, `DatabaseEncryptCommandTest`, `EncryptorFactoryTest`, `AES256FixedTypeTest`
- Expanded `EntityServiceTest` coverage

### Changed

- Renamed `dev/` to `.dev/` for hidden directory convention

## [v2.2.0] - 2026-03-13

### Added

- `Configuration` — `enabled_types` and `encryptors` nodes: allow restricting active encryptors per bundle configuration
- `FakeEncryptor` — no-op encryptor for use in test environments
- Test classes: `AES256EncryptorTest`, `AES256FixedEncryptorTest`, `FakeEncryptorTest`, `AES256TypeTest`

### Fixed

- `AbstractDatabaseCommand::getManagerName()` — return `null` when option value is not a string (prevents type error on missing option)

### Changed

- `DatabaseDecryptCommand` / `DatabaseEncryptCommand` — replace `configure()` + `setName()` with `#[AsCommand]` attribute
- `AbstractDatabaseCommand` — Yoda conditions, descriptive variable names, inline `getManager()` call
- Code style alignment across all source files (Yoda comparisons, `[] === $x` over `empty($x)`, catch variable naming)

## [v2.1.0] - 2025-01-06

### Changed

- Allow `precision-soft/symfony-console 2.*`

## [v2.0.0] - 2024-11-24

### Added

- Doctrine DBAL 4 support (`doctrine/dbal: ^4.0`)

### Changed

- Constructor property promotion across `AbstractEncryptor`, `AbstractDatabaseCommand`, `EntityService`, `EntityMetadataDto`
- `AbstractType` — remove space before cast: `(string) $value` → `(string)$value`

## [v1.0.0] - 2024-09-17

### Added

- `AbstractEncryptor` + `AES256Encryptor` / `AES256FixedEncryptor` — AES-256 encryption primitives (random-nonce and deterministic variants)
- `FakeEncryptor` — no-op encryptor for test environments
- Custom Doctrine DBAL types: `AbstractType`, `AES256Type`, `AES256FixedType` — transparent encrypt/decrypt on persistence
- `EncryptorFactory` — resolves encryptors by type name/class; tracks registered encryptors
- `EntityService` — metadata helpers (`isEncrypted()`, `isValueEncrypted()`, encrypted-field enumeration) for entity-level workflows
- `EntityMetadataDto` — encrypted-field metadata snapshot used by `EntityService` and the database commands
- `DatabaseEncryptCommand` and `DatabaseDecryptCommand` — console commands that re-encrypt or decrypt existing data in bulk; share logic via `AbstractDatabaseCommand`
- Project-specific exception hierarchy: `Exception`, `DuplicateEncryptorException`, `EncryptorNotFoundException`, `FieldNotEncryptedException`, `TypeNotFoundException`, `StopException`
- `PrecisionSoftDoctrineEncryptBundle` + `PrecisionSoftDoctrineEncryptExtension` + `Configuration` — Symfony DI integration and config tree
- `EncryptorInterface` contract for custom encryptor implementations

### Notes

- Initial public release of `precision-soft/symfony-doctrine-encrypt`

[Unreleased]: https://github.com/precision-soft/symfony-doctrine-encrypt/compare/v4.0.0...HEAD

[v4.0.0]: https://github.com/precision-soft/symfony-doctrine-encrypt/compare/v3.2.0...v4.0.0

[v3.2.0]: https://github.com/precision-soft/symfony-doctrine-encrypt/compare/v3.1.2...v3.2.0

[v3.1.2]: https://github.com/precision-soft/symfony-doctrine-encrypt/compare/v3.1.1...v3.1.2

[v3.1.1]: https://github.com/precision-soft/symfony-doctrine-encrypt/compare/v3.1.0...v3.1.1

[v3.1.0]: https://github.com/precision-soft/symfony-doctrine-encrypt/compare/v3.0.2...v3.1.0

[v3.0.2]: https://github.com/precision-soft/symfony-doctrine-encrypt/compare/v3.0.1...v3.0.2

[v3.0.1]: https://github.com/precision-soft/symfony-doctrine-encrypt/compare/v3.0.0...v3.0.1

[v3.0.0]: https://github.com/precision-soft/symfony-doctrine-encrypt/compare/v2.2.4...v3.0.0

[v2.2.4]: https://github.com/precision-soft/symfony-doctrine-encrypt/compare/v2.2.3...v2.2.4

[v2.2.3]: https://github.com/precision-soft/symfony-doctrine-encrypt/compare/v2.2.2...v2.2.3

[v2.2.2]: https://github.com/precision-soft/symfony-doctrine-encrypt/compare/v2.2.1...v2.2.2

[v2.2.1]: https://github.com/precision-soft/symfony-doctrine-encrypt/compare/v2.2.0...v2.2.1

[v2.2.0]: https://github.com/precision-soft/symfony-doctrine-encrypt/compare/v2.1.0...v2.2.0

[v2.1.0]: https://github.com/precision-soft/symfony-doctrine-encrypt/compare/v2.0.0...v2.1.0

[v2.0.0]: https://github.com/precision-soft/symfony-doctrine-encrypt/compare/v1.0.0...v2.0.0

[v1.0.0]: https://github.com/precision-soft/symfony-doctrine-encrypt/releases/tag/v1.0.0

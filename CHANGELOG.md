# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Fixed

- `AbstractDatabaseCommand::processEntities()` — throw project `Exception` instead of generic `\RuntimeException`

### Changed

- `AbstractEncryptor` — `$mac` renamed to `$messageAuthenticationCode`; `$info` parameter renamed to `$information`
- `EncryptorFactory::getType()` — `$dbalType` renamed to `$type`
- `AbstractType` — removed `final` from `getFullName()`, `getEncryptor()`, `setEncryptor()`, `convertToDatabaseValue()`, `convertToPHPValue()`
- `FakeEncryptor` — removed `final` modifier
- `StopException` — removed `final` modifier
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

Initial release.

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

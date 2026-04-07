# Changelog

All notable changes to `precision-soft/symfony-doctrine-encrypt` will be documented in this file.

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

[v3.0.0]: https://github.com/precision-soft/symfony-doctrine-encrypt/compare/v2.2.4...v3.0.0

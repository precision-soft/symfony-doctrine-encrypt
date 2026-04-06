# CHANGELOG

## v3.0.0

### Breaking Changes

- Dropped Doctrine DBAL 3 support — requires DBAL 4.*
- Removed `AbstractType::getName()` (DBAL 3 compatibility method)
- Rename `AES256Encryptor` to `Aes256Encryptor`, `AES256FixedEncryptor` to `Aes256FixedEncryptor` — CamelCase acronyms naming convention
- Rename `AES256Type` to `Aes256Type`, `AES256FixedType` to `Aes256FixedType` — type short names change from `AES256` to `Aes256` and `AES256fixed` to `Aes256fixed`
- `AbstractEncryptor` — use HKDF-derived encryption and MAC keys instead of raw salt; remove `serialize()`/`unserialize()` wrapping; use `hash_hmac()` instead of `hash()` for MAC computation
- `Aes256FixedEncryptor::generateNonce()` — use HKDF-derived `$nonceKey` instead of raw `$salt` for HMAC key; rewrite deterministic nonce from cyclic character loop to `hash_hmac('sha256')` truncated to IV length
- `AbstractEncryptor::encrypt()` — skip encryption if data already has encryption marker (double-encrypt guard)
- Upgrade `precision-soft/symfony-console` from `2.*` to `^4.0`

### Fixed

- `Aes256Encryptor::generateNonce()` — add `false`/zero guard on `openssl_cipher_iv_length()` before `random_bytes()`
- `Aes256FixedEncryptor::generateNonce()` — add `false` guard on `openssl_cipher_iv_length()` before `substr()`
- `PrecisionSoftDoctrineEncryptBundle` — add null container guards in `boot()` and `registerTypes()`
- `EntityService::hasEncryptor()` — explicit `true === isset()` instead of implicit boolean
- `EntityService::isValueEncrypted()` — explicit `true === str_starts_with()` instead of implicit boolean
- `DatabaseDecryptCommand` / `DatabaseEncryptCommand` — replace `PARTIAL e.{fields}` with `select('e')` (DBAL 4 compatibility)
- `EncryptorFactory` — always include `FakeEncryptor` even when `enabledEncryptors` filter is active
- `AbstractDatabaseCommand::getOriginalEntityData()` — read full original entity data from UnitOfWork before overriding encrypted fields with null, preventing unnecessary UPDATEs on non-encrypted columns
- `AbstractType::getSQLDeclaration()` — default to `VARCHAR(1000)` when no column length specified, preventing silent data truncation of encrypted values

### Added

- PHPStan level 8 with baseline
- Test classes: `ConfigurationTest`, `PrecisionSoftDoctrineEncryptExtensionTest`, `EntityMetadataDtoTest`, `AbstractEncryptorCryptoTest`, `AbstractTypeTest`, `ExceptionTest`, `EncryptorFactoryExtendedTest`, `EntityServiceExtendedTest`, `PrecisionSoftDoctrineEncryptBundleTest`
- Expanded test coverage (143 tests, 261 assertions)

### Changed

- Upgrade from PHPUnit 9 to PHPUnit 11.5 via `precision-soft/symfony-phpunit: ^3.0`
- Replace `<coverage>` with `<source>`, `<listeners>` with `<extensions>` in `phpunit.xml.dist`
- Add `failOnRisky` and `failOnWarning` attributes to `phpunit.xml.dist`
- Replace `@dataProvider` PHPDoc annotations with `#[DataProvider]` attributes in `AbstractEncryptorCryptoTest`
- Replaced `squizlabs/php_codesniffer` with PHPStan for static analysis
- Descriptive variable names across all source and test files
- Standardized `.dev/` infrastructure (Dockerfile, docker-compose, pre-commit, utility.sh, .profile)
- Renamed `phpunit.xml` to `phpunit.xml.dist`
- Quote `$COMPOSER_DEV_MODE` variable in `composer.json` hook script
- Extract shared loop logic into `AbstractDatabaseCommand::processEntities()` template method, eliminating duplication between `DatabaseDecryptCommand` and `DatabaseEncryptCommand`

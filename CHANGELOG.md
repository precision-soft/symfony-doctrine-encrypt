# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [v4.6.0] - 2026-09-01 - Online salt rotation with resumable, verifiable batch runs

### Added

- `precision-soft:doctrine:database:rotate` rewrites loaded plaintext directly with the configured current salt, so online rotation no longer needs a database-wide plaintext interval between decrypt and encrypt commands.
- `--entity`, `--from-id`, `--checkpoint` and `--dry-run` on all three database commands. Entity selection restricts a run to named classes, the checkpoint is a json file replaced atomically after every flushed batch so an interrupted run resumes where it stopped, and a dry run walks every selected row without writing.
- `--verify` on `database:rotate` reads the stored columns back and fails unless every selected value carries the current salt version.
- `AbstractEncryptor::getCurrentSaltVersion()` exposes the version new writes are stamped with, and `AbstractEncryptor::getCurrentEnvelopePrefix()` the envelope prefix they carry — so a caller never has to reassemble the envelope layout itself.

### Changed

- `symfony/config` now accepts 7.x and 8.x, and `precision-soft/symfony-console` is required from `^4.7`, the first release that allows Symfony 8 across every component it pulls in. Symfony 8 itself needs PHP 8.4, so a PHP 8.2 or 8.3 install still resolves Symfony 7. CI covers PHP 8.2 through 8.5 and adds a lane resolving the highest allowed dependency set.
- The progress bar now counts the rows a run will actually walk, so a resume no longer reports a total it can never reach.

### Fixed

- `--verify` escaped nothing before matching the salt-version prefix, so a salt version containing `_` — legal under `SALT_VERSION_PATTERN` — was matched as a `LIKE` wildcard and rows written under a *different* salt could pass verification. The prefix is now escaped and matched with an explicit `ESCAPE` clause.
- A checkpoint file listing an entity as completed replayed that entity's stale cursor on the next run, so reusing a checkpoint for a second rotation scanned no rows and still reported success. A completed entity now starts over.
- `--from-id` was bound as a string against an integer identifier, which only works on engines that coerce silently. The value is now cast to the identifier's mapped type, and rejected when it cannot be.
- `AbstractEncryptor` now rejects a salts map whose versions differ only by letter case; under a case-insensitive column collation those versions are indistinguishable to the prefix check `--verify` relies on.
- `--verify` built its prefix from `FORMAT_VERSION_V1` rather than the encryptor's own current format version, so a subclass overriding `CURRENT_FORMAT_VERSION` would have seen every row reported as stale. It now asks the encryptor for the prefix.
- A checkpoint cursor whose keys do not address the entity's identifier fields is now rejected. It previously fell through `applyKeysetPagination` as a null value and silently rescanned the table from the first row, or — for a composite identifier with no usable field — produced an empty `WHERE` group.
- `--entity` now drops a repeated class name, which otherwise made `--from-id` refuse a single selected entity.

## [v4.5.0] - 2026-08-17 - Identifier-complete lookups, no key material in serialize, and a real database suite

### Fixed

- `EntityService::hasEncryptedValue()` — returned a verdict derived from an unrelated row when the entity was not fully identified. The guard tested `in_array(null, $identifiers, true)`, which can never be true: Doctrine's `getIdentifierValues()` **omits** null identifiers rather than returning them, so a transient entity yielded `[]` and a partly-populated composite key yielded a short array. Both fell through and built a `SELECT` with no `WHERE` clause — or with only part of one — so the method answered from whatever row the database returned first. The identifier set is now required to be complete, and no query is issued otherwise. Found by the new integration suite; the unit tests could not see it because they mock the connection
- `phpstan-baseline.neon` — **deleted.** It was 61 lines / 10 entries / 18 suppressed occurrences, and eight of those were a single habit: `base64_decode(…, true)` returns `string|false` and the crypto tests consumed the result directly. Decoding now goes through `tests/Utility/Base64Decoder`, which asserts the payload really is strict base64 instead of letting an invalid one surface as a `TypeError` three lines later — and the same helper replaced three `assert(false !== …)` narrowings that `zend.assertions=-1` had compiled out in every environment, the containers included. The rest were seventeen `/** @var X|MockInterface */` and `/** @var X */` docblocks over `MockContainerTrait::get()`, whose generic return type already yields the correct `MockInterface&T` and which the docblocks were overriding with something weaker, and two `assertIsArray()` calls on typed returns, now assertions on the factory's actual keys and type names. Level 8 is `[OK]` with two `ignoreErrors` entries in
  `phpstan.neon`, each stating its reason
- `AbstractEncryptor::encryptWithSaltVersion()` — did not apply the already-encrypted pass-through guard that `encrypt()` applies, so the write path stored a marker-shaped value untouched while the deterministic lookup path re-encrypted it. A `WHERE ... IN (...)` built from `getDeterministicCiphertextCandidates()` / `setEncryptedParameterInList()` could therefore never match the row that had been written. The guard is applied after the salt-version check, so an unknown version remains a loud error rather than a silent pass-through

### Changed

- `AbstractEncryptor::__serialize()` / `__unserialize()` — added, and both throw. An encryptor holds the HKDF-derived encryption, authentication and nonce subkeys in ordinary properties, so `serialize()` previously wrote them verbatim into whatever store the caller was using — a session, a cache entry, a queued message. `__debugInfo()` only ever covered `var_dump()`/`print_r()`. Refusing is louder and safer than emitting a redacted object that would then decrypt nothing. **`var_export()` is not covered and cannot be**: PHP provides no hook for it, so it is documented in the README's Security considerations instead
- `EntityService::getEncryptedFields()` — the unknown-class guard was an `assert()`, which `zend.assertions=-1` compiles out in production *and* in this project's containers, so it had never executed in any environment. It is now a real check throwing `Exception`, matching the two sibling guards converted before it. Callers passing a class name that does not exist now get a message naming the bundle and the class instead of a Doctrine mapping error further down
- `Configuration` — dropped `defaultNull()` from the `enabled_types` and `encryptors` scalar prototypes. A default declared on a prototype is never consulted; both nodes resolved to `[]` before and after, which is now pinned by a test
- comments across the package normalized to the house rule — the default is no comment, and a warranted one is a single short line. Every multi-line rationale block, narrative test docblock and shell section header was removed; the `.dev/` scripts, the `Dockerfile` and the compose file now carry nothing but their shebang and one line about `tini` as PID 1. Nothing behavioral changed. `CONTRIBUTING.md` gained the two sections that now carry the rationale — *Development toolchain* (the pinned pcov and infection builds, the `php.dev.ini` overlay, the `db` profile, the mutation thresholds) and *Continuous integration* (the jobs, and why `--fail-on-skipped` is passed in CI only) — and its *Verification* section now documents `.dev/validate/all.sh` and its flags, replacing the stale description of the old hook

### Added

- `Contract\ExceptionInterface` and `Exception\Trait\ExceptionTrait` — exceptions now carry a structured `context` array alongside the message, read with `getContext()` and set with `setContext()` or the new fourth constructor argument. The context is purely additive: no existing message, code or previous throwable changed, so a consumer logging only `getMessage()` sees exactly what it saw before. Ported from `precision-soft/symfony-console`, which has carried it since v4.5.0, so every package in the portfolio now exposes the same contract. Note for consumers subclassing the package exception: a subclass that already declares its own `$context` property or a `getContext()`/`setContext()` method will collide with the trait
- `tests/Functional/` — the first integration suite in this bundle's history, executing real SQL against both MySQL 8.4 and MariaDB 11.4. It proves what no unit test could: that an encrypted field is ciphertext in the column and plaintext in PHP, that `Aes256FixedType` is matchable in a `WHERE` clause (the entire reason the type exists), that a rotation-safe `IN (...)` lookup still finds rows written under a previous salt, that `hasEncryptedValue()` works against a real schema, and that the encrypt/decrypt commands migrate a real table idempotently and across batches. Every test is `#[Group('integration')]` and skips — never fails — when the database is absent
- `composer test-integration` — runs the integration group; `composer test` now excludes it, so `composer check` stays fast and offline
- coverage for two `EntityService` contracts the unit suite could not see. **`hasEncryptedValue()`'s `WHERE` clause is now asserted predicate by predicate**: the query-builder mock expected `andWhere()` and `setParameter()` with no arguments and no cardinality, so a query built with **no `WHERE` at all** satisfied it — the very defect this method was fixed for, since an unpredicated `SELECT` answers from an arbitrary row. Removing the clause now turns four tests red instead of none. **And the encrypted-field cache is asserted to be keyed by the entity class**: the key is `($managerName ?? '') . '|' . $class`, and without the class one entity is handed another's field list, which decides whether values are encrypted on write and decrypted on read
- Tamper-matrix, adversarial-corpus and secret-hygiene test suites for the encryptors: every single-bit flip and truncation of a payload, cross-epoch salt-version substitution, format-version forgery, legacy-shape downgrade, all 256 single-byte plaintexts, block/IV-size boundaries, multi-megabyte values, and assertions that no dump or error path exposes the salt or any derived key

## [v4.4.0] - 2026-06-17 - Configurable batch size for encrypt and decrypt commands

### Added

- `AbstractDatabaseCommand` — `--batch-size` option (default `50`) controls how many entities are processed per batch in the encrypt/decrypt commands; the value is validated as a positive integer and rejected otherwise. Lets large or memory-constrained databases tune throughput instead of the hard-coded `50`
- `composer.json` — added `test`, `phpstan`, `cs-check`, `cs-fix` and an aggregate `check` convenience script wrapping `simple-phpunit`, `phpstan`, and `php-cs-fixer`

### Changed

- `AbstractEncryptor::looksEncrypted()` — documented that the `<ENC>\0` prefix is reserved and that the check validates ciphertext shape only, not the MAC

## [v4.3.1] - 2026-04-23 - Widen AbstractType and AbstractEncryptor visibility for extensibility

### Changed

- `AbstractType::setEncryptor()` — return type widened from `self` to `static`; `AbstractType` is abstract and both `Aes256Type` and `Aes256FixedType` extend it, so fluent chains that call `setEncryptor()` on a concrete subclass now correctly return the subclass type instead of `AbstractType`
- `AbstractEncryptor::$encryptionKeysBySaltVersion`, `$macKeysBySaltVersion`, `$nonceKeysBySaltVersion` — visibility widened from `private readonly` to `protected readonly`; these derived-key caches are in an abstract class that must be subclassed to use, so concrete extensions that override `encrypt()` or `decrypt()` can now access the key material directly
- `AbstractEncryptor::$initialVectorLengthCache` — visibility widened from `private` to `protected` for the same reason

## [v4.3.0] - 2026-04-23 - Visibility widening for library extensibility

### Changed

- `AbstractType::$encryptor` — widened from `private` to `protected` so subclasses can access or replace the encryptor instance without going through the public getter/setter
- `EntityMetadataDto::$classMetadata` / `$encryptionFields` — widened from `private` to `protected`; the DTO can be subclassed with direct property reads instead of going through the public getters
- `EncryptorFactory::$encryptors`, `$encryptorsByTypeName`, `$typeNames` — widened from `private` to `protected`; matches the progressive visibility-widening pattern established in v3.1.0 and v4.2.0

## [v4.2.0] - 2026-04-23 - Late-static-binding and library-extensibility fixes

### Changed

- `AbstractEncryptor` — switched `self::ENCRYPTION_MARKER`, `self::SALT_VERSION_PATTERN`, and `self::DEFAULT_SALT_VERSION` to `static::` inside `decrypt()`, `encryptWithSaltVersion()`, `looksEncrypted()`, and the constructor body, so subclasses that override these public constants are honored. Byte-identical behavior for the base class; the default-parameter reference still uses `self::` because PHP 8.2 does not allow `static::` in default parameter values
- `AbstractEncryptor::looksEncrypted()` — locals renamed `$parts` → `$encryptedParts` and `$count` → `$partCount` for consistency with `decrypt()` in the same class
- `Aes256FixedEncryptor::generateNonceForSaltVersion()` — hardcoded `'sha256'` string replaced with `static::HASH_ALGORITHM` so subclasses that override the hash algorithm are honored; byte-identical behavior for the base class
- `PrecisionSoftDoctrineEncryptBundle::registerTypes()` — two adjacent floating docblocks (`@info` and `@var`) merged into a single docblock attached to `$encryptorFactory`
- `README.md` — `EntityService` API table updated to show `getEntitiesWithEncryption(managerName?)` matching the renamed parameter
- `README.md` — service-tag reference corrected from `precision_soft.doctrine.encrypt.encryptor` (wrong separators and extra segment) to the actual tag `precision-soft.doctrine.encryptor` as defined by `PrecisionSoftDoctrineEncryptExtension::DOCTRINE_ENCRYPTOR`
- `composer.json` — `description` field expanded from the placeholder `doctrine encrypt type` to a descriptive one-liner for Packagist listings (`Symfony bundle providing transparent AES-256 encryption for Doctrine ORM entity fields via custom DBAL types`)
- `AbstractType::getSQLDeclaration()` — switched `self::DEFAULT_LENGTH` to `static::DEFAULT_LENGTH` for the same reason
- `AbstractDatabaseCommand` — switched `self::OPTION_MANAGER` and `self::BATCH_SIZE` to `static::` inside `configure()`, `getManagerName()`, and `processEntities()`
- `EntityService::getEntitiesWithEncryption()` — parameter renamed from `$manager` to `$managerName` for consistency with every other method in the class (the bare `$manager` was the last odd one out). Positional callers are unaffected; named-argument callers (`getEntitiesWithEncryption(manager: '…')`) must update the keyword
- `CHANGELOG.md` — every historical entry now carries a `## [vX.Y.Z] - YYYY-MM-DD - Title` heading conforming to the precision-soft audit format; section ordering normalized per entry to the canonical `Breaking Changes → Fixed → Changed → Added → Deprecated → Removed`; `v2.2.4` release date corrected (`2026-03-20` → `2026-03-21`) to match the actual tag date; `v1.0.0` `### Notes` subsection dropped

### Added

- `AbstractType::DEFAULT_LENGTH` — visibility widened from `private` to `protected` so subclasses can override the default column length used when no explicit length is configured
- `AbstractDatabaseCommand::BATCH_SIZE` — visibility widened from `private` to `protected` so subclasses can tune the bulk-operation batch size
- `EntityService::getDeterministicEncryptor()` — visibility widened from `private` to `protected` for subclass extensibility (matches the v3.1.0 widening pattern across the rest of `EntityService`)

## [v4.1.0] - 2026-04-20 - Legacy-salt routing, deterministic rotation, and salt-version validation

### Changed

- `Aes256FixedEncryptor` — deterministic nonce derivation is now per-salt-version so the same plaintext under different salt epochs produces distinct ciphertext. Single-salt deployments are byte-identical (nonce key resolves to the current-version entry)
- `AbstractEncryptor::deriveKey()` — renamed first parameter `$salt` to `$masterKey` with an `@info` docblock clarifying that the bundle's "salt" config value is the HKDF IKM and the HKDF salt parameter is intentionally empty
- `src/Resources/config/services.php` / `PrecisionSoftDoctrineEncryptExtension` — wire the new `legacy_salt_version` parameter into the encryptor parent service

### Added

- `AbstractEncryptor::__construct()` — new optional `?string $legacySaltVersion = null` parameter (third argument) identifying which salt-version key to use when decrypting legacy 4-part payloads. Defaults to the first key in `$saltsByVersion` so existing single-salt configs decrypt legacy data without change
- `AbstractEncryptor::encryptWithSaltVersion()` — public method producing a v1 payload stamped with an explicit salt-version, so deterministic lookups can enumerate candidate ciphertexts across all active versions
- `AbstractEncryptor::getActiveSaltVersions()` — returns the configured salt-version identifiers in declaration order, used by the deterministic WHERE-IN helper
- `AbstractEncryptor::generateNonceForSaltVersion()` — protected hook letting deterministic subclasses derive a per-version nonce (keyed by `nonceKeysBySaltVersion[saltVersion]`) so each salt epoch produces a distinct deterministic nonce
- `EntityService::setEncryptedParameterInList()` — binds a deterministic query parameter as an `IN (...)` of per-salt-version ciphertext candidates, so WHERE clauses against deterministic fields continue to match across rotation
- `EntityService::getDeterministicCiphertextCandidates()` — produces the candidate list for manual `IN (...)` construction
- `Configuration` — new `legacy_salt_version` node (optional, falls back to the first key in `salts`); enforces the salt-version regex at config time
- `AbstractEncryptor::SALT_VERSION_PATTERN` — `/^[A-Za-z0-9_.-]{1,32}$/` validation of salt-version identifiers at construction and via the Configuration node; dots are permitted so version identifiers like `v1.0` or `2026.04` are accepted
- `Configuration` — rejects `legacy_salt_version` when combined with the single-salt `salt` shorthand; the option only makes sense with the multi-salt `salts` map
- `tests/Encryptor/RotationTest.php` — 16 cases covering legacy-decrypt, multi-salt rotation, deterministic-IN enumeration, and salt-version validation

## [v4.0.0] - 2026-04-19 - Multi-salt rotation, v1 wire format, and canonical HMAC

### Breaking Changes

- `AbstractEncryptor::encrypt()` — output format changed from 4 parts to 6 parts: `<ENC>\0v1\0<salt-version>\0<b64-ct>\0<b64-mac>\0<b64-nonce>`. A `v1` format-version field is now inserted after the marker so future format revisions can be rolled out without ambiguity, and a `<salt-version>` field identifies which configured salt was used so multi-salt rotation works end-to-end
- `AbstractEncryptor::__construct()` — signature widened to `array|string $saltsByVersion, string $currentSaltVersion = AbstractEncryptor::DEFAULT_SALT_VERSION`. Passing a single salt string keeps working (coerced into a one-entry map keyed by `default`); passing an `array<string, string>` enables multi-salt mode. The previous `string $salt` signature is retained via the `array|string` union
- `AbstractEncryptor` — HMAC input is now a canonical length-prefixed concatenation (`pack('N', len) . value` for each of `version`, `saltVersion`, `algorithm`, `ciphertext`, `nonce`) instead of raw `algorithm . ciphertext . nonce`. This prevents MAC ambiguity between concatenated fields of variable length. Legacy ciphertexts remain verifiable because `decrypt()` routes 4-part payloads to the legacy HMAC formula
- Re-encrypting existing rows produces different ciphertext/MAC bytes. Any stored ciphertext written by a deterministic encryptor (`Aes256FixedEncryptor`) and used in a WHERE clause must be re-encrypted after upgrade — WHERE queries against legacy 4-part ciphertexts will no longer match values encrypted under v4

### Changed

- `AbstractEncryptor::decrypt()` — transparently reads both 6-part v1 and 4-part legacy payloads; legacy data remains readable without migration and is always decrypted under the currently active salt
- `AbstractEncryptor::looksEncrypted()` — updated to recognize both 4-part and 6-part shapes when guarding against double-encryption
- `PrecisionSoftDoctrineEncryptExtension` — emits two parameters (`precision_soft_doctrine_encrypt.salts_by_version` and `precision_soft_doctrine_encrypt.current_salt_version`) that the `AbstractEncryptor` parent service binds to constructor arguments. Shorthand `salt` is transparently expanded into a one-entry map

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

## [v3.2.0] - 2026-04-18 - Deterministic encryptor interface and WHERE-query support

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

### Added

- `Contract\DeterministicEncryptorInterface` — marker interface for encryptors that produce identical ciphertext for identical plaintext. Implemented by `Aes256FixedEncryptor`. Required for `EntityService::setEncryptedParameter()`
- `Exception\NonDeterministicEncryptorException` — thrown by `EntityService::setEncryptedParameter()` when the field's encryptor does not implement `DeterministicEncryptorInterface`, preventing WHERE clauses that would never match
- `README.md` — "Security considerations" entry describing cipher (AES-256-CTR), key derivation (HKDF-SHA256 with per-purpose info strings), and authentication (HMAC-SHA256)
- `README.md` — custom encryptor example demonstrating how to implement `DeterministicEncryptorInterface` for WHERE-compatible encryptors

## [v3.1.1] - 2026-04-14 - Command execution template and type refinement

### Changed

- `AbstractDatabaseCommand::executeOperation()` — new template method consolidating the duplicated try/catch, confirmation prompt, and iteration loop previously repeated in `DatabaseDecryptCommand` and `DatabaseEncryptCommand`
- `AbstractDatabaseCommand::BATCH_SIZE` — extracted the magic number `50` from `processEntities()` into a class constant
- `DatabaseDecryptCommand::execute()` / `DatabaseEncryptCommand::execute()` — simplified to a single-line delegation to `executeOperation()`
- `AbstractType::$encryptor` — declared nullable (`?EncryptorInterface = null`) instead of relying on `isset()` for presence detection
- `AbstractType::convertToDatabaseValue()` / `convertToPHPValue()` — now access the encryptor through `getEncryptor()` (which calls `validate()`) instead of duplicating the `validate()` call and touching `$this->encryptor` directly
- `AbstractType::validate()` — `null === $this->encryptor` check replaces the `isset()` check
- `AbstractEncryptor::__debugInfo()` — relocated immediately after the constructor for declaration ordering consistency
- `composer.lock` — bumped `precision-soft/symfony-console` to `v4.2.1`, `precision-soft/symfony-phpunit` to `v3.2.1`, `phpstan/phpstan` to `2.1.47`

## [v3.1.0] - 2026-04-13 - Visibility widening, variable renaming, and test modernization

### Fixed

- `AbstractDatabaseCommand::processEntities()` — throw project `Exception` instead of generic `\RuntimeException`
- `AbstractEncryptor` — Yoda condition on `>` operator corrected (`static::MINIMUM_KEY_LENGTH > \strlen($salt)` → `\strlen($salt) < static::MINIMUM_KEY_LENGTH`)
- `AbstractEncryptor` — Yoda condition on `>=` operator corrected (`0 >= $initialVectorLength` → `$initialVectorLength <= 0`)

### Changed

- `AbstractEncryptor` — `$mac` renamed to `$messageAuthenticationCode`; `$info` parameter renamed to `$information`
- `AbstractEncryptor` — removed `final` from `getTypeName()`
- `AbstractDatabaseCommand` — `resetEncryptorsToFake()`, `restoreEncryptors()`, `getQuestionText()` visibility widened from `private` to `protected`
- `EncryptorFactory::getType()` — `$dbalType` renamed to `$type`
- `AbstractType` — removed `final` from `getFullName()`, `getEncryptor()`, `setEncryptor()`, `convertToDatabaseValue()`, `convertToPHPValue()`
- `AbstractType` — `validate()` visibility widened from `private` to `protected`
- `FakeEncryptor` — removed `final` modifier
- `StopException` — removed `final` modifier
- `PrecisionSoftDoctrineEncryptBundle` — `registerTypes()` visibility widened from `private` to `protected`
- `EntityService` — `getEncryptedFields()`, `getFieldsForClassMetadata()` visibility widened from `private` to `protected`
- 2 Mockery-based test classes migrated to `AbstractTestCase` (EntityServiceExtendedTest, AbstractDatabaseCommandTest)

## [v3.0.2] - 2026-04-10 - Encryption marker detection and database command hardening

### Fixed

- `EntityService::hasEncryptedValue()` — marker check now includes null-byte glue (`ENCRYPTION_MARKER . GLUE`), fixing false positives when a plaintext value starts with `<ENC>`
- `AbstractDatabaseCommand::processEntities()` — add `is_numeric()` guard on COUNT query result; throw `RuntimeException` on non-numeric result
- `AbstractDatabaseCommand::processEntities()` — move encryptor swap/restore outside the batch loop into a single `finally` block; prevents premature restore after each batch iteration
- `DatabaseDecryptCommand` / `DatabaseEncryptCommand` — catch `Throwable` instead of `Exception` to capture all errors, including `RuntimeException`

### Changed

- `AbstractEncryptor::GLUE` — visibility widened from `protected` to `public`; accessible to `EntityService` and external code without class extension
- `EncryptorFactory` — PHPDoc `@param string[]` → `@param class-string[]` for `$enabledEncryptors`
- `composer.lock` — bumped `precision-soft/symfony-console` to `v4.1.2`, `precision-soft/symfony-phpunit` to `v3.1.1`

### Added

- `AbstractEncryptor::__debugInfo()` — returns only algorithm name, preventing sensitive key material from leaking in debug/dump output
- `AbstractEncryptor::$initialVectorLengthCache` — caches `openssl_cipher_iv_length()` result to avoid repeated calls per encrypt/decrypt operation

## [v3.0.1] - 2026-04-08 - IV length accessor rename and configuration simplification

### Fixed

- `Configuration::getConfigTreeBuilder()` — removed duplicate salt length validation (already enforced at runtime by `AbstractEncryptor::MINIMUM_KEY_LENGTH`)

### Changed

- `AbstractEncryptor::getIvLength()` renamed to `getInitialVectorLength()` — zero-abbreviation naming consistency; affects subclasses that override this method
- `Configuration::getConfigTreeBuilder()` — simplified tree builder, removed redundant chained `->end()` calls on scalar prototype and array nodes

## [v3.0.0] - 2026-04-07 - HKDF key derivation, CamelCase naming, and DBAL 4 only

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

### Added

- `AbstractEncryptor::getIvLength()` — extracted IV length retrieval with false/zero guard; throws `Exception` when `openssl_cipher_iv_length()` returns `false` or `0`
- `AbstractDatabaseCommand::processEntities()` — template method replacing duplicated `encrypt`/`decrypt` loops; manages progress bar, entity manager lifecycle, and encryptor swapping
- `AbstractDatabaseCommand::applyKeysetPagination()` — keyset pagination support for both single and composite primary keys
- `Configuration` — salt validation: minimum 32 characters enforced at bundle configuration time
- `EncryptorFactory` — `encryptorsByTypeName` lookup cache for O (1) encryptor resolution by type name
- PHPStan level 8 with baseline
- Test classes: `ConfigurationTest`, `PrecisionSoftDoctrineEncryptExtensionTest`, `EntityMetadataDtoTest`, `AbstractEncryptorCryptoTest`, `AbstractDatabaseCommandTest`, `Aes256EncryptorTest`, `AbstractTypeTest`, `ExceptionTest`, `EncryptorFactoryExtendedTest`, `EntityServiceExtendedTest`, `PrecisionSoftDoctrineEncryptBundleTest`

## [v2.2.4] - 2026-03-21 - README clone URL correction

### Fixed

- README — correct repository clone URL

## [v2.2.3] - 2026-03-19 - Shared encryptor base-class logic

### Changed

- `AbstractEncryptor` — extracted shared `encrypt()` and `decrypt()` logic from `AES256Encryptor` and `AES256FixedEncryptor`; both encryptors now delegate entirely to the base class
- `AbstractEncryptor::generateNonce()` declared `abstract`
- `AES256Encryptor` / `AES256FixedEncryptor` — removed duplicated encrypt/decrypt/constructor logic; now only implement `getTypeClass()` and `generateNonce()`

## [v2.2.2] - 2026-03-19 - Fixed-encryptor nonce generation off-by-one

### Fixed

- `AES256FixedEncryptor::generateNonce()` — fix off-by-one nonce generation (cyclic loop was producing incorrect nonce length)

### Changed

- `AbstractEncryptor::getTypeClass()` declared `abstract`

## [v2.2.1] - 2026-03-19 - Test expansion and hidden .dev directory

### Changed

- Renamed `dev/` to `.dev/` for hidden directory convention

### Added

- Test classes: `DatabaseDecryptCommandTest`, `DatabaseEncryptCommandTest`, `EncryptorFactoryTest`, `AES256FixedTypeTest`
- Expanded `EntityServiceTest` coverage

## [v2.2.0] - 2026-03-13 - Configurable encryptors, FakeEncryptor, and test coverage

### Fixed

- `AbstractDatabaseCommand::getManagerName()` — return `null` when option value is not a string (prevents type error on missing option)

### Changed

- `DatabaseDecryptCommand` / `DatabaseEncryptCommand` — replace `configure()` + `setName()` with `#[AsCommand]` attribute
- `AbstractDatabaseCommand` — Yoda conditions, descriptive variable names, inline `getManager()` call
- Code style alignment across all source files (Yoda comparisons, `[] === $x` over `empty($x)`, catch variable naming)

### Added

- `Configuration` — `enabled_types` and `encryptors` nodes: allow restricting active encryptors per bundle configuration
- `FakeEncryptor` — no-op encryptor for use in test environments
- Test classes: `AES256EncryptorTest`, `AES256FixedEncryptorTest`, `FakeEncryptorTest`, `AES256TypeTest`

## [v2.1.0] - 2025-01-06 - Symfony console version flexibility

### Changed

- Allow `precision-soft/symfony-console 2.*`

## [v2.0.0] - 2024-11-24 - Doctrine DBAL 4 compatibility and constructor promotion

### Changed

- Constructor property promotion across `AbstractEncryptor`, `AbstractDatabaseCommand`, `EntityService`, `EntityMetadataDto`
- `AbstractType` — remove space before cast: `(string) $value` → `(string)$value`

### Added

- Doctrine DBAL 4 support (`doctrine/dbal: ^4.0`)

## [v1.0.0] - 2024-09-17 - Initial release: AES-256 encryption with Doctrine integration

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

[Unreleased]: https://github.com/precision-soft/symfony-doctrine-encrypt/compare/v4.6.0...HEAD

[v4.6.0]: https://github.com/precision-soft/symfony-doctrine-encrypt/compare/v4.5.0...v4.6.0

[v4.5.0]: https://github.com/precision-soft/symfony-doctrine-encrypt/compare/v4.4.0...v4.5.0

[v4.4.0]: https://github.com/precision-soft/symfony-doctrine-encrypt/compare/v4.3.1...v4.4.0

[v4.3.1]: https://github.com/precision-soft/symfony-doctrine-encrypt/compare/v4.3.0...v4.3.1

[v4.3.0]: https://github.com/precision-soft/symfony-doctrine-encrypt/compare/v4.2.0...v4.3.0

[v4.2.0]: https://github.com/precision-soft/symfony-doctrine-encrypt/compare/v4.1.0...v4.2.0

[v4.1.0]: https://github.com/precision-soft/symfony-doctrine-encrypt/compare/v4.0.0...v4.1.0

[v4.0.0]: https://github.com/precision-soft/symfony-doctrine-encrypt/compare/v3.2.0...v4.0.0

[v3.2.0]: https://github.com/precision-soft/symfony-doctrine-encrypt/compare/v3.1.1...v3.2.0

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

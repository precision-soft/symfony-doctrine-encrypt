# Symfony Doctrine Encrypt Bundle

[![ci](https://github.com/precision-soft/symfony-doctrine-encrypt/actions/workflows/ci.yml/badge.svg)](https://github.com/precision-soft/symfony-doctrine-encrypt/actions/workflows/ci.yml)
[![PHP >= 8.2](https://img.shields.io/badge/php-%3E%3D8.2-8892BF)](https://www.php.net/)
[![PHPStan Level 8](https://img.shields.io/badge/phpstan-level%208-brightgreen)](https://phpstan.org/)
[![Code Style PER-CS2.0](https://img.shields.io/badge/code%20style-PER--CS2.0-blue)](https://www.php-fig.org/per/coding-style/)
[![License MIT](https://img.shields.io/badge/license-MIT-green)](LICENSE)

Symfony bundle for transparent AES-256 field-level encryption of Doctrine ORM entity fields via custom Doctrine types.

**You may fork and modify it as you wish. Contributions are welcomed.**

## Requirements

- PHP 8.2+ with `ext-openssl`
- Doctrine ORM 3.*
- Doctrine DBAL 4.*
- Symfony 7.* or 8.* (Symfony 8 itself requires PHP 8.4+)

## Installation

```shell
composer require precision-soft/symfony-doctrine-encrypt
```

Register the bundle in `config/bundles.php`:

```php
<?php

use PrecisionSoft\Doctrine\Encrypt\PrecisionSoftDoctrineEncryptBundle;

return [
    PrecisionSoftDoctrineEncryptBundle::class => ['all' => true],
];
```

## Configuration

Create `config/packages/precision_soft_doctrine_encrypt.php`:

```php
<?php

declare(strict_types=1);

use PrecisionSoft\Doctrine\Encrypt\Encryptor\Aes256Encryptor;
use PrecisionSoft\Doctrine\Encrypt\Encryptor\Aes256FixedEncryptor;
use Symfony\Config\PrecisionSoftDoctrineEncryptConfig;

return static function (PrecisionSoftDoctrineEncryptConfig $precisionSoftDoctrineEncryptConfig): void {
    $precisionSoftDoctrineEncryptConfig->salt('%env(APP_ENCRYPTION_SALT)%');
    $precisionSoftDoctrineEncryptConfig->encryptors([
        Aes256Encryptor::class,
        Aes256FixedEncryptor::class,
    ]);
    $precisionSoftDoctrineEncryptConfig->enabledTypes(['encryptedAes256', 'encryptedAes256fixed']);
};
```

The PHP variant is preferred over YAML because the `Symfony\Config\PrecisionSoftDoctrineEncryptConfig` class gives you IDE autocomplete and catches typos at parse time.

`encryptors` is optional — when omitted, every encryptor registered with the `precision-soft.doctrine.encryptor` service tag is active. List entries to restrict the built-in set or to swap a built-in encryptor for your own (see [Custom encryptors](#custom-encryptors)).

`enabledTypes` is optional — when omitted, every type corresponding to an active encryptor is registered. Use this when you want a subset of columns encrypted (for example, only deterministic columns) without removing the encryptor class from the service container.

`salt` is required — minimum 32 characters. It is used as HKDF input material, not a password; use a randomly generated high-entropy string. All subkeys (encryption, MAC, deterministic nonce) are derived from this single salt via HKDF-SHA256 with distinct info strings.

Generate a salt and add it to `.env`:

```shell
php -r "echo base64_encode(random_bytes(48));"
```

```dotenv
APP_ENCRYPTION_SALT=<paste the generated value here>
```

A 32-byte (44-character base64) salt is the minimum; 48 bytes (64-character base64) is recommended. Store the salt in a secret manager (Symfony secrets, Vault, AWS Secrets Manager, ...) — never commit it. If you run multiple Doctrine entity managers, the bundle applies the same salt and the same registered types to every manager; per-manager keys are not currently supported.

### Multi-salt configuration (for key rotation)

When rotating encryption keys without a maintenance window, configure a map of versioned salts and point `currentSaltVersion` at the one to use for new writes. Every encryptor can still decrypt values written under any listed version.

```php
<?php

declare(strict_types=1);

use Symfony\Config\PrecisionSoftDoctrineEncryptConfig;

return static function (PrecisionSoftDoctrineEncryptConfig $precisionSoftDoctrineEncryptConfig): void {
    $precisionSoftDoctrineEncryptConfig->salts([
        'v1' => '%env(APP_ENCRYPTION_SALT_V1)%',
        'v2' => '%env(APP_ENCRYPTION_SALT_V2)%',
    ]);
    $precisionSoftDoctrineEncryptConfig->currentSaltVersion('v2');
};
```

`salt` and `salts` are mutually exclusive. When `salts` is used, `currentSaltVersion` is required and must reference one of the listed versions. Every salt must meet the same minimum-length requirement (32 characters). See [Secret rotation](#secret-rotation) for the full workflow.

## Encryption types

| Type              | Doctrine type name     | Use case                                                                                                |
|-------------------|------------------------|---------------------------------------------------------------------------------------------------------|
| `Aes256Type`      | `encryptedAes256`      | General encryption — different ciphertext each time (non-deterministic)                                 |
| `Aes256FixedType` | `encryptedAes256fixed` | Deterministic encryption — same plaintext always produces the same ciphertext, enabling `WHERE` queries |

## Usage

### Entity mapping

```php
<?php

declare(strict_types=1);

namespace App\Entity;

use Doctrine\ORM\Mapping as ORM;

#[ORM\Entity]
class Customer
{
    #[ORM\Column(type: 'encryptedAes256')]
    private string $name;

    #[ORM\Column(type: 'encryptedAes256fixed')]
    private string $email;
}
```

The entity always holds the plaintext value. Encryption and decryption happen transparently at the persistence layer.

### WHERE queries with encrypted fields

`encryptedAes256fixed` fields can be searched with a WHERE clause. Use `EntityService::setEncryptedParameter()` to encrypt the search value before binding it. The method requires the field's encryptor to implement `DeterministicEncryptorInterface`; otherwise it throws `NonDeterministicEncryptorException`, since non-deterministic encryptors produce a different ciphertext on every call and the generated WHERE clause would never match.

```php
<?php

declare(strict_types=1);

namespace App\Repository;

use App\Entity\Customer;
use Doctrine\Bundle\DoctrineBundle\Repository\ServiceEntityRepository;
use Doctrine\Persistence\ManagerRegistry;
use PrecisionSoft\Doctrine\Encrypt\Service\EntityService;

class CustomerRepository extends ServiceEntityRepository
{
    public function __construct(
        ManagerRegistry $managerRegistry,
        private readonly EntityService $entityService,
    ) {
        parent::__construct($managerRegistry, Customer::class);
    }

    public function findByEmail(string $email): ?Customer
    {
        $queryBuilder = $this->createQueryBuilder('c')
            ->where('c.email = :email');

        $this->entityService->setEncryptedParameter($queryBuilder, 'email', Customer::class, 'email', $email);

        return $queryBuilder->getQuery()->getOneOrNullResult();
    }
}
```

### EntityService API

| Method                                                  | Description                                                                             |
|---------------------------------------------------------|-----------------------------------------------------------------------------------------|
| `getEncryptor(class, field)`                            | Returns the encryptor configured for the field                                          |
| `hasEncryptor(class, field)`                            | Returns `true` if the field uses an encrypted type                                      |
| `hasEncryption(entity\|class, field)`                   | Same as `hasEncryptor`, accepts object or class string                                  |
| `encrypt(data, class, field)`                           | Encrypts a value using the field's encryptor                                            |
| `decrypt(data, class, field)`                           | Decrypts a value using the field's encryptor                                            |
| `setEncryptedParameter(qb, param, class, field, value)` | Encrypts a value and sets it as a query parameter                                       |
| `hasEncryptedValue(entity, field)`                      | Reads the raw DB column and checks if it is currently encrypted (additional DBAL query) |
| `getEntitiesWithEncryption(managerName?)`               | Returns all entity classes that have at least one encrypted field                       |

## Commands

Encrypt an unencrypted database (after enabling the bundle on an existing database):

```shell
php bin/console precision-soft:doctrine:database:encrypt
```

Decrypt an encrypted database (before disabling the bundle):

```shell
php bin/console precision-soft:doctrine:database:decrypt
```

Rotate rows directly to the configured current salt without an intermediate plaintext database:

```shell
php bin/console precision-soft:doctrine:database:rotate
```

All three commands process entities in batches of 50 and ask for confirmation before running. Pass `--no-interaction` to skip the confirmation prompt in automated environments.

Use the `--manager` option to target a specific Doctrine entity manager:

```shell
php bin/console precision-soft:doctrine:database:encrypt --manager=secondary
```

### Running against a large database

All three commands share the same options for splitting a long run into pieces you can supervise:

| Option         | Effect                                                                                                                                      |
|----------------|---------------------------------------------------------------------------------------------------------------------------------------------|
| `--batch-size` | Rows loaded, flushed and cleared per iteration. Defaults to 50.                                                                             |
| `--entity`     | Comma-separated entity class names to restrict the run to. A leading backslash is accepted. Defaults to every entity with encrypted fields. |
| `--checkpoint` | Path to a json file holding the resume cursor, replaced atomically after every flushed batch.                                               |
| `--from-id`    | Resume after this identifier. Requires a single `--entity` with a single identifier field.                                                  |
| `--dry-run`    | Walk every selected row without writing entities or the checkpoint.                                                                         |

`--verify` is specific to `database:rotate`, the command whose whole purpose is to leave every value on the current salt:

```shell
php bin/console precision-soft:doctrine:database:rotate \
    --entity='App\Entity\User' \
    --checkpoint=var/rotation.json \
    --verify
```

It reads the stored columns of the selected entities back after the rewrite and fails unless every value carries the current salt version - the whole table, not only the rows this run walked: `--from-id` and a checkpoint narrow the walk, never the check, because the point of the check is that no row is left behind. Under SINGLE_TABLE inheritance the count covers the selected class and its subclasses, the rows the walk could see, so a sibling row left on another salt is not the selected class' failure. Combined with `--dry-run` it becomes the check itself: nothing is written, the columns are still read back, and the command fails naming the fields and the row counts that are not yet on the current salt - run it before a rotation to see what is stale, and after one before dropping the old salt.

**Checkpoints.** A checkpoint records the last identifier written per entity, and marks each entity completed when its pass finishes. Rerunning with the same path resumes an interrupted run from the last flushed batch, while an entity that already completed starts over — so the same file can be reused for a later rotation without silently scanning nothing. `--dry-run` never writes it, and `--from-id` overrides the stored cursor for that run.

The file belongs to the run that wrote it: it carries the command name, the entity manager and the salt version the run writes with, and a run refuses a file written under another scope - a `database:rotate` interrupted mid-way cannot be resumed by `database:encrypt`, against another `--manager`, or after the current salt version moved on, because every row before the foreign cursor would be skipped as done. The format is version 2 since v4.7.0; a file written by v4.6.0 is refused with a message asking to finish that run with the release that wrote it, or to delete the file.

The cursor holds the identifier as an integer or a string. An integer identifier - `integer`, `smallint`, `bigint` - is bound as the integer the engine hands back (a `bigint` beyond `PHP_INT_MAX` stays a string, as in DBAL), a string identifier as is, and any other identifier type - a uid, a date - is rebuilt through its DBAL type on the resume and on `--from-id`, so the comparison the keyset makes is the one the mapping makes. An identifier whose value is neither an integer, a string nor a `Stringable` object cannot be checkpointed and the run says so; an identifier the type cannot rebuild from the stored value is refused with the type and the field named.

## Security considerations

- **Cipher and key derivation**: Encryption uses AES-256-CTR. Per-salt subkeys are derived via HKDF-SHA256 (`hash_hkdf()`) with distinct info strings (`'encryption'`, `'authentication'`, `'nonce'`), producing separate subkeys for each purpose. The raw salt is never used directly as a key. Authentication uses HMAC-SHA256.
- **Salt stability and rotation**: Salts are the encryption key material. Versioned salts (see [Multi-salt configuration](#multi-salt-configuration-for-key-rotation)) let you add new salts without losing access to data written under older ones, because every ciphertext carries its own salt-version identifier. Dropping a salt from configuration makes every row previously written under it unreadable — always run `database:rotate` to migrate rows off the old version first.
- **Non-deterministic vs deterministic**: `Aes256Type` uses a random nonce per encryption, so the same plaintext produces different ciphertext on each call — this is the secure default. `Aes256FixedType` uses a deterministic nonce derived from the plaintext, enabling `WHERE` queries but leaking the fact that two rows have the same value.
- **MAC verification**: Every encrypted value includes an HMAC-SHA256 tag. Tampered or corrupted values are rejected on decryption. The MAC input is a canonical length-prefixed concatenation of `(format-version, salt-version, algorithm, ciphertext, nonce)`, which prevents cross-field ambiguity when any field has variable length.
- **Raw string encryption**: Values are encrypted and decrypted as raw strings without any serialisation layer.
- **Double-encryption protection**: The `encrypt()` method detects the encryption marker and returns already-encrypted data unchanged. This prevents accidental double-encryption when processing raw values that are already encrypted.
- **Key separation**: Encryption, MAC, and deterministic-nonce subkeys are derived independently via HKDF info strings, so compromising one subkey does not expose the others.
- **Key material and dump paths**: The likeliest way to leak keys is not a broken cipher but a dumped service. `__debugInfo()` reduces an encryptor to its algorithm and salt-version shape, which covers `var_dump()`, `print_r()` and Symfony's VarDumper (the profiler and `dump()`). `serialize()` and `unserialize()` are refused outright — an encryptor must never be written into a session, a cache entry or a queued message. The salt itself is marked `#[\SensitiveParameter]`, so it is redacted from stack traces. **`var_export()` remains an exposure**: PHP offers no hook for it — there is no counterpart to `__debugInfo()`, and `__set_state()` only governs the reverse direction — so never `var_export()` an encryptor or any object graph containing one.
- **The `<ENC>\0` prefix is reserved**: `looksEncrypted()` checks the envelope *shape*, never the MAC. A plaintext that both starts with the marker and mimics the six-part shape with valid base64 segments is therefore passed through by `encrypt()` unchanged — and then rejected by `decrypt()`, because no MAC can verify it. Such a value is stored and cannot be read back. Do not place attacker-controlled values that may begin with `<ENC>\0` into an encrypted field; a marker-prefixed value whose segments are *not* valid base64 is ordinary plaintext and round-trips normally.
- **The envelope is not canonical**: base64 decoding accepts unpadded input, so stripping the trailing `=` padding produces a different string that authenticates and decrypts identically. This is harmless for integrity — the MAC covers the decoded bytes — but it means a ciphertext has more than one valid spelling. The bundle always writes the padded form, and `Aes256FixedType` lookups compare strings, so only values this bundle produced will match.
- **Column sizing**: ciphertext is roughly 1.34x the plaintext (base64) plus about eighty bytes of envelope. A column that does not declare a length is created at `AbstractType::DEFAULT_LENGTH` (1000), which overflows at roughly 685 plaintext characters — MySQL and MariaDB reject the write with a "data too long" error rather than truncating, so the failure is loud, but size the column for the ciphertext rather than the plaintext.

## Secret rotation

v4.0.0 embeds the salt version inside every ciphertext (see [Format versioning](#format-versioning)), so the bundle supports both online (dual-salt) and offline rotation out of the box.

### Online rotation (no plaintext window)

This is the path to use when you cannot decrypt the whole database at once. Old and new salts coexist, old rows remain readable under the old version, new writes pick up the new version.

1. Add the new salt alongside the old one and point `currentSaltVersion` at the new version. Deploy.

    ```php
    <?php

    declare(strict_types=1);

    use Symfony\Config\PrecisionSoftDoctrineEncryptConfig;

    return static function (PrecisionSoftDoctrineEncryptConfig $precisionSoftDoctrineEncryptConfig): void {
        $precisionSoftDoctrineEncryptConfig->salts([
            'v1' => '%env(APP_ENCRYPTION_SALT_V1)%',
            'v2' => '%env(APP_ENCRYPTION_SALT_V2)%',
        ]);
        $precisionSoftDoctrineEncryptConfig->currentSaltVersion('v2');
    };
    ```

   From this point on, **new writes** are stamped with `v2` and use the `v2` subkeys; **reads** of old `v1` rows continue to succeed because their salt version is embedded in the payload.

2. Force every row through the current salt so old rows get re-encrypted under `v2`:

    ```shell
    php bin/console precision-soft:doctrine:database:rotate
    ```

   The command reads through the application and flushes each batch with the current encryptor. Plaintext exists only in process memory for the loaded batch and is never persisted as an intermediate database state.

3. Once every row is under `v2` - `database:rotate --dry-run --verify` says so without writing anything - drop the old salt from configuration and redeploy:

    ```php
    $precisionSoftDoctrineEncryptConfig->salts(['v2' => '%env(APP_ENCRYPTION_SALT_V2)%']);
    $precisionSoftDoctrineEncryptConfig->currentSaltVersion('v2');
    ```

**A salt version dropped too early**: a row still stored under a version that is no longer configured cannot be read - `decrypt()` refuses an unknown salt version - and `database:rotate` cannot skip it either: the batch that loads it fails, the run stops with the entity and the cursor it was loading after in the message, and nothing after that batch is touched. Put the version back, rotate, verify, then drop it. `--verify` cannot list such rows, because it only tells current from not current.

**Deterministic columns**: `encryptedAes256fixed` uses a deterministic nonce derived from the current salt. A row encrypted under `v1` produces a different ciphertext under `v2`, so WHERE queries stop matching until the row is re-encrypted. If you have deterministic columns used in WHERE clauses, run step 2 as part of the same deploy that flips `currentSaltVersion`, or accept that queries miss old rows until step 2 completes.

### Offline rotation (maintenance window)

This is the simpler path when you can briefly hold the database in plaintext:

1. Decrypt every encrypted column under the current salt:

    ```shell
    php bin/console precision-soft:doctrine:database:decrypt
    ```

2. Swap `salt` (or the active entry in `salts`) for the new value and redeploy.

3. Re-encrypt every column under the new salt:

    ```shell
    php bin/console precision-soft:doctrine:database:encrypt
    ```

Between steps 1 and 3 the database contains plaintext — restrict access and keep the window short.

For multi-manager setups, pass `--manager=<name>` to each command and repeat per manager.

## Format versioning

The current encrypted output format (`v1`, introduced in v4.0.0) is:

```
<ENC>\0v1\0<salt-version>\0<base64-ciphertext>\0<base64-mac>\0<base64-nonce>
```

`<ENC>` is a fixed marker (`AbstractEncryptor::ENCRYPTION_MARKER`). The second field is the format version identifier (`AbstractEncryptor::FORMAT_VERSION_V1`). The third field identifies which salt in the configured `salts` map was used to derive the keys — on single-salt configurations it is always `default` (`AbstractEncryptor::DEFAULT_SALT_VERSION`). Separators are null bytes (`\0`).

The HMAC is computed over a canonical, length-prefixed concatenation to eliminate concatenation ambiguity across variable-length fields:

```
pack('N', len(version)) || version
  || pack('N', len(salt-version)) || salt-version
  || pack('N', len(algorithm)) || algorithm
  || pack('N', len(ciphertext)) || ciphertext
  || pack('N', len(nonce)) || nonce
```

### Legacy format (pre-v4.0.0)

Values written by v3.x used a 4-part, non-versioned layout:

```
<ENC>\0<base64-ciphertext>\0<base64-mac>\0<base64-nonce>
```

`decrypt()` transparently accepts both layouts. Legacy values are always decrypted with the current salt (they pre-date salt versioning). `encrypt()` always produces `v1`. Existing legacy ciphertexts remain decryptable without migration; byte-level WHERE queries on `encryptedAes256fixed` columns, however, require the database to be re-encrypted (see [Upgrading from v3.x to v4.0.0](#upgrading-from-v3x-to-v400)).

## Upgrading from v3.x to v4.0.0

v4.0.0 changes the on-disk format of encrypted values. `decrypt()` accepts both legacy and `v1` formats, but `encrypt()` only produces `v1`. This has two consequences:

- **Reads** (entity hydration, `EntityService::decrypt()`) continue to work on legacy rows without any action.
- **WHERE queries** on `encryptedAes256fixed` columns (`EntityService::setEncryptedParameter()`) will **not match legacy rows** after the upgrade, because the search parameter is encrypted in `v1` format while the stored value is in legacy format.

To re-encrypt the database in place under the new format:

1. Upgrade the bundle to v4.0.0.
2. Run `php bin/console precision-soft:doctrine:database:decrypt`. Decryption handles both legacy and `v1` values.
3. Run `php bin/console precision-soft:doctrine:database:encrypt`. All values are re-written in `v1` format.

After step 3, all WHERE queries on deterministic-encrypted columns work again. Plan for a maintenance window: during step 2 the database contains plaintext data.

## Custom encryptors

You can replace the built-in encryptor for any Doctrine type by implementing `EncryptorInterface` and registering it as a tagged service. This allows you to introduce custom encryption logic (such as versioned secrets or external KMS integration) without modifying the bundle.

```php
<?php

declare(strict_types=1);

namespace App\Encryptor;

use PrecisionSoft\Doctrine\Encrypt\Contract\EncryptorInterface;
use PrecisionSoft\Doctrine\Encrypt\Type\Aes256Type;

class MyCustomEncryptor implements EncryptorInterface
{
    public function getTypeClass(): string
    {
        return Aes256Type::class;
    }

    public function getTypeName(): string
    {
        return Aes256Type::getFullName();
    }

    public function encrypt(string $data): string
    {
    }

    public function decrypt(string $data): string
    {
    }
}
```

If the custom encryptor produces the same ciphertext for the same plaintext across calls, mark it with `DeterministicEncryptorInterface` so it can be used with `EntityService::setEncryptedParameter()` for WHERE queries:

```php
<?php

declare(strict_types=1);

namespace App\Encryptor;

use PrecisionSoft\Doctrine\Encrypt\Contract\DeterministicEncryptorInterface;
use PrecisionSoft\Doctrine\Encrypt\Type\Aes256FixedType;

class MyDeterministicEncryptor implements DeterministicEncryptorInterface
{
    public function getTypeClass(): string
    {
        return Aes256FixedType::class;
    }

    public function getTypeName(): string
    {
        return Aes256FixedType::getFullName();
    }

    public function encrypt(string $data): string
    {
    }

    public function decrypt(string $data): string
    {
    }
}
```

When using the `encryptors` configuration key, list only your custom encryptor class to ensure it takes precedence over the built-in one. The bundle rejects duplicate encryptors for the same Doctrine type, so only one encryptor per type can be active.

## Exception context

Every exception in this package carries a structured `context` array next to its message, so the facts describing a failure do not have to be parsed back out of a string:

```php
try {
    // ...
} catch (Exception $exception) {
    $logger->error($exception->getMessage(), $exception->getContext());
}
```

`getContext()` returns `[]` when nothing was attached. `setContext()` replaces it and returns the exception, and the constructor accepts it as an optional fourth argument. Values are expected to be scalars, so the array stays serialisable by a logger.

The context is purely **additive**: no message, code or previous throwable changed when it was introduced, so code that logs only `getMessage()` behaves exactly as before.

Nothing in this bundle attaches a context of its own yet — the one place it catches a throwable it rethrows it unchanged — so the capability is there for consumers throwing or extending these exceptions in their own encryptors.

Every exception in the package implements `Contract\ExceptionInterface`, so a consumer can read the context off any of them without knowing the concrete class. A subclass of your own that already declares a `$context` property or a
`getContext()`/`setContext()` method will collide with `Exception\Trait\ExceptionTrait`.

## Example application

A runnable customer directory lives under [`.example/`](./.example/README.md): a `User` whose e-mail is deterministic and whose phone and address are random, written and read through the ORM with the bundle booted by a micro-kernel the way an application boots it; a `CustomerDirectory` service with the lookup by e-mail through `setEncryptedParameter()`, the lookup across every active salt version through `setEncryptedParameterInList()` while a rotation is in flight, and the refusal to search a random column; the encrypt and decrypt commands over a legacy plaintext table; the online salt rotation from one kernel generation to the next with `--dry-run --verify` as the check before and after; and the checkpoints that resume an interrupted run and refuse a file of another command or salt. It runs on MySQL and MariaDB, installs the bundle from the working tree through a path repository, so it always tests the code as it stands; run it with `.dev/validate/all.sh --example` (which starts the
databases) or `cd .example && composer install && composer check`. The directory is `export-ignore`d and never reaches a consumer's `vendor/`.

## Dev

The development environment uses Docker. The `./dc` script is a Docker Compose wrapper located in `.dev/`.

```shell
git clone git@github.com:precision-soft/symfony-doctrine-encrypt.git
cd symfony-doctrine-encrypt

./dc build && ./dc up -d
```

Run the full gate the way the pre-commit hook runs it - the CI workflow in
`.github/workflows/ci.yml` calls the same composer scripts, so the two cannot drift:

```shell
.dev/validate/all.sh
.dev/validate/all.sh --audit    # also audits the locked dependencies ( needs the network )
.dev/validate/all.sh --staged   # what the pre-commit hook runs: nothing unless the index carries php
.dev/validate/all.sh --example  # also installs and checks the example application against the databases
```

Mutation testing is opt-in for the same reason, plus cost - it runs the suite once per mutant:

```shell
.dev/validate/all.sh --mutation
```

Infection is a pinned phar in the image, not a composer dependency, and `infection.json5` carries a
`minMsi` floor equal to the last measured score, so the section fails when a change makes the suite weaker rather than only reporting a number. Raise the floor when the score improves.

The integration suite needs real databases, which are behind a Compose profile so the default `up`
stays fast and offline:

```shell
./dc --profile db up -d
.dev/validate/all.sh --integration
```

Tests connect through `DATABASE_URL_MYSQL` and `DATABASE_URL_MARIADB` and skip themselves when those services are not running, so `composer check` never depends on them.

Build against another PHP version with the `PHP_VERSION` build argument - each version is tagged as its own image, so switching back and forth costs nothing:

```shell
PHP_VERSION=8.4 ./dc build && PHP_VERSION=8.4 ./dc up -d
```

Coverage is available through pcov, which is installed but disabled by default:

```shell
./dc exec dev php -d pcov.enabled=1 vendor/bin/simple-phpunit --coverage-text
```

After editing a file, `./dc restart dev` (a few seconds) is enough to be sure the container is not serving a stale copy - the bind mount can keep the old inode after an atomic rewrite.

## Todo

- **Easy WHERE** — pass unencrypted parameters to QueryBuilder and have them automatically encrypted (currently requires manual `setEncryptedParameter()` calls).

## Inspired by

- https://github.com/GiveMeAllYourCats/DoctrineEncryptBundle
- https://github.com/jackprice/doctrine-encrypt

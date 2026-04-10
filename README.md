# Symfony Doctrine Encrypt Bundle

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
- Symfony 7.*

## Installation

```shell
composer require precision-soft/symfony-doctrine-encrypt
```

Register the bundle in `config/bundles.php`:

```php
return [
    PrecisionSoft\Doctrine\Encrypt\PrecisionSoftDoctrineEncryptBundle::class => ['all' => true],
];
```

## Configuration

Create `config/packages/precision_soft_doctrine_encrypt.yaml`:

```yaml
precision_soft_doctrine_encrypt:
    # Required. Minimum 32 characters. Keep this secret and stable — changing it renders all encrypted data unreadable.
    salt: '%env(APP_ENCRYPTION_SALT)%'

    # Optional. Restrict which encryptors are active. When empty, all registered encryptors are enabled.
    # encryptors:
    #     - PrecisionSoft\Doctrine\Encrypt\Encryptor\Aes256Encryptor
    #     - PrecisionSoft\Doctrine\Encrypt\Encryptor\Aes256FixedEncryptor

    # Optional. Restrict which Doctrine types are registered. When empty, all types are registered.
    # enabled_types:
    #     - encryptedAes256
    #     - encryptedAes256fixed
```

Add the salt to your `.env`:

```dotenv
APP_ENCRYPTION_SALT=your-random-salt-of-at-least-32-characters
```

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

`encryptedAes256fixed` fields can be searched with a WHERE clause. Use `EntityService::setEncryptedParameter()` to encrypt the search value before binding it:

```php
<?php

declare(strict_types=1);

use Doctrine\Persistence\ManagerRegistry;
use Doctrine\Bundle\DoctrineBundle\Repository\ServiceEntityRepository;
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
| `getEntitiesWithEncryption(manager?)`                   | Returns all entity classes that have at least one encrypted field                       |

## Commands

Encrypt an unencrypted database (after enabling the bundle on an existing database):

```shell
php bin/console precision-soft:doctrine:database:encrypt
```

Decrypt an encrypted database (before disabling the bundle):

```shell
php bin/console precision-soft:doctrine:database:decrypt
```

Both commands process entities in batches of 50 and ask for confirmation before running. Pass `--no-interaction` to skip the confirmation prompt in automated environments.

Use the `--manager` option to target a specific Doctrine entity manager:

```shell
php bin/console precision-soft:doctrine:database:encrypt --manager=secondary
```

## Security considerations

- **Salt stability**: The salt is the encryption key. If it changes, all existing encrypted data becomes unreadable. Store it in a secret manager and never rotate it without first decrypting the database.
- **Non-deterministic vs deterministic**: `Aes256Type` uses a random nonce per encryption, so the same plaintext produces different ciphertext on each call — this is the secure default. `Aes256FixedType` uses a deterministic nonce derived from the plaintext, enabling `WHERE` queries but leaking the fact that two rows have the same value.
- **MAC verification**: Every encrypted value includes an HMAC-SHA256 tag. Tampered or corrupted values are rejected on decryption.
- **Raw string encryption**: Values are encrypted and decrypted as raw strings without any serialisation layer.
- **Double-encryption protection**: The `encrypt()` method detects the encryption marker and returns already-encrypted data unchanged. This prevents accidental double-encryption when processing raw values that are already encrypted.
- **Key derivation**: The raw salt is never used directly. Separate encryption and MAC keys are derived via HKDF (or a SHA-256 fallback), so compromising one key does not expose the other.

## Key rotation limitations

This bundle does **not** support transparent key rotation. All encrypted values are tied to the single configured salt. To rotate the encryption key you must:

1. Decrypt the entire database with the current salt using `precision-soft:doctrine:database:decrypt`.
2. Change the `salt` configuration to the new value.
3. Re-encrypt the entire database using `precision-soft:doctrine:database:encrypt`.

During the rotation window the database contains plaintext data — plan for a maintenance window and restrict access accordingly.

For applications that require online key rotation (encrypting new data with a new key while still decrypting old data with the previous key), consider implementing a versioned encryption layer on top of the bundle's `EncryptorInterface`. The PynBooking project demonstrates this pattern with a version-tagged prefix and a map of secrets keyed by version.

## Format versioning

The encrypted output format is:

```
<ENC>\0<base64-ciphertext>\0<base64-mac>\0<base64-nonce>
```

`<ENC>` is a fixed marker (`AbstractEncryptor::ENCRYPTION_MARKER`). The separator is a null byte (`\0`). There is currently no version identifier embedded in the format. If the encryption scheme changes in a future release, a migration path will be provided. Existing data remains readable as long as the salt is unchanged.

## Custom encryptors

You can replace the built-in encryptor for any Doctrine type by implementing `EncryptorInterface` and registering it as a tagged service. This allows you to introduce custom encryption logic (such as versioned secrets or external KMS integration) without modifying the bundle.

```php
<?php

declare(strict_types=1);

use PrecisionSoft\Doctrine\Encrypt\Contract\EncryptorInterface;
use PrecisionSoft\Doctrine\Encrypt\Type\Aes256Type;

class MyCustomEncryptor implements EncryptorInterface
{
    public function getTypeClass(): string
    {
        return Aes256Type::class;
    }

    public function getTypeName(): ?string
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

When using the `encryptors` configuration key, list only your custom encryptor class to ensure it takes precedence over the built-in one. The bundle rejects duplicate encryptors for the same Doctrine type, so only one encryptor per type can be active.

## Dev

The development environment uses Docker. The `./dc` script is a Docker Compose wrapper located in `.dev/`.

```shell
git clone git@github.com:precision-soft/symfony-doctrine-encrypt.git
cd symfony-doctrine-encrypt

./dc build && ./dc up -d
```

## Todo

- **Easy WHERE** — pass unencrypted parameters to QueryBuilder and have them automatically encrypted (currently requires manual `setEncryptedParameter()` calls).

## Inspired by

- https://github.com/GiveMeAllYourCats/DoctrineEncryptBundle
- https://github.com/jackprice/doctrine-encrypt

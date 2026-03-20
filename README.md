# Symfony Doctrine Encrypt Bundle

Symfony bundle for transparent AES-256 field-level encryption of Doctrine ORM entity fields via custom Doctrine types.

**You may fork and modify it as you wish. Contributions are welcomed.**

## Requirements

- PHP 8.2+ with `ext-openssl`
- Doctrine ORM 3.*
- Doctrine DBAL 3.* or 4.*
- Symfony 7.*

## Installation

```shell
composer require precision-soft/symfony-doctrine-encrypt
```

Register the bundle in `config/bundles.php`:

```php
return [
    /* ... */
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
    #     - PrecisionSoft\Doctrine\Encrypt\Encryptor\AES256Encryptor
    #     - PrecisionSoft\Doctrine\Encrypt\Encryptor\AES256FixedEncryptor

    # Optional. Restrict which Doctrine types are registered. When empty, all types are registered.
    # enabled_types:
    #     - encryptedAES256
    #     - encryptedAES256fixed
```

Add the salt to your `.env`:

```dotenv
APP_ENCRYPTION_SALT=your-random-salt-of-at-least-32-characters
```

## Encryption types

| Type | Doctrine type name | Use case |
|---|---|---|
| `AES256Type` | `encryptedAES256` | General encryption — different ciphertext each time (non-deterministic) |
| `AES256FixedType` | `encryptedAES256fixed` | Deterministic encryption — same plaintext always produces the same ciphertext, enabling `WHERE` queries |

## Usage

### Entity mapping

```php
use Doctrine\ORM\Mapping as ORM;

#[ORM\Entity]
class Customer
{
    /* non-deterministic — secure for data at rest, cannot be queried with where */
    #[ORM\Column(type: 'encryptedAES256')]
    private string $name;

    /* deterministic — same input always produces the same ciphertext, enabling where queries */
    #[ORM\Column(type: 'encryptedAES256fixed')]
    private string $email;
}
```

The entity always holds the plaintext value. Encryption and decryption happen transparently at the persistence layer.

### WHERE queries with encrypted fields

`encryptedAES256fixed` fields can be searched with a WHERE clause. Use `EntityService::setEncryptedParameter()` to encrypt the search value before binding it:

```php
use PrecisionSoft\Doctrine\Encrypt\Service\EntityService;

class CustomerRepository extends ServiceEntityRepository
{
    public function __construct(
        ManagerRegistry $registry,
        private readonly EntityService $entityService,
    ) {
        parent::__construct($registry, Customer::class);
    }

    public function findByEmail(string $email): ?Customer
    {
        $qb = $this->createQueryBuilder('c')
            ->where('c.email = :email');

        $this->entityService->setEncryptedParameter($qb, 'email', Customer::class, 'email', $email);

        return $qb->getQuery()->getOneOrNullResult();
    }
}
```

### EntityService API

| Method | Description |
|---|---|
| `getEncryptor(class, field)` | Returns the encryptor configured for the field |
| `hasEncryptor(class, field)` | Returns `true` if the field uses an encrypted type |
| `isEncrypted(entity\|class, field)` | Same as `hasEncryptor`, accepts object or class string |
| `encrypt(data, class, field)` | Encrypts a value using the field's encryptor |
| `decrypt(data, class, field)` | Decrypts a value using the field's encryptor |
| `setEncryptedParameter(qb, param, class, field, value)` | Encrypts a value and sets it as a query parameter |
| `isValueEncrypted(entity, field)` | Reads the raw DB column and checks if it is currently encrypted (additional DBAL query) |
| `getEntitiesWithEncryption(manager?)` | Returns all entity classes that have at least one encrypted field |

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
- **Non-deterministic vs deterministic**: `AES256Type` uses a random nonce per encryption, so the same plaintext produces different ciphertext on each call — this is the secure default. `AES256FixedType` uses a deterministic nonce derived from the plaintext, enabling `WHERE` queries but leaking the fact that two rows have the same value.
- **MAC verification**: Every encrypted value includes an HMAC-SHA256 tag. Tampered or corrupted values are rejected on decryption.
- **Plaintext serialisation**: Values are PHP-serialised before encryption. On decryption, only scalar strings are accepted (`allowed_classes: false`), preventing object injection.

## Dev

```shell
git clone git@github.com:precision-soft/symfony-doctrine-encrypt.git
cd doctrine-encrypt
composer install
vendor/bin/phpunit
```

## Todo

- **Easy WHERE** — pass unencrypted parameters to QueryBuilder and have them automatically encrypted (currently requires manual `setEncryptedParameter()` calls).

## Inspired by

- https://github.com/GiveMeAllYourCats/DoctrineEncryptBundle
- https://github.com/jackprice/doctrine-encrypt

# Symfony Doctrine Encrypt — example

The customer directory of a shop — users whose e-mail, phone and address live encrypted in the database — built on `precision-soft/symfony-doctrine-encrypt` and run against MySQL 8.4 and MariaDB 11.8. It is the minimum of code that demonstrates the maximum of the bundle: one entity, one service, one kernel, and a test suite that does with them what an application does. Paths in this file are relative to `.example/`.

## What it represents

- `src/CustomerDirectoryKernel.php` — a micro-kernel registering `FrameworkBundle`, `DoctrineBundle` and `PrecisionSoftDoctrineEncryptBundle`, so the encrypted types are registered the way they are in an application: by the bundle, at boot, from the configured salts. An application reads the database and the salts from its environment; the kernel takes them as arguments so a test can boot the same directory against another engine or with the next salt generation.
- `src/Entity/User.php` — the customer: a readable `displayName`, an `email` on `encryptedAes256fixed` (deterministic, so a login can look it up), a `phone` and a nullable `address` on `encryptedAes256` (random, so two equal values never share a ciphertext).
- `src/Service/CustomerDirectory.php` — registration and the lookups: by e-mail through `EntityService::setEncryptedParameter()`, across every active salt version through `setEncryptedParameterInList()`, by phone as the refusal the library makes for a random column; `hasEncryptedValue()` for what the row holds on disk and `getEntitiesWithEncryption()` for what the mapping declares.
- `src/Exception/Exception.php` — the directory's own exception on the bundle's, so it carries a context.

## What each test shows

| Test file                                  | Library capability demonstrated                                                                                                                                                                                                                                                                               |
|--------------------------------------------|---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| `tests/Functional/EncryptedFieldTest.php`  | a registered user stored as a six-part envelope and read back as plaintext, the deterministic column repeating its ciphertext where the random one never does, `null` staying `null` on disk, `hasEncryptedValue()` and the encrypted fields read from the mapping                                            |
| `tests/Functional/CustomerLookupTest.php`  | the lookup by the deterministic e-mail, `NonDeterministicEncryptorException` for a random column, and the lookup during a rotation matching the ciphertext of every active salt version                                                                                                                       |
| `tests/Functional/DatabaseCommandTest.php` | `database:encrypt` over a legacy plaintext table read transparently before the switch-over, in batches with a checkpoint, idempotent on a second run, `database:decrypt` back to plaintext, and `--dry-run` walking the rows without writing a value or the checkpoint                                        |
| `tests/Functional/SaltRotationTest.php`    | the online rotation: the next salt current with the previous one readable, `database:rotate --dry-run --verify` failing before and passing after, the rows rewritten in batches under the new salt with `--verify`, and the plain lookup working again once the deterministic column carries the current salt |
| `tests/Functional/CheckpointTest.php`      | a checkpoint left mid-run resuming after its cursor and starting over once the class completed, the version 2 file with its scope, and the refusal of a file written by another command or towards another salt version                                                                                       |

Two things worth knowing before writing a scenario of your own: the encrypted types live in Doctrine's global type registry, so the last kernel booted in a process decides which encryptors the types carry — a test that boots two salt generations runs its commands on the second one; and the kernel boots without debug and with its cache removed before every boot, because a debug kernel dumps `config/reference.php` next to the sources while a cached one would ignore a changed salts map.

## How to run

From the repository root, with the databases up:

```bash
.dev/validate/all.sh --example
```

or by hand, inside the dev container:

```bash
cd .example && composer install && composer check
```

`composer.lock` is not committed: the example installs the bundle from the working tree through a path repository, so it always tests the code as it stands. `composer test` runs with `--fail-on-skipped`, so a database that is not there is a failure, not a skip. The root's `composer cs-check` covers this directory; `phpstan.neon` includes `../.dev/phpstan/rules.neon`, so the house rules apply here too. The directory is `export-ignore`d and never reaches a consumer's `vendor/`.

# Doctrine encrypt

The bundle will automatically register the types from **\PrecisionSoft\Doctrine\Encrypt\Type** as Doctrine types.

It can be used for any string field.

**You may fork and modify it as you wish**.

**Contributions are welcomed**.

## Purpose

Encrypt and decrypt data using Doctrine.

I am trying to solve a few problems that i found with the current offerings:

* Have encrypt and decrypt available if using entities or just selecting fields.
* Easy where (_for the moment the parameters have to be encrypted before setting them_).

## Usage

* The value on the entity will always be unencrypted.
* The purpose for **AES256FixedEncryptor**, **AES256FixedType** pair is to be able to use **WHERE**, as it will always return the same result for the same input.
* **EntityService::getEncryptor()** will return the encryptor used for the field, if you need to encrypt a value to use it as a **WHERE** parameter.
* Inside entity:

```php
class Customer
{
    /**
     * @ORM\Column(type="encryptedAES256")
     */
    private string $name;

    public function getName(): ?string
    {
        return $this->name;
    }

    public function setName(string $name): self
    {
        $this->name = $name;

        return $this;
    }
}
```

* To encrypt an unencrypted database:

```shell script 
php bin/console precision-soft:doctrine:database:encrypt
```

* To decrypt an encrypted database:

```shell script 
php bin/console precision-soft:doctrine:database:decrypt
```

## Dev

```shell
git clone git@gitlab.com:precision-soft-open-source/symfony/doctrine-encrypt.git
cd doctrine-encrypt

./dc build && ./dc up -d
```

## Todo

* Easy where, pass the unencrypted params and have them automatically encrypt.
* Configure registered encryptors.
* Have a **isEncrypted($entity, $fieldName): bool** method.
* Unit tests.

## Inspired by

* https://github.com/GiveMeAllYourCats/DoctrineEncryptBundle
* https://github.com/jackprice/doctrine-encrypt

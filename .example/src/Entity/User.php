<?php

declare(strict_types=1);

/*
 * Copyright (c) Precision Soft
 */

namespace PrecisionSoft\Doctrine\Encrypt\Example\Entity;

use Doctrine\ORM\Mapping as ORM;

/**
 * The display name stays readable for every listing; the e-mail is deterministic so a login can look it up, the phone and the address are random so equal values never share a ciphertext.
 */
#[ORM\Entity]
#[ORM\Table(name: 'customer_user')]
class User
{
    #[ORM\Id]
    #[ORM\GeneratedValue]
    #[ORM\Column(type: 'integer')]
    protected ?int $id = null;

    #[ORM\Column(type: 'string', length: 64)]
    protected string $displayName;

    #[ORM\Column(type: 'encryptedAes256fixed', length: 512)]
    protected string $email;

    #[ORM\Column(type: 'encryptedAes256', length: 512)]
    protected string $phone;

    #[ORM\Column(type: 'encryptedAes256', length: 1024, nullable: true)]
    protected ?string $address;

    public function __construct(string $displayName, string $email, string $phone, ?string $address = null)
    {
        $this->displayName = $displayName;
        $this->email = $email;
        $this->phone = $phone;
        $this->address = $address;
    }

    public function getId(): ?int
    {
        return $this->id;
    }

    public function getDisplayName(): string
    {
        return $this->displayName;
    }

    public function getEmail(): string
    {
        return $this->email;
    }

    public function setEmail(string $email): static
    {
        $this->email = $email;

        return $this;
    }

    public function getPhone(): string
    {
        return $this->phone;
    }

    public function setPhone(string $phone): static
    {
        $this->phone = $phone;

        return $this;
    }

    public function getAddress(): ?string
    {
        return $this->address;
    }

    public function setAddress(?string $address): static
    {
        $this->address = $address;

        return $this;
    }
}

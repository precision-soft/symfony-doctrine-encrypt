<?php

declare(strict_types=1);

/*
 * Copyright (c) Precision Soft
 */

namespace PrecisionSoft\Doctrine\Encrypt\Test\Utility\Entity;

use Doctrine\ORM\Mapping as ORM;

/**
 * `$defaultLength` omits its length on purpose, so the column is created at `AbstractType::DEFAULT_LENGTH` and ciphertext expansion can be observed against a real engine.
 *
 * @internal
 */
#[ORM\Entity]
#[ORM\Table(name: 'encrypted_subject')]
class EncryptedSubject
{
    #[ORM\Id]
    #[ORM\GeneratedValue]
    #[ORM\Column(type: 'integer')]
    protected ?int $id = null;

    #[ORM\Column(type: 'string', length: 64)]
    protected string $label = '';

    #[ORM\Column(type: 'encryptedAes256', length: 4096, nullable: true)]
    protected ?string $randomised = null;

    #[ORM\Column(type: 'encryptedAes256fixed', length: 4096, nullable: true)]
    protected ?string $deterministicValue = null;

    #[ORM\Column(type: 'encryptedAes256', nullable: true)]
    protected ?string $defaultLength = null;

    public function getId(): ?int
    {
        return $this->id;
    }

    public function getLabel(): string
    {
        return $this->label;
    }

    public function setLabel(string $label): static
    {
        $this->label = $label;

        return $this;
    }

    public function getRandomised(): ?string
    {
        return $this->randomised;
    }

    public function setRandomised(?string $randomised): static
    {
        $this->randomised = $randomised;

        return $this;
    }

    public function getDeterministicValue(): ?string
    {
        return $this->deterministicValue;
    }

    public function setDeterministicValue(?string $deterministicValue): static
    {
        $this->deterministicValue = $deterministicValue;

        return $this;
    }

    public function getDefaultLength(): ?string
    {
        return $this->defaultLength;
    }

    public function setDefaultLength(?string $defaultLength): static
    {
        $this->defaultLength = $defaultLength;

        return $this;
    }
}

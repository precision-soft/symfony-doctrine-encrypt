<?php

declare(strict_types=1);

/*
 * Copyright (c) Precision Soft
 */

namespace PrecisionSoft\Doctrine\Encrypt\Test\Utility\Entity;

use Doctrine\ORM\Mapping as ORM;

/** @internal */
#[ORM\Entity]
#[ORM\Table(name: 'encrypted_bigint_subject')]
class BigintEncryptedSubject
{
    #[ORM\Id]
    #[ORM\GeneratedValue]
    #[ORM\Column(type: 'bigint')]
    protected int|string|null $id = null;

    #[ORM\Column(type: 'string', length: 64)]
    protected string $label = '';

    #[ORM\Column(type: 'encryptedAes256', length: 4096, nullable: true)]
    protected ?string $randomised = null;

    public function getId(): int|string|null
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
}

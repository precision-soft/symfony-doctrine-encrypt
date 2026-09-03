<?php

declare(strict_types=1);

/*
 * Copyright (c) Precision Soft
 */

namespace PrecisionSoft\Doctrine\Encrypt\Example\Service;

use Doctrine\ORM\EntityManagerInterface;
use Doctrine\Persistence\ManagerRegistry;
use PrecisionSoft\Doctrine\Encrypt\Example\Entity\User;
use PrecisionSoft\Doctrine\Encrypt\Example\Exception\Exception;
use PrecisionSoft\Doctrine\Encrypt\Service\EntityService;

/**
 * The customer directory: registration, the lookups a login and a support desk need, and the questions an operator asks about what the database holds.
 */
class CustomerDirectory
{
    public function __construct(
        protected readonly ManagerRegistry $managerRegistry,
        protected readonly EntityService $entityService,
    ) {}

    public function register(string $displayName, string $email, string $phone, ?string $address = null): User
    {
        $user = new User($displayName, $email, $phone, $address);

        $entityManager = $this->getEntityManager();
        $entityManager->persist($user);
        $entityManager->flush();

        return $user;
    }

    /** the login path: one ciphertext per e-mail under the current salt, so the column can be compared */
    public function findByEmail(string $email): ?User
    {
        $queryBuilder = $this->getEntityManager()->createQueryBuilder()
            ->select('u')
            ->from(User::class, 'u')
            ->where('u.email = :email');

        $this->entityService->setEncryptedParameter($queryBuilder, 'email', User::class, 'email', $email);

        $user = $queryBuilder->getQuery()->getOneOrNullResult();

        return true === $user instanceof User ? $user : null;
    }

    /**
     * the same lookup while a rotation is in flight: a row written under the previous salt carries another ciphertext, so every active salt version is a candidate
     *
     * @return list<string> the ciphertexts the query compared against, one per active salt version
     */
    public function findByEmailAcrossSaltVersions(string $email, ?User &$user = null): array
    {
        $queryBuilder = $this->getEntityManager()->createQueryBuilder()
            ->select('u')
            ->from(User::class, 'u')
            ->where('u.email IN (:emails)');

        $candidates = $this->entityService->setEncryptedParameterInList($queryBuilder, 'emails', User::class, 'email', $email);

        $found = $queryBuilder->getQuery()->getOneOrNullResult();
        $user = true === $found instanceof User ? $found : null;

        return $candidates;
    }

    /** a random ciphertext never repeats, so the library refuses to build this comparison; the directory relays the refusal */
    public function findByPhone(string $phone): ?User
    {
        $queryBuilder = $this->getEntityManager()->createQueryBuilder()
            ->select('u')
            ->from(User::class, 'u')
            ->where('u.phone = :phone');

        $this->entityService->setEncryptedParameter($queryBuilder, 'phone', User::class, 'phone', $phone);

        $user = $queryBuilder->getQuery()->getOneOrNullResult();

        return true === $user instanceof User ? $user : null;
    }

    public function findById(int $id): User
    {
        $user = $this->getEntityManager()->find(User::class, $id);

        if (false === $user instanceof User) {
            throw new Exception(\sprintf('no user with the id `%d`', $id), 0, null, ['id' => $id]);
        }

        return $user;
    }

    /** reads the stored column back: true once the row is on disk as ciphertext, false for a plaintext row of a legacy import */
    public function hasStoredCiphertext(User $user, string $field): bool
    {
        return $this->entityService->hasEncryptedValue($user, $field);
    }

    /** @return array<string, string> field name => encrypted type name, straight from the mapping */
    public function getEncryptedFields(): array
    {
        foreach ($this->entityService->getEntitiesWithEncryption() as $entityMetadataDto) {
            if (User::class === $entityMetadataDto->getClassMetadata()->getName()) {
                return $entityMetadataDto->getEncryptionFields();
            }
        }

        return [];
    }

    public function hasEncryption(string $field): bool
    {
        return $this->entityService->hasEncryption(User::class, $field);
    }

    protected function getEntityManager(): EntityManagerInterface
    {
        $objectManager = $this->managerRegistry->getManager();

        if (false === $objectManager instanceof EntityManagerInterface) {
            throw new Exception(\sprintf('expected an `EntityManagerInterface`, got `%s`', $objectManager::class));
        }

        return $objectManager;
    }
}

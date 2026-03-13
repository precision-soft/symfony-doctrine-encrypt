<?php

declare(strict_types=1);

/*
 * Copyright (c) Precision Soft
 */

namespace PrecisionSoft\Doctrine\Encrypt\Command;

use Doctrine\Persistence\ManagerRegistry;
use Doctrine\Persistence\ObjectManager;
use PrecisionSoft\Doctrine\Encrypt\Dto\EntityMetadataDto;
use PrecisionSoft\Doctrine\Encrypt\Exception\StopException;
use PrecisionSoft\Doctrine\Encrypt\Service\EncryptorFactory;
use PrecisionSoft\Doctrine\Encrypt\Service\EntityService;
use PrecisionSoft\Symfony\Console\Command\AbstractCommand;
use Symfony\Component\Console\Input\InputOption;
use Symfony\Component\Console\Question\ConfirmationQuestion;

abstract class AbstractDatabaseCommand extends AbstractCommand
{
    protected const OPTION_MANAGER = 'manager';

    public function __construct(
        protected readonly ManagerRegistry $managerRegistry,
        protected readonly EncryptorFactory $encryptorFactory,
        protected readonly EntityService $entityService,
    ) {
        parent::__construct();
    }

    protected function configure(): void
    {
        parent::configure();

        $this->addOption(self::OPTION_MANAGER, null, InputOption::VALUE_OPTIONAL, 'the entity manager for which to run the command');
    }

    protected function getManagerName(): ?string
    {
        $managerName = $this->input->getOption(self::OPTION_MANAGER);

        return \is_string($managerName) ? $managerName : null;
    }

    protected function getManager(): ObjectManager
    {
        return $this->managerRegistry->getManager($this->getManagerName());
    }

    protected function getOriginalEntityData(EntityMetadataDto $entityMetadataDto): array
    {
        $originalEntityData = [];

        foreach ($entityMetadataDto->getEncryptionFields() as $field => $type) {
            $originalEntityData[$field] = null;
        }

        return $originalEntityData;
    }

    protected function askForConfirmation(array $entitiesWithEncryption): void
    {
        if (false === $this->input->isInteractive()) {
            return;
        }

        $confirmationQuestion = new ConfirmationQuestion(
            $this->getQuestionText(
                [
                    \sprintf('`%s` entities found which are containing properties with encryption types.', \count($entitiesWithEncryption)),
                    'wrong settings can make your data unrecoverable.',
                    'i advise you to make a backup before running this command.',
                    'continue with this action? (y/yes)',
                ],
            ),
            false,
        );

        $question = $this->getHelper('question');

        if (false === $question->ask($this->input, $this->output, $confirmationQuestion)) {
            throw new StopException();
        }
    }

    private function getQuestionText(array $questionParts): string
    {
        $maxLength = 0;

        foreach ($questionParts as $questionPart) {
            $maxLength = \max(\strlen($questionPart), $maxLength);
        }

        $indent = \str_repeat(' ', 4);

        foreach ($questionParts as &$questionPart) {
            $questionPart = $indent . \str_pad($questionPart, $maxLength, ' ');
        }

        unset($questionPart);

        return '<question>' . \implode(\PHP_EOL, $questionParts) . '</question>: ';
    }
}

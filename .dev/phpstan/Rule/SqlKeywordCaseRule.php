<?php

declare(strict_types=1);

/*
 * Copyright (c) Precision Soft
 */

namespace PrecisionSoft\Dev\PhpStan\Rule;

use PhpParser\Node;
use PhpParser\Node\InterpolatedStringPart;
use PhpParser\Node\Scalar\InterpolatedString;
use PhpParser\Node\Scalar\String_;
use PHPStan\Analyser\Scope;
use PHPStan\Rules\IdentifierRuleError;
use PHPStan\Rules\Rule;
use PHPStan\Rules\RuleErrorBuilder;

/** @implements Rule<Node> */
class SqlKeywordCaseRule implements Rule
{
    /** @var list<string> */
    protected const STATEMENT_KEYWORD_LIST = ['SELECT', 'INSERT', 'UPDATE', 'DELETE', 'CREATE', 'ALTER', 'DROP', 'TRUNCATE', 'WITH'];
    /** @var list<string> */
    protected const CLAUSE_KEYWORD_LIST = ['FROM', 'INTO', 'SET', 'TABLE', 'WHERE', 'VALUES', 'JOIN', 'EXISTS'];
    /** @var list<string> */
    protected const PHRASE_LIST = ['ORDER BY', 'GROUP BY', 'PARTITION BY', 'IS NULL', 'IS NOT NULL', 'NOT NULL', 'IF NOT EXISTS', 'IF EXISTS', 'ON DELETE', 'ON UPDATE', 'PRIMARY KEY', 'FOREIGN KEY', 'UNIQUE KEY', 'AUTO_INCREMENT'];
    /** @var list<string> */
    protected const WORD_LIST = [
        'ABS', 'ADD', 'ALL', 'ALTER', 'AND', 'ANY', 'ARRAY', 'AS', 'ASC', 'AVG', 'BEGIN', 'BETWEEN', 'BIGINT', 'BINARY', 'BIT', 'BLOB', 'BOOL', 'BOOLEAN', 'BYTEA',
        'CASCADE', 'CASE', 'CAST', 'CHANGE', 'CHAR', 'CHARACTER', 'CHARSET', 'CHECK', 'COALESCE', 'COLLATE', 'COLUMN', 'COMMENT', 'COMMIT', 'CONCAT', 'CONSTRAINT',
        'CONVERT', 'COUNT', 'CREATE', 'CROSS', 'CURRENT_DATE', 'CURRENT_TIME', 'CURRENT_TIMESTAMP', 'DATABASE', 'DATE', 'DATETIME', 'DAY', 'DECIMAL', 'DECLARE',
        'DEFAULT', 'DELETE', 'DESC', 'DESCRIBE', 'DISTINCT', 'DOUBLE', 'DROP', 'DUPLICATE', 'ELSE', 'END', 'ENGINE', 'ENUM', 'ESCAPE', 'EXCEPT', 'EXECUTE',
        'EXISTS', 'EXPLAIN', 'FALSE', 'FETCH', 'FIRST', 'FLOAT', 'FOR', 'FOREIGN', 'FROM', 'FULL', 'FUNCTION', 'GET_LOCK', 'GRANT', 'HAVING', 'HOUR',
        'IF', 'IFNULL', 'IGNORE', 'ILIKE', 'IN', 'INDEX', 'INNER', 'INSERT', 'INT', 'INTEGER', 'INTERSECT', 'INTERVAL', 'INTO', 'IS', 'IS_FREE_LOCK', 'IS_USED_LOCK',
        'JOIN', 'JSON', 'JSONB', 'JSON_EXTRACT', 'JSON_UNQUOTE', 'KEY', 'LAST', 'LAST_INSERT_ID', 'LEFT', 'LENGTH', 'LIKE', 'LIMIT', 'LOCK', 'LOCKED', 'LONGBLOB',
        'LONGTEXT', 'LOWER', 'MATCH', 'MAX', 'MEDIUMINT', 'MEDIUMTEXT', 'MIN', 'MINUTE', 'MODIFY', 'MONTH', 'NATURAL', 'NEXT', 'NOT', 'NOW', 'NOWAIT', 'NULL',
        'NULLIF', 'NULLS', 'NUMERIC', 'OFFSET', 'ON', 'ONLY', 'OR', 'OUTER', 'OVER', 'PRECISION', 'PREPARE', 'PRIMARY', 'REAL', 'REFERENCES', 'RELEASE',
        'RELEASE_LOCK', 'RENAME', 'REPLACE', 'RESTRICT', 'RETURNING', 'REVOKE', 'RIGHT', 'ROLLBACK', 'ROUND', 'ROW', 'ROWS', 'ROW_NUMBER', 'SAVEPOINT', 'SCHEMA',
        'SECOND', 'SELECT', 'SEQUENCE', 'SERIAL', 'SET', 'SHARE', 'SHOW', 'SKIP', 'SMALLINT', 'SOME', 'START', 'SUBSTRING', 'SUM', 'TABLE', 'TEMPORARY', 'TEXT',
        'THEN', 'TIME', 'TIMESTAMP', 'TINYINT', 'TINYTEXT', 'TO', 'TRANSACTION', 'TRIGGER', 'TRIM', 'TRUE', 'TRUNCATE', 'UNION', 'UNIQUE', 'UNSIGNED', 'UPDATE',
        'UPPER', 'USE', 'USING', 'UUID', 'VALUES', 'VARBINARY', 'VARCHAR', 'VIEW', 'WHEN', 'WHERE', 'WINDOW', 'WITH', 'YEAR', 'ZEROFILL',
        'PG_ADVISORY_LOCK', 'PG_ADVISORY_UNLOCK', 'PG_TRY_ADVISORY_LOCK', 'PG_ADVISORY_XACT_LOCK', 'PG_TRY_ADVISORY_XACT_LOCK',
        'JSON_SEARCH', 'JSON_CONTAINS', 'JSON_LENGTH', 'JSON_VALUE', 'JSON_TABLE', 'JSON_ARRAY', 'JSON_OBJECT', 'JSON_SET', 'JSON_KEYS', 'JSON_TYPE',
        'JSON_VALID', 'JSON_QUOTE', 'JSON_MERGE_PATCH', 'JSON_ARRAYAGG', 'JSON_OBJECTAGG', 'JSONB_BUILD_OBJECT', 'JSONB_AGG', 'DATE_FORMAT', 'DATE_ADD',
        'DATE_SUB', 'DATEDIFF', 'TIMESTAMPDIFF', 'UNIX_TIMESTAMP', 'FROM_UNIXTIME', 'STR_TO_DATE', 'GREATEST', 'LEAST', 'GROUP_CONCAT', 'STRING_AGG',
        'ARRAY_AGG', 'GENERATE_SERIES', 'EXTRACT', 'EPOCH', 'FLOOR', 'CEIL', 'CEILING', 'MOD', 'POWER', 'SQRT', 'RAND', 'RANDOM', 'MD5', 'SHA1', 'SHA2',
        'HEX', 'UNHEX', 'INSTR', 'LOCATE', 'POSITION', 'LPAD', 'RPAD', 'LTRIM', 'RTRIM', 'REVERSE', 'REGEXP', 'RLIKE', 'SIMILAR', 'COLLATION', 'CHARACTER_LENGTH',
        'CHAR_LENGTH', 'OCTET_LENGTH', 'ASCII', 'ORD', 'FORMAT', 'TRUNCATE', 'SIGN', 'PI', 'EXP', 'LN', 'LOG', 'LOG10', 'LOG2', 'CURDATE', 'CURTIME', 'SYSDATE',
        'UTC_TIMESTAMP', 'LOCALTIME', 'LOCALTIMESTAMP', 'DAYOFWEEK', 'DAYOFMONTH', 'DAYOFYEAR', 'WEEK', 'QUARTER', 'MICROSECOND', 'UUID_TO_BIN', 'BIN_TO_UUID',
        'GEN_RANDOM_UUID', 'NEXTVAL', 'CURRVAL', 'SETVAL', 'LASTVAL', 'ROW_COUNT', 'FOUND_ROWS', 'VERSION', 'CONNECTION_ID', 'BIT_AND', 'BIT_OR', 'BIT_XOR',
        'STDDEV', 'STDDEV_POP', 'STDDEV_SAMP', 'VARIANCE', 'VAR_POP', 'VAR_SAMP', 'RANK', 'DENSE_RANK', 'NTILE', 'LAG', 'LEAD', 'FIRST_VALUE', 'LAST_VALUE',
    ];

    public function getNodeType(): string
    {
        return Node::class;
    }

    public function processNode(Node $node, Scope $scope): array
    {
        $text = $this->getText($node);

        if (null === $text || false === $this->isSql($text)) {
            return [];
        }

        $errorList = [];

        foreach ($this->getViolationList($text) as [$word, $isKeyword]) {
            $errorList[] = $this->buildError($word, $isKeyword);
        }

        return $errorList;
    }

    protected function getText(Node $node): ?string
    {
        if (true === $node instanceof String_) {
            return $node->value;
        }

        if (false === $node instanceof InterpolatedString) {
            return null;
        }

        $text = '';

        foreach ($node->parts as $part) {
            $text .= true === $part instanceof InterpolatedStringPart ? $part->value : ' ? ';
        }

        return $text;
    }

    protected function isSql(string $text): bool
    {
        $wordList = \preg_split('/[^A-Za-z0-9_]+/', \trim($text), -1, \PREG_SPLIT_NO_EMPTY);

        if (false === $wordList || 0 === \count($wordList)) {
            return false;
        }

        if (false === \in_array(\strtoupper($wordList[0]), static::STATEMENT_KEYWORD_LIST, true)) {
            return false;
        }

        foreach (\array_slice($wordList, 1) as $word) {
            if (true === \in_array(\strtoupper($word), static::CLAUSE_KEYWORD_LIST, true)) {
                return true;
            }
        }

        return false;
    }

    /** @return list<array{0: string, 1: bool}> */
    protected function getViolationList(string $text): array
    {
        $violationList = [];
        $cleanText = \preg_replace(
            [
                "/'(?:[^'\\\\]|\\\\.)*'/",
                '/"(?:[^"\\\\]|\\\\.)*"/',
                '/`[^`]*`/',
                '/\[[^\]]*\]/',
                '/:[A-Za-z_][A-Za-z0-9_]*/',
                '/%[A-Za-z]/',
            ],
            ' ',
            $text,
        ) ?? $text;

        foreach (static::PHRASE_LIST as $phrase) {
            $phrasePattern = '/\b' . \str_replace(' ', '\s+', \preg_quote($phrase, '/')) . '\b/i';

            \preg_match_all($phrasePattern, $cleanText, $matchList);

            foreach ($matchList[0] as $match) {
                $normalisedMatch = \preg_replace('/\s+/', ' ', $match) ?? $match;

                if ($phrase !== $normalisedMatch) {
                    $violationList[] = [$normalisedMatch, true];
                }
            }

            $cleanText = \preg_replace($phrasePattern, ' ', $cleanText) ?? $cleanText;
        }

        $wordList = \preg_split('/[^A-Za-z0-9_]+/', $cleanText, -1, \PREG_SPLIT_NO_EMPTY);

        foreach (false === $wordList ? [] : $wordList as $word) {
            $upperWord = \strtoupper($word);
            $isKnownWord = true === \in_array($upperWord, static::WORD_LIST, true);

            if (true === $isKnownWord && $word !== $upperWord) {
                $violationList[] = [$word, true];

                continue;
            }

            if (false === $isKnownWord && 1 === \preg_match('/^[A-Z][A-Z0-9_]+$/', $word)) {
                $violationList[] = [$word, false];
            }
        }

        return $violationList;
    }

    protected function buildError(string $word, bool $isKeyword): IdentifierRuleError
    {
        $message = true === $isKeyword
            ? \sprintf('sql keyword `%s` must be uppercase', $word)
            : \sprintf('sql identifier `%s` must be lowercase (only keywords and functions are uppercase)', $word);

        return RuleErrorBuilder::message($message)
            ->identifier('precisionSoft.sqlKeywordCase')
            ->build();
    }
}

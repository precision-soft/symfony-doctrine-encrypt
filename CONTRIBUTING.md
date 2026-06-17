# CONTRIBUTING

This document describes local development, testing, and contribution rules for Symfony Doctrine Encrypt.

## Development setup

Prerequisites:

- PHP 8.2+
- Composer
- Docker (the repository ships a containerized development shell under [`.dev/`](./.dev/))

The repository uses a Docker-based development shell driven by the [`./dc`](./dc) wrapper (a thin Docker
Compose wrapper), which also installs the repository git hooks (see the `install-hooks` script in
[`composer.json`](./composer.json)):

```bash
./dc build && ./dc up -d   # build and start the `dev` container (composer install runs on boot)
./dc exec dev bash         # open a shell inside the container
```

Inside the container, run the verification commands described below.

## Verification

The development shell profile ([`.dev/docker/.profile`](./.dev/docker/.profile)) defines convenience
functions:

- `ci` / `cu` — `composer install` / `composer update`
- `pfix` — run `php-cs-fixer` (PER-CS 2.0 code style)
- `punit` — run `simple-phpunit` (the test suite)
- `pstan` — run `phpstan` (level 8 static analysis)
- `full` — run `composer install`, then `pfix`, `punit`, and `pstan` in sequence

Run the full suite before opening a pull request:

```bash
full
```

The git `pre-commit` hook ([`.dev/git-hooks/pre-commit`](./.dev/git-hooks/pre-commit)) enforces the same
checks on staged PHP files: `php-cs-fixer`, `php -l`, `phpstan`, and `simple-phpunit`. A commit is
rejected if any of them fail.

## Development workflow

Before opening a pull request:

1. Run the full verification suite (see [Verification](#verification)).
2. Keep changes scoped. Avoid drive-by refactors unless they are required for the change.
3. Update documentation when behavior, invariants, or public APIs change — including
   [`README.md`](./README.md) and [`CHANGELOG.md`](./CHANGELOG.md).

## Code style

The repository enforces a strict, opinionated style on top of
[PER-CS 2.0](https://www.php-fig.org/per/coding-style/). `php-cs-fixer` and `phpstan` (level 8) are the
automated enforcers; the rules below are normative and contributions are expected to follow them.

### Naming

- Explicit, descriptive names with **zero unnecessary abbreviations** (`reference` not `ref`,
  `repository` not `repo`, `configuration` not `config`, `service` not `svc`).
- Acronyms in camelCase for identifiers: `urlString`, `httpClient`, `jsonDecoder`, `userId`.
- Acronyms in class names use CamelCase, not all-caps: `Dto` not `DTO`, `Http` not `HTTP`,
  `Api` not `API`, `Url` not `URL`.
- Singular names for classes, types, files, and directories (unless the project requires plural).
- `camelCase` for variables, methods, and properties.
- No numbered variables — never `$result1` / `$result2`; use descriptive names such as
  `$firstResult` / `$secondResult` or `$userEntity` / `$postEntity`.
- A variable holding an instance is named after its class (or alias) in camelCase:
  `$testBackedEnumType = new TestBackedEnumType()`.

### Comparisons and boolean logic

- Apply **Yoda style** for all equality comparisons (constant on the left):
  `null === $value`, `'x' === $value`, `0 === count($items)`.
- **Never use the `!` negation operator.** Express conditions with explicit comparisons instead.
- **No implicit boolean coercion.** Every condition must be an explicit comparison:
  `true === $flag`, `null === $value`, `false === class_exists($class)`, `true === empty($items)`.
  Never write bare `if ($var)`, `if (!$var)`, or `if (empty($var))`.

### Imports

- **All classes are imported via `use` at the top of the file.** Never reference a class by its
  fully-qualified name inline (no `new \Foo\Bar\Baz()` or `\Foo\Bar\Baz::method()`).
- On a naming conflict, use an alias: `use Foo\Bar\Baz as AliasedBaz;`.
- Built-in PHP functions may keep the backslash prefix (`\sprintf`, `\time`, `\ini_get`); the `use`
  rule applies only to classes and interfaces.

### Class member ordering

Top-to-bottom order inside a class body:

1. Trait imports (`use TraitName;`).
2. Constants — `public` → `protected` → `private`.
3. Static properties — `public` → `protected` → `private`.
4. Instance properties — `public` → `protected` → `private`.
5. Abstract methods (abstract classes only) — before all concrete methods.
6. Magic methods — grouped, `__construct` first.
7. Static methods — `public` → `protected` → `private`.
8. Instance methods — `public` → `protected` → `private`.

Getters/setters do not form their own block: they follow the declaration order of the properties they
access, grouped by visibility.

### Getters and setters

- Always `getXyz()` / `setXyz()` for property accessors — never `isXyz()`, even for booleans.
- `hasXyz()` is allowed for boolean query / existence-check methods (for example `hasPermission()`);
  these are query methods, not property getters.

### Exceptions

- Always throw **project-specific exceptions** from the project's own `Exception` namespace. Never throw
  generic `\Exception` or `\RuntimeException`.

### Doctrine entities

- Entities contain only getters and setters — no business logic (logic belongs in services).

### Comments and messages

- All comments in **English**, and minimal — only when they add real architectural or contractual value.
- No `@todo` markers in code; track work in the issue tracker instead.
- Error messages must be **fully lowercase**.

## Reporting bugs

When submitting a bug report, include:

- The exact version (tag/commit).
- PHP version and operating system.
- Clear reproduction steps (minimal example if possible).
- The observed behavior and the expected behavior.
- Relevant logs and stack traces (redact secrets).

If the issue is security-sensitive, do not file it publicly; follow [`SECURITY.md`](./SECURITY.md).

## Submitting pull requests

- Use a topic branch based on `main`.
- Keep the PR focused: one logical change-set per PR.
- Add or update tests for behavioral changes.
- Update [`CHANGELOG.md`](./CHANGELOG.md) under the `[Unreleased]` section.
- Update [`README.md`](./README.md) when userland behavior or the public API changes.

## Security and support

- For security issues, follow [`SECURITY.md`](./SECURITY.md): report privately through GitHub's private
  vulnerability reporting with a minimal reproduction and impact assessment. Do not open a public issue.
- For non-security questions, use the standard issue tracker and include context (version, steps, logs).

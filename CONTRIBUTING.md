# CONTRIBUTING

This document describes local development, testing, and contribution rules for Symfony Doctrine Encrypt.

## Development setup

Prerequisites:

- PHP 8.2+
- Composer
- Docker (the repository ships a containerized development shell under [`.dev/`](./.dev/))

The repository uses a Docker-based development shell driven by the [`./dc`](./dc) wrapper (a thin Docker Compose wrapper), which also installs the repository git hooks (see the `install-hooks` script in
[`composer.json`](./composer.json)):

```bash
./dc build && ./dc up -d   # build and start the `dev` container (composer install runs on boot)
./dc exec dev bash         # open a shell inside the container
```

Inside the container, run the verification commands described below.

## Verification

The development shell profile ([`.dev/docker/.profile`](./.dev/docker/.profile)) defines convenience functions:

- `ci` / `cu` — `composer install` / `composer update`
- `pfix` — run `php-cs-fixer` (PER-CS 2.0 code style)
- `punit` — run `simple-phpunit` (the test suite)
- `pstan` — run `phpstan` (level 8 static analysis)
- `full` — run `composer install`, then `pfix`, `punit`, and `pstan` in sequence

The gate itself lives in one place — [`.dev/validate/all.sh`](./.dev/validate/all.sh) — so a section is added once and every caller inherits it. Run it from the host, before opening a pull request:

```bash
.dev/validate/all.sh                  # cs-check, phpstan, test
.dev/validate/all.sh --audit          # also audit the locked dependencies (needs the network)
.dev/validate/all.sh --integration    # also run the integration suite (starts mysql and mariadb)
.dev/validate/all.sh --example        # also run the example application's gate (skipped with a notice where .example/ has no composer.json yet)
.dev/validate/all.sh --mutation       # also run mutation testing (slow: the suite runs once per mutant)
```

The three default sections are what `composer check` runs, so they stay fast and offline. The four flagged sections are deliberately outside it: `--audit` is the only section needing the network, `--integration` needs a running database, and `--mutation` costs a full suite run per mutant. `--example` installs and checks the example application under `.example/` — a standalone `composer.json` that takes this package from the working tree through a path repository, so the section drives the code the way a consumer does; it is skipped with a notice where `.example/` carries no `composer.json` yet, and under `--staged` it runs whenever the index touches `.example/`. The composer script is named `deps-audit` rather than `audit`, because a script named `audit` collides with Composer's own command and is skipped in silence.

The git `pre-commit` hook ([`.dev/git-hooks/pre-commit`](./.dev/git-hooks/pre-commit)) is a deliberately thin caller of the same script (`--staged`, which does nothing unless the index carries a PHP change). It checks and never fixes — run `composer cs-fix` yourself. It adds one guard CI cannot: it reads the index and rejects a force-staged `.dev-data/` path or `.dev/docker/.env.local`, both of which are gitignored and, by the time a push reaches CI, would already be in the history.

### Development toolchain

The dev image ([`.dev/docker/Dockerfile`](./.dev/docker/Dockerfile)) pins the two tools the gate needs but `composer.lock` must not describe:

- **pcov** is built from a pinned tarball rather than `pecl install`, so a rebuild cannot move the coverage driver under a mutation baseline. It is installed but disabled ([`.dev/docker/php.dev.ini`](./.dev/docker/php.dev.ini)) and enabled per run: `php -d pcov.enabled=1 vendor/bin/simple-phpunit --coverage-text`. The `composer mutation` script passes the same flag for the initial test run.
- **infection** is a pinned phar, not a composer dev dependency: `composer.lock` is one converged toolchain shared across the portfolio, and a tool outside `composer check` must not move it. The pin requires PHP 8.3, above this package's `>=8.2` floor, which is one reason the dev image defaults to PHP 8.4; an image built for the floor (`PHP_VERSION=8.2`) takes the last release that still runs there (`INFECTION_VERSION_PHP_8_2`), so both images carry a working `infection`. The default is (`PHP_VERSION` in [`.dev/docker/.env`](./.dev/docker/.env)); the floor still builds with `PHP_VERSION=8.2 ./dc build`, and CI's matrix certifies every version in between.

`php.dev.ini` is copied to `conf.d/zz-dev.ini`, so it sorts after every `docker-php-ext-*.ini` and has the last word. It lifts `memory_limit`, which `php.ini-production` ships at 128M — the `--memory-limit` flag stays in the composer scripts anyway, because CI runs them on a runner that never sees this overlay. `opcache.enable_cli = 0` is an explicit no-op: the CLI SAPI never loads opcache in these images, so stale code in the container is an inode problem in the bind mount, and `./dc restart dev` is the fix. The `.profile` copy is the last layer in the image, because every layer below a `COPY` is invalidated with it and `.profile` is the file that keeps changing.

`config.platform.php` in `composer.json` pins composer's resolution to the 8.2 floor, so `composer.lock` installs on every interpreter in the CI matrix no matter which one ran `composer update`; without it an update from the 8.4 container would lock Symfony 8, which needs PHP 8.4 and would fail the 8.2 and 8.3 legs. The `latest-deps` CI lane drops the pin on purpose, because it is the one job that wants the ceiling.

The `db` profile is started only on request (`./dc --profile db up -d`). `DATABASE_URL_MYSQL` and `DATABASE_URL_MARIADB` are set on the `dev` service whether or not it is up, so a test connects and skips rather than branching on configuration. The database services publish no ports and store on `tmpfs`, so their credentials reach nothing and no state survives a restart.

Mutation thresholds live in [`infection.json5`](./infection.json5) (`minMsi`, `minCoveredMsi`, both at 81). They are the measured baseline rounded down: raise them when the score improves, and never lower one to make a run pass.

### Continuous integration

[`.github/workflows/ci.yml`](./.github/workflows/ci.yml) cannot call `.dev/validate/all.sh` — the script needs Docker and a compose project — so it runs the same composer scripts natively across a PHP version matrix instead. Six jobs: `static`, `test` (`phpstan` and the suite on PHP 8.2 through 8.5), `integration` (real MySQL 8.4 and MariaDB 11.8), `latest-deps` (drops the platform pin, resolves the highest allowed dependency set on PHP 8.5 and asserts that the direct Symfony packages reached 8.x), `example` (installs and checks the example application under `.example/` on PHP 8.4, the dev default; a repository whose `.example/` carries no `composer.json` yet prints a notice and passes) and `audit`. Every job carries a 20-minute timeout, so a hung runner fails instead of holding the queue.

The integration job passes `--fail-on-skipped`, which is deliberately not in `phpunit.xml.dist`: locally a missing database is a skip, so `composer check` stays offline, while in CI a broken `DATABASE_URL` must fail instead of printing a screen of green skips. The `latest-deps` lane applies it to the unit suite as well, since it is the only lane whose dependencies are not pinned and therefore the only one where a suite could degrade to skips without anyone noticing.

Every job except `latest-deps` installs the locked dependencies. That one lane deliberately resolves the upper dependency bound, while the others keep reproducible analyser and test versions. The `vendor/bin/.phpunit` cache step comes *after* the install, because `simple-phpunit` builds a tree `composer.lock` does not describe and composer owns `vendor/`, so it would clean a pre-restored directory back out.

## Development workflow

Before opening a pull request:

1. Run the full verification suite (see [Verification](#verification)).
2. Keep changes scoped. Avoid drive-by refactors unless they are required for the change.
3. Update documentation when behavior, invariants, or public APIs change — including
   [`README.md`](./README.md) and [`CHANGELOG.md`](./CHANGELOG.md).

## Code style

The repository enforces a strict, opinionated style on top of
[PER-CS 2.0](https://www.php-fig.org/per/coding-style/). `php-cs-fixer` and `phpstan` (level 8) are the automated enforcers; the rules below are normative and contributions are expected to follow them.

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
  `true === $flag`, `null === $value`, `false === class_exists($class)`, `true === empty($items)`. Never write bare `if ($var)`, `if (!$var)`, or `if (empty($var))`.

### Imports

- **All classes are imported via `use` at the top of the file.** Never reference a class by its fully-qualified name inline (no `new \Foo\Bar\Baz()` or `\Foo\Bar\Baz::method()`).
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

Getters/setters do not form their own block: they follow the declaration order of the properties they access, grouped by visibility.

### Getters and setters

- Always `getXyz()` / `setXyz()` for property accessors — never `isXyz()`, even for booleans.
- `hasXyz()` is allowed for boolean query / existence-check methods (for example `hasPermission()`); these are query methods, not property getters.

### Exceptions

- Always throw **project-specific exceptions** from the project's own `Exception` namespace. Never throw generic `\Exception` or `\RuntimeException`.

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

- For security issues, follow [`SECURITY.md`](./SECURITY.md): report privately through GitHub's private vulnerability reporting with a minimal reproduction and impact assessment. Do not open a public issue.
- For non-security questions, use the standard issue tracker and include context (version, steps, logs).

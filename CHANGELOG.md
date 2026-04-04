# CHANGELOG

## v3.0.0

### Breaking changes

- Dropped Doctrine DBAL 3 support — requires DBAL 4.*
- Removed `AbstractType::getName()` (DBAL 3 compatibility method)
- Requires `precision-soft/symfony-console` 3.*
- Requires `precision-soft/symfony-phpunit` 2.* (dev)

### Improvements

- Code style alignment — variable naming, Yoda conditions, explicit comparisons
- Replaced `assertTrue`/`assertFalse`/`assertIsArray` with `assertSame` in all tests
- Standardized `.dev/` infrastructure (Dockerfile, docker-compose, pre-commit, utility.sh)
- Removed `squizlabs/php_codesniffer` (using php-cs-fixer only)
- Renamed `phpunit.xml` to `phpunit.xml.dist`
- PHPStan level 8 with baseline
- Expanded test coverage (143 tests, 263 assertions)

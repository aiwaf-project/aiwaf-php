# Examples

This folder contains framework-ready integration examples for the current PHP support scope.

## Included

- `plain-php/` - Single-file bootstrap for a classic front-controller app
- `laravel/` - Service-provider style bootstrap and console trainer command
- `symfony/` - Kernel/request bootstrap and console trainer command
- `wordpress/` - MU-plugin bootstrap and WP-CLI training command

## Notes

- Replace placeholder paths with your project-specific paths.
- Run AIWAF as early as possible in request handling.
- Keep training (`cli/detect_and_train.php`) on a schedule (cron or task scheduler).

## Docker Sandbox

This repo includes a Docker sandbox patterned like the original examples bundle:

- Compose file: `examples/sandbox/docker-compose.yml`
- Service Dockerfiles:
	- `examples/sandbox/aiwaf-laravel/Dockerfile`
	- `examples/sandbox/aiwaf-symfony/Dockerfile`
	- `examples/sandbox/aiwaf-wordpress/Dockerfile`
	- `examples/sandbox/aiwaf-trainer/Dockerfile`
	- `examples/sandbox/aiwaf-tests/Dockerfile`
- Target app service: `juice` (`bkimminich/juice-shop`)

Run from repo root:

```bash
docker compose -f examples/sandbox/docker-compose.yml up --build
```

This starts:

- AIWAF Laravel sandbox (`PHP 8.1`) on `http://localhost:8081`
- AIWAF Symfony sandbox (`PHP 8.2`) on `http://localhost:8082`
- AIWAF WordPress sandbox (`PHP 8.0`) on `http://localhost:8083`
- Juice Shop on `http://localhost:3001`

Each sandbox forwards traffic to the internal `juice:3000` target after AIWAF checks.

### Sandbox Test Utilities (Python + PHP)

The sandbox includes equivalent utilities in both Python and PHP:

- Attack suite runner:
	- `examples/sandbox/attack-suite.py`
	- `examples/sandbox/attack-suite.php`
- Aggregate compare:
	- `examples/sandbox/compare-results.py`
	- `examples/sandbox/compare-results.php`
- Mode compare (normal vs attacks):
	- `examples/sandbox/compare-results-modes.py`
	- `examples/sandbox/compare-results-modes.php`

Examples:

```bash
php examples/sandbox/attack-suite.php
php examples/sandbox/compare-results.php
php examples/sandbox/compare-results-modes.php
```

One-off trainer run:

```bash
docker compose -f examples/sandbox/docker-compose.yml --profile trainer run --rm aiwaf-trainer
```

One-off test run:

```bash
docker compose -f examples/sandbox/docker-compose.yml --profile tests run --rm aiwaf-tests
```

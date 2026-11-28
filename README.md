# iWorks.ie Security Audit

Free, read-only WordPress security audit for [wordpress.org](https://wordpress.org/plugins/iworksie-security-audit/). An audit, not a firewall: it runs only when you click, proves exposures with a real logged-out request, and explains every fix in plain English. Built on [`iworks-tools-core`](https://github.com/littlegreenman70/iworks-tools-core).

## Requirements

- WordPress 6.5+
- PHP 7.4+ (the plugin code is written for 7.4: no typed properties, union types, `match`, named arguments, enums, nullsafe or `readonly`)
- Composer and PHP 8.x for development tooling (Strauss needs PHP 8)

## Checks (22)

| Group | Check id | What it looks for |
|---|---|---|
| Exposure | `secret_files` | wp-config copies, `.env`, `.htpasswd`, phpinfo pages, downloadable |
| Exposure | `backup_files` | `.sql`, `.zip`, `.tar.gz`, `.wpress`, `.bak`… in web folders |
| Exposure | `version_control` | `.git` / `.svn` / `.hg` |
| Exposure | `log_files` | `debug.log`, `error_log`, `*.log` |
| Exposure | `directory_listing` | "Index of" pages on uploads / wp-includes |
| Config | `debug_display` | WP_DEBUG_DISPLAY, display_errors, public debug log |
| Config | `file_editor` | DISALLOW_FILE_EDIT |
| Config | `security_keys` | missing, sample text, short or duplicated salts |
| Config | `https` | home/site URL scheme |
| Config | `registration` | open sign-ups with a powerful default role |
| Config | `core_auto_updates` | automatic security releases disabled |
| Access | `admin_username` | guessable administrator logins |
| Access | `user_enumeration` | REST users endpoint and `?author=1` |
| Access | `xmlrpc` | open `xmlrpc.php` / `system.multicall` |
| Access | `login_protection` | a known 2FA / login-limit plugin is active |
| Software | `core_updates` | WordPress behind (same branch = Critical) |
| Software | `extension_updates` | plugin/theme updates waiting |
| Software | `abandoned_plugins` | closed on WordPress.org or no update in 2 years |
| Software | `inactive_code` | inactive plugins and themes |
| Software | `php_version` | PHP end of life |
| Server | `file_permissions` | world-writable key paths |
| Server | `security_headers` | HSTS, nosniff, framing, referrer policy, PHP version leak |

Exposure checks first list candidate files on disk (one level deep in the home, ABSPATH, wp-content, uploads and known backup-plugin folders), then request each anonymously. Only a 200/206 whose body matches the file type (e.g. `ref:` for `.git/HEAD`, `PK\x03\x04` for zips, `DB_NAME` for wp-config copies, never an HTML page) counts as exposed.

## Local development

```bash
composer install
ln -sfn "$(pwd)" /opt/homebrew/var/www/www.iworks.new/wp-content/plugins/iworksie-security-audit
wp plugin activate iworksie-security-audit --path=/opt/homebrew/var/www/www.iworks.new
```

Core is resolved from `../iworks-tools-core` in development and from the public GitHub repo in CI.

```bash
composer lint                 # PHPCS: WordPress standard + PHPCompatibilityWP 7.4-
composer analyse              # PHPStan level 6
composer test:unit
bin/install-wp-tests.sh iworks_tests_sa root '' 127.0.0.1 latest
composer test:integration
composer build                # build/iworksie-security-audit(.zip)

# Real WordPress + PHP in Docker against the built plugin:
curl -sSL -o bin/wp-cli.phar https://github.com/wp-cli/wp-cli/releases/download/v2.12.0/wp-cli-2.12.0.phar
bin/smoke-test.sh wordpress:php7.4-apache build/iworksie-security-audit /path/to/wordpress-6.5
```

## WP-CLI

```bash
wp iworksie-security audit
wp iworksie-security audit --format=json
```

## License

GPL-2.0-or-later

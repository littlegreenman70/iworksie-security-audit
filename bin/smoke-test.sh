#!/usr/bin/env bash
#
# End-to-end smoke test of the BUILT plugin in a real WordPress + PHP container.
#
# Usage:
#   bin/smoke-test.sh <wordpress-docker-image> <built-plugin-dir> [wp-core-dir] [extra-plugin-dir ...]
#
# Example:
#   bin/smoke-test.sh wordpress:php7.4-apache build/iworksie-security-audit ~/wp/6.5.15
#
# - <wordpress-docker-image>  any official wordpress:*-apache image (picks the PHP version)
# - [wp-core-dir]             optional WordPress release to install instead of the image's own
#                             (pass "" to keep the image's version)
# - [extra-plugin-dir]        other built plugins to activate alongside (e.g. Health Check)
#
# Needs: docker, curl, php (host) and WPCLI_PHAR pointing to a wp-cli.phar.
# SMOKE_KEEP=1 keeps the site running afterwards (skips uninstall) for manual checks.
# Checks: activation, CLI audit, planted exposures detected, admin screens render,
# every AJAX check succeeds, settings save schedules cron, no PHP notices/warnings
# from this plugin in the debug log, uninstall leaves nothing behind.

set -euo pipefail

IMAGE="${1:?image}"
BUILD="$(cd "${2:?built plugin dir}" && pwd)"
CORE="${3:-}"
shift 3 2>/dev/null || shift $#
EXTRA=("$@")
WPCLI_PHAR="${WPCLI_PHAR:-$(dirname "$0")/wp-cli.phar}"

NAME="iwiesa-smoke-$$"
NET="${NAME}-net"
DB="${NAME}-db"
WP="${NAME}-wp"
WORK="$(mktemp -d)"
FAILS=0

pass() { echo "  PASS  $*"; }
fail() { echo "  FAIL  $*"; FAILS=$((FAILS + 1)); }

cleanup() {
	if [ "${SMOKE_KEEP:-}" = "1" ]; then
		echo "   Kept containers: $WP (IP ${IP:-?}), $DB. Remove with: docker rm -f $WP $DB; docker network rm $NET"
		return
	fi
	docker rm -f "$WP" "$DB" >/dev/null 2>&1 || true
	docker network rm "$NET" >/dev/null 2>&1 || true
	rm -rf "$WORK"
}
trap cleanup EXIT

wp() { docker exec -u www-data -w /var/www/html "$WP" php -d memory_limit=512M /usr/local/bin/wp "$@"; }

echo "== $IMAGE ${CORE:+(WordPress from $CORE)}"

docker network create "$NET" >/dev/null
docker run -d --name "$DB" --network "$NET" \
	-e MARIADB_ROOT_PASSWORD=root -e MARIADB_DATABASE=wp mariadb:10.11 >/dev/null

docker create --name "$WP" --network "$NET" \
	-e WORDPRESS_DB_HOST="$DB" -e WORDPRESS_DB_USER=root -e WORDPRESS_DB_PASSWORD=root -e WORDPRESS_DB_NAME=wp \
	-e WORDPRESS_DEBUG=1 \
	-e WORDPRESS_CONFIG_EXTRA="define( 'WP_DEBUG_LOG', '/tmp/wp-debug.log' ); define( 'WP_DEBUG_DISPLAY', false ); define( 'WP_ENVIRONMENT_TYPE', 'production' );" \
	"$IMAGE" >/dev/null
if [ -n "$CORE" ]; then
	docker cp "$CORE/." "$WP:/var/www/html/"
fi
docker start "$WP" >/dev/null
docker cp "$WPCLI_PHAR" "$WP:/usr/local/bin/wp"

# Wait for the entrypoint to write wp-config.php and for the database.
for _ in $(seq 1 60); do
	if docker exec "$WP" test -f /var/www/html/wp-config.php && wp db check >/dev/null 2>&1; then
		break
	fi
	sleep 2
done
docker exec "$WP" chown -R www-data:www-data /var/www/html

PHPV="$(docker exec "$WP" php -r 'echo PHP_VERSION;')"
wp core install --url=http://localhost --title=Smoke --admin_user=smokeadmin --admin_password=smoke-pass-123 \
	--admin_email=smoke@example.com --skip-email >/dev/null
WPV="$(wp core version)"
echo "   WordPress $WPV, PHP $PHPV"

docker cp "$BUILD" "$WP:/var/www/html/wp-content/plugins/iworksie-security-audit"
for extra in "${EXTRA[@]}"; do
	docker cp "$extra" "$WP:/var/www/html/wp-content/plugins/$(basename "$extra")"
done
docker exec "$WP" chown -R www-data:www-data /var/www/html/wp-content/plugins

if wp plugin activate iworksie-security-audit >/dev/null; then pass "activates"; else fail "activate"; fi
for extra in "${EXTRA[@]}"; do
	if wp plugin activate "$(basename "$extra")" >/dev/null; then pass "activates alongside $(basename "$extra")"; else fail "activate $(basename "$extra")"; fi
done

# --- Plant things the audit must find (all inside this throwaway container).
docker exec -u www-data "$WP" sh -c '
	cd /var/www/html &&
	cp wp-config.php wp-config.php.bak &&
	mkdir -p .git && printf "ref: refs/heads/main\n" > .git/HEAD &&
	printf -- "-- MySQL dump 10.13\nCREATE TABLE wp_posts (id int);\n" > backup.sql &&
	printf "[01-Jan-2026 10:00:00 UTC] PHP Warning: test\n" > wp-content/debug.log'

# --- CLI audit.
if wp iworksie-security audit --format=json > "$WORK/audit.json" 2>"$WORK/audit.err"; then
	pass "wp iworksie-security audit"
else
	fail "wp iworksie-security audit: $(cat "$WORK/audit.err")"
fi
php -r '
	$rows = json_decode( file_get_contents( $argv[1] ), true );
	if ( ! is_array( $rows ) ) { echo "  FAIL  audit JSON did not parse\n"; exit( 1 ); }
	$by = array(); foreach ( $rows as $r ) { $by[ $r["id"] ] = $r["status"]; }
	$fails = 0;
	echo ( 22 === count( $rows ) ? "  PASS  22 checks ran\n" : "  FAIL  expected 22 checks, got " . count( $rows ) . "\n" ); if ( 22 !== count( $rows ) ) { $fails++; }
	foreach ( array( "secret_files", "backup_files", "version_control", "log_files" ) as $id ) {
		$s = isset( $by[ $id ] ) ? $by[ $id ] : "missing";
		if ( "critical" === $s ) { echo "  PASS  planted file found: $id\n"; } else { echo "  FAIL  $id expected critical, got $s\n"; $fails++; }
	}
	foreach ( $by as $id => $s ) { echo "        $id: $s\n"; }
	exit( $fails ? 1 : 0 );
' "$WORK/audit.json" || FAILS=$((FAILS + 1))

# --- Admin screens and AJAX as a logged-in administrator.
IP="$(docker inspect -f "{{(index .NetworkSettings.Networks \"$NET\").IPAddress}}" "$WP")"
C=(curl -sS --resolve "localhost:80:$IP" -b "$WORK/jar" -c "$WORK/jar")
"${C[@]}" -o /dev/null http://localhost/wp-login.php
"${C[@]}" -o /dev/null -d "log=smokeadmin&pwd=smoke-pass-123&testcookie=1&redirect_to=http%3A%2F%2Flocalhost%2Fwp-admin%2F" http://localhost/wp-login.php

page() {
	local url="$1" out="$2" expect="$3" code
	code="$("${C[@]}" -o "$out" -w '%{http_code}' "$url")"
	if [ "$code" = "200" ] && grep -q "$expect" "$out" && ! grep -qiE 'Fatal error|Warning: |Notice: |Deprecated: ' "$out"; then
		pass "renders $url"
	else
		fail "$url (HTTP $code, expected text: $expect)"
	fi
}
page "http://localhost/wp-admin/admin.php?page=iworksie-security-audit" "$WORK/audit.html" "Run audit again"
page "http://localhost/wp-admin/admin.php?page=iworksie-security-audit&tab=report" "$WORK/report.html" "Security Audit report"
page "http://localhost/wp-admin/admin.php?page=iworksie-security-audit&tab=settings" "$WORK/settings.html" "Weekly audit email"
page "http://localhost/wp-admin/admin.php?page=iworks-tools" "$WORK/overview.html" "Security Audit"

NONCE="$(grep -o '"checksNonce":"[a-z0-9]*"' "$WORK/audit.html" | head -1 | cut -d'"' -f4)"
IDS="$(php -r 'if ( preg_match( "/var iwtCore = (\{.*?\});/s", file_get_contents( $argv[1] ), $m ) ) { $j = json_decode( $m[1], true ); foreach ( $j["checks"] as $c ) { echo $c["id"], "\n"; } }' "$WORK/audit.html")"
if [ -z "$NONCE" ] || [ -z "$IDS" ]; then
	fail "could not read checks/nonce from the page"
else
	AJAX_FAILS=0
	for id in $IDS; do
		body="$("${C[@]}" -d "action=iwiesa_run_check&nonce=$NONCE&check_id=$id" http://localhost/wp-admin/admin-ajax.php)"
		if ! echo "$body" | grep -q '"success":true'; then
			AJAX_FAILS=$((AJAX_FAILS + 1))
			echo "        AJAX $id: $body"
		fi
	done
	if [ "$AJAX_FAILS" = "0" ]; then pass "every check runs over AJAX ($(echo "$IDS" | wc -l) checks)"; else fail "$AJAX_FAILS AJAX checks failed"; fi
	if "${C[@]}" -d "action=iwiesa_finish_audit&nonce=$NONCE" http://localhost/wp-admin/admin-ajax.php | grep -q '"success":true'; then pass "finish audit"; else fail "finish audit"; fi
	if "${C[@]}" -d "action=iwiesa_run_check&nonce=bad&check_id=https" http://localhost/wp-admin/admin-ajax.php | grep -q '"success":true'; then fail "bad nonce accepted"; else pass "bad nonce rejected"; fi
fi

SNONCE="$(grep -o 'name="_wpnonce" value="[a-z0-9]*"' "$WORK/settings.html" | head -1 | cut -d'"' -f4)"
"${C[@]}" -o /dev/null -d "action=iwiesa_save_settings&_wpnonce=$SNONCE&_wp_http_referer=%2Fwp-admin%2F&iwiesa_weekly_email=1&iwiesa_only_issues=1&iwiesa_email=ops%40example.com" http://localhost/wp-admin/admin-post.php
if wp cron event list --fields=hook --format=csv | grep -q iwiesa_weekly_audit; then pass "weekly email schedules cron"; else fail "weekly cron not scheduled"; fi
if [ "$(wp option get iwiesa_settings --format=json | php -r '$s=json_decode(stream_get_contents(STDIN),true); echo $s["email"];')" = "ops@example.com" ]; then pass "settings saved"; else fail "settings not saved"; fi

# Run the weekly job once (mail just goes to the container's sendmail stub).
if wp cron event run iwiesa_weekly_audit >/dev/null 2>&1; then pass "weekly job runs"; else fail "weekly job"; fi

# --- PHP notices from our code?
docker exec "$WP" sh -c 'cat /tmp/wp-debug.log 2>/dev/null || true' > "$WORK/debug.log"
if grep -E 'iworksie-security-audit|iwiesa' "$WORK/debug.log" > "$WORK/ours.log"; then
	fail "PHP notices from this plugin:"
	head -20 "$WORK/ours.log"
else
	pass "no PHP notices, warnings or deprecations from this plugin"
fi

if [ "${SMOKE_KEEP:-}" = "1" ]; then
	echo "   SMOKE_KEEP=1: skipping uninstall so the site can be inspected."
	exit "$FAILS"
fi

# --- Uninstall leaves nothing.
wp plugin deactivate iworksie-security-audit >/dev/null
if wp cron event list --fields=hook --format=csv | grep -q iwiesa_weekly_audit; then fail "cron left after deactivate"; else pass "deactivate clears cron"; fi
wp plugin uninstall iworksie-security-audit >/dev/null
LEFT="$(wp option list --search='iwiesa*' --format=count) $(wp option list --search='_transient_iwiesa*' --format=count)"
if [ "$LEFT" = "0 0" ]; then pass "uninstall removes all options"; else fail "options left after uninstall: $LEFT"; fi

echo "   Result: $FAILS failure(s)"
exit "$FAILS"

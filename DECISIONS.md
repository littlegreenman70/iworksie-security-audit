# Decisions

| Date (Europe/Dublin) | Decision | Reason |
|----------------------|----------|--------|
| 2026-11-26 | Prefix `iwiesa` / `IWIESA`, namespace `IWorksIE\SecurityAudit`, Strauss prefix `IWorksIE\SecurityAudit\Vendor\` | Build plan §3 (per-plugin short prefix "sa"). |
| 2026-11-26 | Plugin code targets PHP 7.4 syntax from the start; PHPCompatibilityWP `7.4-` in PHPCS; smoke-tested on real PHP 7.4, 8.1, 8.2, 8.3, 8.4 | Cormac: base the code on an earlier PHP version and test it. |
| 2026-11-26 | Exposure checks only probe files that exist on disk, then require a content signature | Guessing URLs causes false positives (soft 404s) and noise; competitors' false positives are a top complaint. |
| 2026-11-26 | Files in backup-plugin folders (updraft, ai1wm-backups, …) are reported only when actually downloadable | Those folders are protected on purpose; flagging them as "blocked" would nag every backup-plugin user. |
| 2026-11-26 | Probes: no cookies, no redirects, first 8 KB only (`Range` + `limit_response_size`), 6 s timeout, max 15 probes / 15 s per check | Proves exposure like a visitor, stays inside a 30 s PHP limit on shared hosts. |
| 2026-11-26 | Plugin boots only in wp-admin, AJAX, cron and WP-CLI | "Zero background load" positioning: nothing on the front end. |
| 2026-11-26 | No Site Health bridge | Several checks make HTTP requests, which would run every time Site Health loads; also core's bridge uses one shared `iworks-tools` debug-info key, so a second plugin would overwrite Health Check's section. |
| 2026-11-26 | Weekly email is off by default; "only when something needs attention" is on by default | Competitors are criticised for alert floods. |
| 2026-11-26 | WordPress.org lookups only for plugins listed in `update_plugins` with a `w.org/` id; cached 3 days; disclosed under "External services" in readme | Premium/custom plugins would return false "not found"; wordpress.org guidelines require disclosure. |
| 2026-11-26 | Closed plugin with reason `security-issue` = Critical; other closures and 2-year-stale plugins = Recommended | Severity should match risk. |
| 2026-11-26 | Core update on the same branch (6.8.1 → 6.8.3) = Critical; only a newer major available = Recommended | Same-branch releases are security fixes; majors are optional for a while. |
| 2026-11-26 | Five or more pending plugin/theme updates = Critical, otherwise Recommended | Outdated plugins are the most common way in. |
| 2026-11-26 | `display_errors` is read from `ini_get_all()` global value | WordPress forces display_errors off during AJAX, where checks run, so `ini_get()` always said "off". |
| 2026-11-26 | Local/development environment type downgrades debug display and HTTPS findings to Info | Cormac's www.iworks.new would otherwise be all red for expected dev settings. |
| 2026-11-26 | Inactive themes: allow one spare default "Twenty*" theme | WordPress recommends keeping a fallback theme. |
| 2026-11-26 | Login protection is detected by plugin folder list (filterable: `iwiesa_login_protection_plugins`) | No reliable API to detect 2FA; host-level protection can't be seen, and the result says so. |
| 2026-11-26 | Banner/icon/screenshots not included yet | Same as Health Check: artwork pending; real screenshots to be taken from www.iworks.new before submission. |

| 2026-11-27 | Smoke harness sets `AUTOMATIC_UPDATER_DISABLED` and `WP_AUTO_UPDATE_CORE` false, clears `.maintenance` / `auto_updater.lock` | WP 6.5.15 smoke was returning HTTP 503 on admin tabs after the first page while core tried to auto-update. |
| 2026-11-27 | `bin/install-wp-tests.sh` resolves X.Y to latest X.Y.Z + matching tags/ suite | Same tag-matching fix as the other plugins; keeps future pin jobs safe. |

### 2026-11-28 plurals / final pass
- Plural sweep: no new count-plus-noun strings needed. Included in suite collision + all-together live check.


=== iWorks.ie Security Audit ===
Contributors: littlegreenman
Tags: security, audit, hardening, backup, vulnerability
Requires at least: 6.5
Tested up to: 7.1
Requires PHP: 7.4
Stable tag: 1.0.0
License: GPLv2 or later
License URI: https://www.gnu.org/licenses/gpl-2.0.html

A read-only security audit. Finds exposed backups and config files, risky settings and abandoned plugins, and explains each fix in plain English.

== Description ==

iWorks.ie Security Audit is **an audit, not a firewall**. It does nothing until you click "Run audit", so it adds no load to your site and sits happily alongside Wordfence, Solid Security or any other security plugin.

**It proves what it finds.** For files such as `wp-config.php.bak`, `.env`, `backup.zip` or a `.git` folder, the audit requests each one the way a logged-out visitor would and only marks it Critical when the real file comes back, so you are not chasing false alarms.

**Read-only.** It never changes your site's settings, content or files. The only things it saves are its own results and its own settings, which are removed when you delete the plugin.

= What it checks =

Exposed files (proved with a real request)

* Copies of wp-config.php, `.env`, `.htpasswd` and phpinfo pages
* Backups and database dumps in the website folders
* `.git` and `.svn` folders
* `debug.log` and other log files
* Folder listings switched on

Settings

* Error messages shown to visitors, and the debug log in a public place
* Plugin and theme code editor switched on
* Security keys and salts missing, weak or left as the sample text
* HTTPS
* Open registration with a powerful default role
* Automatic security releases switched off

Logins

* Administrator usernames that are easy to guess
* Usernames visible to logged-out visitors
* XML-RPC open to password guessing
* No two-factor login or login-limit plugin

Software and server

* WordPress, plugin and theme updates waiting
* Plugins closed on WordPress.org or not updated in two years
* Inactive plugins and themes still installed
* PHP version past end of life
* World-writable files and folders
* Missing security headers

Every finding uses the same Good / Recommended / Critical language as WordPress Site Health and comes with "Why it matters" and "How to fix" in plain English. Copy or download a report to send to your developer or host.

Optional: switch on a weekly audit with one short summary email (off by default).

Also available from the command line: `wp iworksie-security audit`.

Need a hand fixing what it finds, or a custom plugin? iWorks builds them: https://www.iworks.ie

= External services =

This plugin makes outgoing requests only while an audit runs (when you click "Run audit", run the WP-CLI command, or when the weekly audit you switched on runs):

* **Your own site.** It requests a few of your own site's addresses (for example a file name it found in your website folder, `/wp-json/wp/v2/users`, `/xmlrpc.php` and your home page) without logging in, to see what a visitor would see. These requests go only to your own site.
* **WordPress.org plugin directory API** (`https://api.wordpress.org/plugins/info/1.2/`). For each installed plugin that comes from WordPress.org, it sends the plugin's slug (its folder name) to find out whether the plugin has been closed or not updated in two years. No other data is sent. Results are cached for three days. WordPress.org privacy policy: https://wordpress.org/about/privacy/

It collects no analytics and sends nothing to iWorks.

== Installation ==

1. Install from Plugins > Add New, or upload the `iworksie-security-audit` folder to `/wp-content/plugins/`.
2. Activate the plugin.
3. Open **iWorks Tools > Security Audit** and click **Run audit**.

== Frequently Asked Questions ==

= Can it break my site? =

No. It only reads settings and files and makes ordinary requests to your own site. It never changes settings, deletes files or blocks anyone.

= Does it replace Wordfence or another security plugin? =

No, and it does not try to. Firewalls block attacks as they happen; this audit finds the weak spots that make attacks succeed. Use both.

= Will it slow my site down? =

No. Nothing runs on the front end and nothing runs in the background unless you switch on the weekly email.

= Why is something "blocked" but still Recommended? =

The file is on your server but your server refused to send it when we asked. That is safe today, but moving host or losing a server rule could expose it, so it is better to move it out of the website folder.

= What do I do about a Critical finding? =

Each finding explains how to fix it. If you would rather someone did it for you, send the report (Report tab) to your developer or host, or to iWorks.

= Does it work on multisite? =

Yes. On multisite only super admins can run the audit.

== Screenshots ==

1. Audit results with score, grouped by Critical, Recommended and Good.
2. A Critical finding: a downloadable backup, with why it matters and how to fix it.
3. Report ready to copy or download for your developer.
4. Settings: optional weekly audit email.

== Changelog ==

= 1.0.0 =
* First release: 22 read-only checks, report, optional weekly email, WP-CLI command.

== Upgrade Notice ==

= 1.0.0 =
First release.

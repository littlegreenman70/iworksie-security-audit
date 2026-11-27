/**
 * iWorks.ie Security Audit: run every check one request at a time.
 */
(function () {
	'use strict';

	function post(action, data) {
		var body = new window.FormData();
		body.append('action', action);
		Object.keys(data || {}).forEach(function (key) {
			body.append(key, data[key]);
		});
		var url =
			(window.iwiesaAdmin && window.iwiesaAdmin.ajaxUrl) ||
			(window.iwtCore && window.iwtCore.ajaxUrl) ||
			'';
		return window
			.fetch(url, {
				method: 'POST',
				credentials: 'same-origin',
				body: body
			})
			.then(function (res) {
				return res.json();
			});
	}

	function escapeHtml(str) {
		return String(str)
			.replace(/&/g, '&amp;')
			.replace(/</g, '&lt;')
			.replace(/>/g, '&gt;')
			.replace(/"/g, '&quot;')
			.replace(/'/g, '&#039;');
	}

	function strings() {
		return (window.iwiesaAdmin && window.iwiesaAdmin.strings) || {};
	}

	function setButtons(buttons, html, disabled) {
		buttons.forEach(function (btn) {
			btn.disabled = disabled;
			btn.innerHTML = html;
		});
	}

	function runAudit() {
		var cfg = window.iwtCore;
		if (!cfg || !cfg.checks || !cfg.checks.length) {
			return;
		}
		var list = document.querySelector('[data-iwt-results]');
		if (!list) {
			return;
		}
		var buttons = Array.prototype.slice.call(document.querySelectorAll('[data-iwiesa-run-audit]'));
		var labels = buttons.map(function (btn) {
			return btn.getAttribute('data-label') || btn.textContent;
		});
		var empty = document.querySelector('[data-iwt-empty]');
		var summaryWrap = document.querySelector('[data-iwt-summary-wrap]');
		var ui = window.iwtCoreUi || {};
		var s = strings();
		var total = cfg.checks.length;
		var collected = [];
		var chain = Promise.resolve();

		if (empty) {
			empty.hidden = true;
		}
		if (summaryWrap) {
			summaryWrap.hidden = false;
		}
		list.innerHTML = '';
		list.setAttribute('aria-busy', 'true');

		cfg.checks.forEach(function (check, index) {
			chain = chain.then(function () {
				var label = (s.progress || 'Checking {current} of {total}…')
					.replace('{current}', String(index + 1))
					.replace('{total}', String(total));
				setButtons(buttons, '<span class="spinner is-active" aria-hidden="true"></span> ' + escapeHtml(label), true);
				return post(cfg.prefix + '_run_check', { nonce: cfg.checksNonce, check_id: check.id })
					.then(function (json) {
						return json && json.success
							? json.data
							: { status: 'info', label: check.label, description: s.failed || 'This check could not run.' };
					})
					.catch(function () {
						return { status: 'info', label: check.label, description: s.failed || 'This check could not run.' };
					})
					.then(function (result) {
						result.id = check.id;
						collected.push(result);
						if (ui.renderGrouped) {
							list.innerHTML = ui.renderGrouped(collected);
							if (ui.bindAccordions) {
								ui.bindAccordions(list);
							}
							if (ui.updateSummary) {
								ui.updateSummary(list);
							}
						}
					});
			});
		});

		chain.then(function () {
			list.removeAttribute('aria-busy');
			buttons.forEach(function (btn, i) {
				btn.disabled = false;
				btn.textContent = labels[i];
			});
			return post('iwiesa_finish_audit', { nonce: cfg.checksNonce }).then(function (json) {
				var el = document.querySelector('.iwiesa-last-checked');
				if (el && json && json.success && json.data && json.data.last_checked) {
					el.textContent = json.data.last_checked;
				}
			});
		});
	}

	document.addEventListener('DOMContentLoaded', function () {
		document.querySelectorAll('[data-iwiesa-run-audit]').forEach(function (btn) {
			btn.setAttribute('data-label', btn.textContent);
			btn.addEventListener('click', runAudit);
		});
	});
})();

// Eraser web UI behavior, loaded from <head> on every page.
//
// The CSP only allows scripts from /static (script-src 'self'), so pages
// have no inline script blocks or on* handlers. Elements declare what a
// click does with data-action (and data-target / data-filter); one delegated
// listener below runs it, including for content htmx swaps in later.
(function () {
    'use strict';

    const byId = (id) => document.getElementById(id);

    // ---- Theme. Applied immediately, before the body renders, to avoid a
    // flash of the wrong theme.

    const sunIcon = '<svg fill="none" viewBox="0 0 24 24" stroke="currentColor"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 3v1m0 16v1m9-9h-1M4 12H3m15.364 6.364l-.707-.707M6.343 6.343l-.707-.707m12.728 0l-.707.707M6.343 17.657l-.707.707M16 12a4 4 0 11-8 0 4 4 0 018 0z"/></svg>';
    const moonIcon = '<svg fill="none" viewBox="0 0 24 24" stroke="currentColor"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M20.354 15.354A9 9 0 018.646 3.646 9.003 9.003 0 0012 21a9.003 9.003 0 008.354-5.646z"/></svg>';

    function getTheme() {
        const stored = localStorage.getItem('eraser-theme');
        if (stored) return stored;
        return window.matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light';
    }

    function setTheme(theme) {
        document.documentElement.classList.toggle('light', theme === 'light');
        localStorage.setItem('eraser-theme', theme);
        const toggle = byId('theme-toggle');
        if (toggle) toggle.innerHTML = theme === 'light' ? moonIcon : sunIcon;
    }

    setTheme(getTheme());

    // ---- Brokers page: "Send to All" job.

    let currentJobId = null;
    let pollInterval = null;

    async function checkForActiveJob() {
        try {
            const resp = await fetch('/api/job/active');
            const data = await resp.json();
            if (data.job && data.job.status === 'running') {
                currentJobId = data.job.id;
                showProgressUI();
                updateProgressDisplay(data.job);
                startPolling();
            }
        } catch (err) {
            console.error('Error checking for active job:', err);
        }
    }

    async function startSendAll() {
        const btn = byId('send-all-btn');
        const btnText = byId('send-all-text');
        const spinner = byId('send-all-spinner');

        btn.disabled = true;
        btnText.textContent = 'Starting...';
        spinner.classList.remove('hidden');

        const search = byId('broker-search').value;
        const category = document.querySelector('[name="category"]').value;
        const region = document.querySelector('[name="region"]').value;

        try {
            const resp = await fetch('/api/send-all', {
                method: 'POST',
                headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
                body: new URLSearchParams({ search, category, region }),
            });
            const data = await resp.json();
            if (!resp.ok) {
                showError(data.error || 'Failed to start sending');
                resetButton();
                return;
            }
            currentJobId = data.job_id;
            showProgressUI();
            startPolling();
        } catch (err) {
            showError('Network error: ' + err.message);
            resetButton();
        }
    }

    function showProgressUI() {
        byId('send-all-progress').innerHTML = `
            <div class="card p-4">
                <div class="flex items-center justify-between mb-2">
                    <span class="font-medium text-primary">Sending emails...</span>
                    <button data-action="cancel-job" class="btn btn-ghost text-sm py-1 px-3 text-red-600 hover:bg-red-50">
                        Cancel
                    </button>
                </div>
                <div id="current-broker" class="text-sm text-secondary mb-2"></div>
                <div class="w-full bg-gray-200 rounded-full h-2 mb-2">
                    <div id="progress-bar" class="bg-indigo-600 h-2 rounded-full transition-all" style="width: 0%"></div>
                </div>
                <div id="progress-text" class="text-xs text-muted">0 of 0 complete (0 sent, 0 failed)</div>
            </div>
        `;
    }

    function updateProgressDisplay(job) {
        const currentBroker = byId('current-broker');
        const progressBar = byId('progress-bar');
        const progressText = byId('progress-text');
        if (currentBroker) {
            currentBroker.textContent = job.current_broker ? `Sending to: ${job.current_broker}` : '';
        }
        if (progressBar) {
            progressBar.style.width = job.progress + '%';
        }
        if (progressText) {
            const processed = job.sent + job.failed;
            progressText.textContent = `${processed} of ${job.total} complete (${job.sent} sent, ${job.failed} failed)`;
        }
    }

    function startPolling() {
        pollInterval = setInterval(pollJobStatus, 1500);
        pollJobStatus();
    }

    async function pollJobStatus() {
        if (!currentJobId) return;
        try {
            const resp = await fetch(`/api/job/${currentJobId}/status`);
            const job = await resp.json();
            updateProgressDisplay(job);
            if (job.status === 'completed' || job.status === 'cancelled') {
                stopPolling();
                showCompletionMessage(job);
                resetButton();
                // Refresh the broker list to show updated statuses.
                htmx.ajax('GET', '/api/brokers', { target: '#broker-list', swap: 'innerHTML' });
            }
        } catch (err) {
            console.error('Error polling job status:', err);
        }
    }

    function stopPolling() {
        if (pollInterval) {
            clearInterval(pollInterval);
            pollInterval = null;
        }
    }

    // Job fields used below are numbers from our own API.
    function showCompletionMessage(job) {
        const progressArea = byId('send-all-progress');
        const remaining = job.total - job.sent - job.failed;

        if (job.error_type === 'auth') {
            progressArea.innerHTML = `
                <div class="bg-red-50 border border-red-200 rounded-lg p-4">
                    <div class="flex items-start gap-3">
                        <svg class="w-6 h-6 text-red-500 flex-shrink-0 mt-0.5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z"/>
                        </svg>
                        <div>
                            <h3 class="font-semibold text-red-800">Email Authentication Failed</h3>
                            <p class="text-red-700 text-sm mt-1">Sent ${job.sent} emails before stopping. Your email provider blocked further sends.</p>
                            <div class="mt-3 p-3 bg-white rounded border border-red-100">
                                <p class="font-medium text-gray-800 mb-2">What to do:</p>
                                <ol class="text-sm text-gray-700 space-y-1 list-decimal list-inside">
                                    <li>Check your email account for security alerts</li>
                                    <li>If using Gmail, <a href="https://myaccount.google.com/apppasswords" target="_blank" rel="noopener noreferrer" class="text-blue-600 underline">generate a new app password</a></li>
                                    <li>Wait 24 hours before trying again (rate limits reset daily)</li>
                                </ol>
                            </div>
                            <p class="text-sm text-gray-600 mt-3">
                                <strong>${remaining} brokers remaining.</strong>
                                Filter by "Pending" status to send to them later.
                            </p>
                        </div>
                    </div>
                </div>
            `;
            return;
        }

        if (job.status === 'paused') {
            progressArea.innerHTML = `
                <div class="bg-blue-50 border border-blue-200 rounded-lg p-4">
                    <div class="flex items-start gap-3">
                        <svg class="w-6 h-6 text-blue-500 flex-shrink-0 mt-0.5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 8v4l3 3m6-3a9 9 0 11-18 0 9 9 0 0118 0z"/>
                        </svg>
                        <div>
                            <h3 class="font-semibold text-blue-800">Daily Limit Reached</h3>
                            <p class="text-blue-700 text-sm mt-1">Sent ${job.sent} emails in this run; the 24-hour limit has been reached.</p>
                            <p class="text-sm text-gray-600 mt-2">${remaining} brokers remaining; send them once the 24-hour limit has room again.</p>
                        </div>
                    </div>
                </div>
            `;
            return;
        }

        const cancelled = job.status === 'cancelled';
        progressArea.innerHTML = `
            <div class="${cancelled ? 'bg-yellow-100 text-yellow-800' : 'bg-green-100 text-green-800'} px-4 py-3 rounded">
                <strong>${cancelled ? 'Cancelled' : 'Complete'}!</strong> Sent ${job.sent} emails (${job.failed} failed).
                <a href="/brokers" class="underline ml-2">Refresh page</a>
            </div>
        `;
    }

    async function cancelJob() {
        if (!currentJobId) return;
        try {
            await fetch(`/api/job/${currentJobId}/cancel`, { method: 'POST' });
        } catch (err) {
            console.error('Error cancelling job:', err);
        }
    }

    function showError(message) {
        const progressArea = byId('send-all-progress');
        progressArea.innerHTML = `
            <div class="bg-red-100 text-red-800 px-4 py-3 rounded">
                <strong>Error:</strong> <span class="error-text"></span>
            </div>
        `;
        // textContent, not innerHTML: messages can include config values.
        progressArea.querySelector('.error-text').textContent = message;
    }

    function resetButton() {
        byId('send-all-btn').disabled = false;
        byId('send-all-text').textContent = 'Send to All';
        byId('send-all-spinner').classList.add('hidden');
        currentJobId = null;
    }

    // ---- History page: "Clear Failed".

    async function clearFailedRecords(btn) {
        if (!confirm('Delete all failed records? This cannot be undone.')) return;

        const label = btn.innerHTML;
        btn.disabled = true;
        btn.innerHTML = '<span class="animate-spin">⏳</span> Clearing...';

        // Messages are set as text: they come from the server.
        const result = byId('clear-result');
        const box = document.createElement('div');
        try {
            const resp = await fetch('/api/history/failed', { method: 'DELETE' });
            const data = await resp.json();
            if (!resp.ok) throw new Error(data.error || 'Failed to clear records');
            box.className = 'bg-green-100 text-green-800 px-4 py-3 rounded';
            box.textContent = data.message + '. ';
            const link = document.createElement('a');
            link.href = '/history';
            link.className = 'underline';
            link.textContent = 'Refresh page';
            box.append(link);
        } catch (err) {
            box.className = 'bg-red-100 text-red-800 px-4 py-3 rounded';
            box.textContent = 'Error: ' + err.message;
        }
        result.replaceChildren(box);

        btn.disabled = false;
        btn.innerHTML = label;
    }

    // ---- Filters on the tasks and pipeline pages.

    function filterItems(type) {
        document.querySelectorAll('.filter-btn').forEach((btn) => {
            btn.classList.toggle('active', btn.dataset.filter === type);
        });
        document.querySelectorAll('.action-item').forEach((item) => {
            const completed = item.dataset.status === 'completed';
            let show;
            if (type === 'all') {
                show = !completed; // all pending items
            } else if (type === 'completed') {
                show = completed;
            } else {
                show = item.dataset.type === type && !completed; // "form" excludes CAPTCHAs
            }
            item.classList.toggle('hidden', !show);
        });
    }

    function filterResponses(type) {
        const dropdown = byId('response-filter');
        if (dropdown) {
            dropdown.value = type;
            htmx.trigger(dropdown, 'change'); // reloads the list via htmx
        }
        byId('response-list').scrollIntoView({ behavior: 'smooth' });
    }

    // ---- Task helper page: click a field to copy its value.

    async function copyField(field) {
        try {
            await navigator.clipboard.writeText(field.dataset.value);
            field.classList.remove('bg-gray-50');
            field.classList.add('bg-green-100');
            setTimeout(() => {
                field.classList.remove('bg-green-100');
                field.classList.add('bg-gray-50');
            }, 500);
        } catch (err) {
            console.error('Failed to copy:', err);
        }
    }

    // ---- Wiring.

    const actions = {
        'toggle-theme': () => setTheme(getTheme() === 'dark' ? 'light' : 'dark'),
        'toggle': (el) => byId(el.dataset.target).classList.toggle('hidden'),
        'hide': (el) => byId(el.dataset.target).classList.add('hidden'),
        'send-all': () => startSendAll(),
        'cancel-job': () => cancelJob(),
        'clear-failed': (el) => clearFailedRecords(el),
        'filter-items': (el) => filterItems(el.dataset.filter),
        'filter-responses': (el) => filterResponses(el.dataset.filter),
        'copy': (el) => copyField(el),
    };

    document.addEventListener('click', (e) => {
        const el = e.target.closest('[data-action]');
        const action = el && actions[el.dataset.action];
        if (action) action(el, e);
    });

    document.addEventListener('DOMContentLoaded', () => {
        setTheme(getTheme()); // the toggle button exists now
        if (byId('send-all-btn')) checkForActiveJob();
    });
})();

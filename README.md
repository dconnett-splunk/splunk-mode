# splunk-mode

Run Splunk searches from Emacs with `auth-source`-backed authentication, a Magit-style overview buffer, and async result views.

The active implementation in this repository is [`splunk-mode.el`](./splunk-mode.el). Older `pepita` files are still present for history, but they are not the current interface.

## Features

- Multiple Splunk backends loaded from `auth-source`
- Interactive overview buffer and transient dispatcher
- Async search job submission and polling
- Table, raw, JSON, and CSV result views
- Result drill-down from the current table cell or detail field
- Search history and "edit current search" flow
- Configurable request timeout and SSL verification toggle

## Requirements

- A recent Emacs
- `magit`
- `transient`
- `request`
- `soap-client`
- Access to the Splunk management API, usually on port `8089`

`auth-source`, `json`, and the URL libraries are built into Emacs.

## Installation

This repository is easiest to use as a local checkout while iterating on the package.

### Doom Emacs

Enable Doom's `:tools magit` module, or make sure `magit` is installed some other way.

Add the non-builtin dependencies in `~/.doom.d/packages.el`:

```elisp
(package! request)
(package! soap-client)
```

Add the package itself in `~/.doom.d/config.el`:

```elisp
(add-to-list 'load-path "/path/to/splunk-mode")

(use-package! splunk-mode
  :commands (splunk-overview splunk-dispatch splunk-search-dispatch)
  :init
  (map! :leader
        :desc "Splunk overview" "o s" #'splunk-overview
        :desc "Splunk dispatch" "o S" #'splunk-dispatch)
  :config
  (setq splunk-auth-source-service "splunk"
        splunk-request-timeout 30))

(defun +splunk/reload ()
  (interactive)
  (when (featurep 'splunk-mode)
    (unload-feature 'splunk-mode t))
  (load-file "/path/to/splunk-mode/splunk-mode.el"))
```

Then run:

```bash
doom sync
```

After the first sync, normal code changes only need:

```text
M-x +splunk/reload
```

### Vanilla Emacs

Install `magit`, `transient`, `request`, and `soap-client` with your preferred package manager, then load the local checkout:

```elisp
(add-to-list 'load-path "/path/to/splunk-mode")
(require 'splunk-mode)

(setq splunk-auth-source-service "splunk"
      splunk-request-timeout 30)
```

To reload during development:

```text
M-x load-file RET /path/to/splunk-mode/splunk-mode.el
```

## auth-source Setup

The package expects credentials in `~/.authinfo.gpg`, `~/.authinfo`, or another configured `auth-source` backend.

Example `~/.authinfo.gpg` entries:

```text
machine splunk-prod.example.com login alice port 8089 password YOUR_SECRET service splunk
machine splunk-dev.example.com login alice port 8089 password YOUR_SECRET service splunk
machine splunk-lab.example.com login bob port 8090 password YOUR_SECRET service splunk
```

Notes:

- `machine` should be just the hostname. Do not include `https://` or `host:port`.
- `service splunk` is recommended when you have multiple entries or non-default ports.
- `splunk-hosts-sync-from-auth-source` imports `(host port username)` entries from `auth-source`.
- If only one backend is available, search/login can auto-select it. If there are several, you will be prompted to choose.

## First-Time Workflow

1. Open `M-x splunk-overview` or `M-x splunk-dispatch`.
2. Import or add servers.
3. Log in.
4. Run a search.

From `splunk-overview`, the built-in menu is:

- `1` Search
- `2` Recent searches
- `3` Switch server
- `4` Add server
- `5` Import servers from `auth-source`
- `6` Login

`splunk-dispatch` provides the same flow in a transient menu:

- Search: `S` for the search transient, `o` for overview
- Inspect: `r` running requests, `h` history
- Servers: add, import, switch, edit, remove, save current
- Auth/Server: change host, login, toggle SSL verification

## Search Defaults

The search transient `M-x splunk-search-dispatch` lets you change:

- `splunk-time-earliest`
- `splunk-time-latest`
- `splunk-result-format`
- `splunk-result-limit`

These values are also reused when you edit or drill down from an existing search.

## Result Views

### Table view

The default table view is optimized for common fields and not for every field a search may return.

- `splunk-visible-fields` sets the preferred columns
- `splunk-max-columns` caps how many columns are shown
- `splunk-time-column-width` controls the `_time` width
- multiline fields such as `_raw` are collapsed to a single line in the table

When a search returns many fields, keep the table narrow and use the detail inspector or raw view for the full event.

### Result keybindings

In `Splunk-Results`:

- `RET`, `o`, or `v` opens the detail inspector for the current row
- `s` drills down on the table cell under point by appending `field=value` to the current search
- `C-c C-f` enables follow mode so the detail window tracks point
- `1` edits and reruns the current search
- `?` or `d` opens `splunk-dispatch`

In the detail inspector:

- `RET` drills down on the field under point
- `1` edits and reruns the current search
- `q` closes the detail window

In raw, JSON, CSV, and history buffers:

- `1` edits and reruns the current search

## Useful Options

- `splunk-auth-source-service`
  Restrict auth lookups and backend imports to a specific service, for example `"splunk"`.

- `splunk-request-timeout`
  Per-request timeout in seconds for login, search submission, and polling.

- `splunk-disable-ssl-verification`
  Disable TLS verification for self-signed Splunk deployments.

- `splunk-result-detail-window-width`
  Width of the right-side detail inspector window.

- `splunk-overview-window-width`
  Width reserved for the overview window when a results buffer is opened beside it.

- `splunk-visible-fields`
  Preferred field order for the table view.

- `splunk-max-columns`
  Maximum number of table columns to display.

## Troubleshooting

- If the package keeps trying `localhost:8089`, your active backend is wrong. Import or switch servers and verify your `auth-source` entry matches host, port, and user.
- If you use a self-signed certificate, run `M-x splunk-toggle-ssl-verification`.
- If requests are timing out, increase `splunk-request-timeout`.
- If Emacs still has the old code loaded after an edit, reload the file instead of restarting your whole session.

## Repository Notes

- [`splunk-mode.el`](./splunk-mode.el) is the current source of truth.
- [`splunk.org`](./splunk.org) is useful historical context, but it does not fully match the live implementation.
- Legacy `pepita` files are preserved for reference and migration context.

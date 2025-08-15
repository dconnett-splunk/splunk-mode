;; [[file:splunk.org::*License][License:1]]
;;; splunk-mode.el --- Run Splunk search commands, export results to CSV/HTML/JSON  -*- lexical-binding: t; -*-

;; Copyright (C) 2019 Sebastian Monia
;; Copyright (C) 2022 David Connett
;;
;; Author: Sebastian Monia <smonia@outlook.com>
;; Author: David Connett <dave.connett@gmail.com>
;;
;; URL: https://github.com/sebasmonia/splunk.git
;; Package-Requires: ((emacs "25.1") (csv "2.1"))
;; Version: 1.0
;; Keywords: tools convenience matching

;; This file is not part of GNU Emacs.

;;; License: MIT

;;; Commentary:

;; Run a Splunk search from Emacs.  Get the results as CSV, with option to export
;; to JSON,  HTML and Org tables.
;; The entry points are splunk-new-search and splunk-search-at-point
;; You will be prompted a query text, and time range for the query, and will get back
;; the results (when ready) in a new buffer.
;; Use describe-mode (C-h m) in the results buffer to see the available commands.
;;
;; Use the command splunk-queries-running to open a buffer with the items waiting for results
;; and splunk-queries-history to see a list of all queries completed in the session.
;;
;; For more details on usage see https://github.com/sebasmonia/splunk/blob/master/README.md
;; including some workflow suggestions.

;;; Code:
;;;
;;; Test
;; This buffer is for text that is not saved, and for Lisp evaluation.
;; To create a file, visit it with C-x C-f and enter text in its buffer.
;;
;; License:1 ends here

;; [[file:splunk.org::*Preamble][Preamble:1]]
(eval-when-compile (require 'cl-lib))
(require 'cl-lib)
(require 'soap-client)
(require 'request)
(require 'json)
(require 'url-parse)
(require 'url-util)
(require 'subr-x)
(require 'transient)

(defgroup splunk nil
  "Splunk Mode"
  :group 'extensions)
;; Preamble:1 ends here

;; [[file:splunk.org::*Variables][Variables:1]]
;; Variables needed for splunk integration
(defvar splunk-password nil)
(defvar splunk-token nil)
(defvar splunk-url nil)

(defcustom splunk-host "localhost"
  "Splunk host, used with username to compute password from .authinfo"
  :type 'string
  :group 'splunk)

(defcustom splunk-port 8089
  "Splunk port"
  :type 'integer
  :group 'splunk)

(defcustom splunk-username "admin"
  "Splunk username"
  :type 'string
  :group 'splunk)

;; Search defaults used by transient UI
(defcustom splunk-time-earliest "-24h"
  "Default earliest time for searches. Examples: \"-24h\", \"@d\"."
  :type 'string
  :group 'splunk)

(defcustom splunk-time-latest "now"
  "Default latest time for searches. Examples: \"now\", \"@d\"."
  :type 'string
  :group 'splunk)

(defcustom splunk-result-format 'table
  "Default result rendering format. Used by UI when displaying results."
  :type '(choice (const :tag "Table" table)
          (const :tag "CSV" csv)
          (const :tag "JSON" json)
          (const :tag "Raw" raw))
  :group 'splunk)

(defcustom splunk-result-limit 1000
  "Default maximum number of results to fetch/display."
  :type 'integer
  :group 'splunk)

(defcustom splunk-debug nil
  "If non-nil, log HTTP responses and show debug info."
  :type 'boolean
  :group 'splunk)

(defcustom splunk-visible-fields '("_time" "host" "source" "sourcetype" "_raw")
  "Preferred field order for tabular rendering. Only fields present are shown."
  :type '(repeat string)
  :group 'splunk)

(defcustom splunk-hide-internal-fields t
  "If non-nil, hide internal fields starting with an underscore, except for `_time` and `_raw`."
  :type 'boolean
  :group 'splunk)

(defcustom splunk-max-columns 8
  "Maximum number of columns to display in the tabular view."
  :type 'integer
  :group 'splunk)

(defcustom splunk-column-min-width 12
  "Minimum width for a table column."
  :type 'integer
  :group 'splunk)

(defcustom splunk-column-max-width 100
  "Maximum width for a table column."
  :type 'integer
  :group 'splunk)

;; list of all hosts stored by user
(defcustom splunk-hosts nil
  "List of all hosts stored by user"
  :type 'list
  :group 'splunk)

;; Splunk logins, stores list of hostnames and associated usernames
(defcustom splunk-logins nil
  "List of all logins stored by user"
  :type 'list
  :group 'splunk)

;; Splunk login endpoint
(defcustom splunk-login-endpoint "/services/auth/login"
  "Splunk login endpoint"
  :type 'string
  :group 'splunk)

;; Splunk search endpoint
(defcustom splunk-search-endpoint "/services/search/jobs"
  "Splunk search endpoint"
  :type 'string
  :group 'splunk)

(defvar splunk--pending-requests (make-vector 20 nil) "Holds data for the pending requests.")
(defvar splunk--request-history nil "Holds the list requests completed.")
(defvar splunk--search-history nil "List of past searches. Elements are plists with keys :query :sid :time :results.")
(defvar splunk--auth-header nil "Cached credentials for Splunk.")
(defvar splunk--last-search-parameters nil)
(defvar splunk--last-http-headers nil)
(defvar splunk--last-http-body nil)
;; Variables:1 ends here

;; [[file:splunk.org::*Basic URL Stuff and HTTP Request Stuff][Basic URL Stuff and HTTP Request Stuff:1]]
;; Create splunk url from host, port and endpoint
(defun splunk-generate-url (host port endpoint)
  "Create splunk url from HOST, PORT and ENDPOINT."
  (concat "https://" host ":" (number-to-string port) endpoint))

(splunk-generate-url "localhost" 8089 "/services/search/jobs")
;; Basic URL Stuff and HTTP Request Stuff:1 ends here

;; [[file:splunk.org::*Authinfo Handlers][Authinfo Handlers:1]]
(defun splunk--prompt-for-credentials ()
  "Prompt for credentials."
  (let ((username (read-string "Username: " splunk-username))
        (password (read-passwd "Password: ")))
    (cons username password)))

;; Prompt user for a splunk host and username and save it permanently
(defun splunk--add-host ()
  "Prompt user for a splunk host and username and save it permanently"
  (interactive)
  (let ((host (read-string "Host: " splunk-host))
        (port (read-string "Port: " (number-to-string splunk-port)))
        (username (read-string "Username: " splunk-username)))
    (add-to-list 'splunk-hosts (list host port username))
    (customize-save-variable 'splunk-hosts splunk-hosts)))


;; Print all hosts from authsource
;; This is useful for debugging
;; Also breaks sometimes, and prints MacOS keyring
(defun splunk-print-authsource ()
  "Print all hosts from authsource."
  (interactive)
  (let ((auth (auth-source-search :max 1000)))
    (when auth
      (dolist (host auth)
        (message "%s" host)))))
;; Authinfo Handlers:1 ends here

;; [[file:splunk.org::*Basic Login Test][Basic Login Test:1]]
;; Tested working
;; (let* ((auth-sources '("~/.authinfo.gpg"))
;;        (auth-source-creation-prompts
;;         '((user . "Enter username: ")
;;           (secret . "Enter password: ")))
;;        (entry (nth 0 (auth-source-search
;;                       :host splunk-host
;;                       :port splunk-port
;;                       :require '(:user :secret)
;;                       :create t))))
;;   (if entry
;;       (when-let ((save-function (plist-get entry :save-function)))
;;         (funcall save-function))
;;     (message "Failed to create a new entry")))
;; Basic Login Test:1 ends here

;; [[file:splunk.org::*Attempt to use jiralib.el:jiralib-call function for inspiration][Attempt to use jiralib.el:jiralib-call function for inspiration:1]]
;; Print all hosts from authsource non-interactively
(defun splunk-print-authsource-non-interactive ()
  "Print all hosts from authsource non-interactively."
  (let ((auth (auth-source-search :max 1000)))
    (when auth
      (dolist (host auth)
        (message "%s" host)))))

;; print a list of saved splunk hosts
;; this is useful for debugging
(defun splunk-print-hosts ()
  "Print a list of saved splunk hosts consed together in a a lisr"
  (interactive)
  (message "%s" splunk-hosts))
;; Change current splunk host
;; prompt for a new host and set the splunk-host variable to the new host
;; set credentials for the new host if none are found
;; authenticate with splunk
(defun splunk-change-host ()
  "Change current splunk host."
  (interactive)
  (let ((host (read-string "Host: " splunk-host)))
    (setq splunk-host host)
    (customize-save-variable 'splunk-host splunk-host)
    (splunk-authenticate)))
;; Attempt to use jiralib.el:jiralib-call function for inspiration:1 ends here

;; [[file:splunk.org::*Servers Management][Servers Management:1]]
;; Utilities to handle multiple Splunk servers.

(defun splunk--format-host-entry (entry)
  "Format a saved server ENTRY from `splunk-hosts` for display."
  (format "%s:%s - %s" (nth 0 entry) (nth 1 entry) (nth 2 entry)))

(defun splunk-hosts-add (&optional host port username)
  "Add a Splunk server to `splunk-hosts`. Prompts if not provided."
  (interactive)
  (let* ((host (or host (read-string "Host: ")))
         (port (or port (read-string "Port: " (number-to-string splunk-port))))
         (username (or username (read-string "Username: " splunk-username)))
         (entry (list host port username)))
    (unless (seq-find (lambda (e) (string= (splunk--format-host-entry e)
                                           (splunk--format-host-entry entry)))
                      splunk-hosts)
      (add-to-list 'splunk-hosts entry t))
    (customize-save-variable 'splunk-hosts splunk-hosts)
    (message "Saved server: %s" (splunk--format-host-entry entry))))

(defun splunk-hosts--select-entry (prompt)
  (let* ((candidates (mapcar (lambda (e) (cons (splunk--format-host-entry e) e)) splunk-hosts))
         (choice (completing-read prompt (mapcar #'car candidates) nil t)))
    (cdr (assoc choice candidates))))

(defun splunk-hosts-switch ()
  "Switch current Splunk server from `splunk-hosts`. Clears cached auth."
  (interactive)
  (if (null splunk-hosts)
      (user-error "No saved servers. Use splunk-hosts-add first")
    (let* ((entry (splunk-hosts--select-entry "Switch to server: "))
           (host (nth 0 entry))
           (port (nth 1 entry))
           (username (nth 2 entry)))
      (splunk--apply-server-entry host port username)
      (message "Switched to %s" (splunk--format-host-entry (list host port username))))))

(defun splunk--apply-server-entry (host port username)
  "Apply HOST, PORT, USERNAME as current server and persist; clear cached auth."
  (setq splunk-host host
        splunk-port (if (integerp port) port (string-to-number port))
        splunk-username username
        splunk--auth-header nil)
  (customize-save-variable 'splunk-host splunk-host)
  (customize-save-variable 'splunk-port splunk-port)
  (customize-save-variable 'splunk-username splunk-username)
  (splunk-overview-refresh))

(defun splunk--switch-to-entry (entry)
  (let ((host (nth 0 entry))
        (port (nth 1 entry))
        (username (nth 2 entry)))
    (splunk--apply-server-entry host port username)
    (message "Switched to %s" (splunk--format-host-entry entry))))

(defun splunk-hosts-save-current ()
  "Save current `splunk-host`, `splunk-port`, `splunk-username` to `splunk-hosts` if not present."
  (interactive)
  (let* ((entry (list splunk-host (number-to-string splunk-port) splunk-username)))
    (unless (seq-find (lambda (e) (string= (splunk--format-host-entry e)
                                           (splunk--format-host-entry entry)))
                      splunk-hosts)
      (add-to-list 'splunk-hosts entry t)
      (customize-save-variable 'splunk-hosts splunk-hosts)
      (message "Saved server: %s" (splunk--format-host-entry entry)))))

(defun splunk-hosts-remove ()
  "Remove a saved Splunk server from `splunk-hosts`."
  (interactive)
  (if (null splunk-hosts)
      (user-error "No saved servers")
    (let* ((entry (splunk-hosts--select-entry "Remove server: ")))
      (setq splunk-hosts (seq-remove (lambda (e)
                                       (string= (splunk--format-host-entry e)
                                                (splunk--format-host-entry entry)))
                                     splunk-hosts))
      (customize-save-variable 'splunk-hosts splunk-hosts)
      (message "Removed server: %s" (splunk--format-host-entry entry)))))

(defun splunk-hosts-edit ()
  "Edit a saved Splunk server entry."
  (interactive)
  (if (null splunk-hosts)
      (user-error "No saved servers")
    (let* ((old (splunk-hosts--select-entry "Edit server: "))
           (host (read-string "Host: " (nth 0 old)))
           (port (read-string "Port: " (nth 1 old)))
           (username (read-string "Username: " (nth 2 old)))
           (new (list host port username)))
      (setq splunk-hosts (cons new (seq-remove (lambda (e)
                                                 (string= (splunk--format-host-entry e)
                                                          (splunk--format-host-entry old)))
                                               splunk-hosts)))
      (customize-save-variable 'splunk-hosts splunk-hosts)
      (message "Updated server: %s" (splunk--format-host-entry new)))))

;; Optional: show saved servers in the overview buffer
(defun splunk-overview-insert-servers ()
  (let ((inhibit-read-only t))
    (magit-insert-section (servers nil)
      (magit-insert-heading "Servers:")
      (if (null splunk-hosts)
          (insert "(none saved)\n")
        (dolist (e splunk-hosts)
          (let* ((label (splunk--format-host-entry e))
                 (is-current (and (string= (nth 0 e) splunk-host)
                                  (string= (nth 2 e) splunk-username)
                                  (= (string-to-number (nth 1 e)) splunk-port))))
            (insert (format "%s%s\n" label (if is-current "  (current)" ""))))))
      (insert "\n"))))
;; Servers Management:1 ends here

;; [[file:splunk.org::*Refactor with help from GPT4][Refactor with help from GPT4:1]]
;; (defun splunk--get-credentials ()
;;   (let* ((auth-source-creation-prompts
;;           '((user . "Splunk user at %h: ")
;;             (secret . "Splunk password for %u@%h: ")
;;             (service . "Splunk service: ")))
;;                   ;;(auth-source-cache-expiry 0) ; Force cache clear
;;          (credentials (auth-source-search
;;                        :service "splunk"
;;                        :require '(:user :secret :service)
;;                        :create t)))
;;     credentials))

;; Use this function for now, too complicated to genericize it for now
(defun splunk--get-credentials ()
  (let* ((credentials (auth-source-search
                       :host splunk-host
                       :port splunk-port
                       :require '(:user :secret)
                       :max 1)))
    credentials))

(defun splunk-prompt-select-host (credentials)
  (completing-read "Select a Splunk host: "
                   (mapcar (lambda (entry) (plist-get entry :host)) credentials)))

(defun splunk-generate-auth-header (user password)
  (concat "Basic " (base64-encode-string (format "%s:%s" user password))))

(require 'url)

(defun splunk-send-login-request (host port auth-header)
  (let ((url-request-method "POST")
        (url-request-extra-headers `(("Authorization" . ,auth-header)))
        (url (format "https://%s:%s/services/auth/login" host port)))
    (with-current-buffer (url-retrieve-synchronously url)
      (prog1 (buffer-string)
        (kill-buffer)))))


(require 'xml)

(defun splunk-cache-login-token (response)
  (let ((xml-response (car (xml-parse-region (point-min) (point-max) response))))
    (when (and (listp xml-response) (eq (car xml-response) 'sessionKey))
      (cdr (car (cdr xml-response))))))

;; Structured body readers (avoid regex parsing)
(defun splunk--read-json-body ()
  (save-excursion
    (goto-char (point-min))
    (when (re-search-forward "\r?\n\r?\n" nil t)
      (let ((headers (buffer-substring-no-properties (point-min) (match-end 0)))
            (json-object-type 'alist)
            (json-array-type 'list)
            (json-key-type 'symbol))
        (setq splunk--last-http-headers headers)
        (setq splunk--last-http-body (buffer-substring-no-properties (point) (point-max)))
        (let ((parsed (ignore-errors (json-read))))
          (when splunk-debug
            (message "[splunk] Parsed JSON: %S" parsed))
          parsed)))))

(defun splunk--read-xml-body ()
  (save-excursion
    (goto-char (point-min))
    (when (re-search-forward "\r?\n\r?\n" nil t)
      (let ((headers (buffer-substring-no-properties (point-min) (match-end 0))))
        (setq splunk--last-http-headers headers)
        (setq splunk--last-http-body (buffer-substring-no-properties (point) (point-max)))
        (let ((parsed (ignore-errors (xml-parse-region (point) (point-max)))))
          (when splunk-debug
            (message "[splunk] Parsed XML: %S" parsed))
          parsed)))))

;; HTTP helpers
(defun splunk--http-status ()
  "Parse `splunk--last-http-headers' and return (CODE . TEXT), or nil."
  (when (and splunk--last-http-headers (> (length splunk--last-http-headers) 0))
    (let* ((headers splunk--last-http-headers)
           (eol (or (string-match "\n" headers) (length headers)))
           (status-line (string-trim-right (substring headers 0 eol)))
           code text)
      (when (string-match "^HTTP/[0-9.]+\\s-+\\([0-9]+\\)\\s-+\\(.*\\)$" status-line)
        (setq code (string-to-number (match-string 1 status-line)))
        (setq text (match-string 2 status-line))
        (cons code text)))))

(defun splunk--truncate (s maxlen)
  (if (and s (> (length s) maxlen))
      (concat (substring s 0 maxlen) "…")
    (or s "")))

(defun splunk-login ()
  "Authenticate against Splunk and cache a session token.
Prompts using `auth-source' if needed. Does not echo secrets."
  (interactive)
  (let* ((auth-source-creation-prompts
          '((user . "Splunk user at %h: ")
            (secret . "Splunk password for %u@%h: ")))
         (cred (nth 0 (auth-source-search :max 1
                                          :host splunk-host
                                          :port splunk-port
                                          :require '(:user :secret)
                                          :create t))))
    (unless cred
      (user-error "No credentials available for %s:%s" splunk-host splunk-port))

    (let* ((user (plist-get cred :user))
           (secret (plist-get cred :secret))
           (password (if (functionp secret) (funcall secret) secret))
           (url (format "http://%s:%s/services/auth/login" splunk-host splunk-port))
           (url-request-method "POST")
           (url-request-extra-headers '(("Content-Type" . "application/x-www-form-urlencoded")
                                        ("Accept" . "application/json")))
           (url-request-data (format "username=%s&password=%s&output_mode=json"
                                     (url-hexify-string user)
                                     (url-hexify-string password))))
      (let ((login-callback
             (lambda (_status)
               (let ((http-response-buffer (current-buffer)))
                 (unwind-protect
                     (progn
                       (let* ((json (splunk--read-json-body))
                              (token (or (and json (alist-get 'sessionKey json))
                                         ;; Fallback to XML parsing if JSON fails or doesn't have sessionKey
                                         (let* ((xml (splunk--read-xml-body))
                                                (root (car-safe xml))
                                                (node (and root (car (xml-get-children root 'sessionKey)))))
                                           (and node (car (xml-node-children node)))))))
                         (if (and token (stringp token) (not (string-empty-p token)))
                             (progn
                               (setq splunk-token token
                                     splunk--auth-header (cons "Authorization" (concat "Splunk " token)))
                               (message "Login successful for %s@%s:%s" user splunk-host splunk-port)
                               (splunk-overview-refresh))
                           ;; Login failed, report HTTP status and body
                           (let* ((status (splunk--http-status))
                                  (code (car status))
                                  (text (cdr status))
                                  (body (splunk--truncate splunk--last-http-body 2000)))
                             (message "Login failed: %s %s\nBody: %s"
                                      (or code "<unknown>") (or text "") body)))))
                   ;; Ensure the temporary HTTP response buffer is killed
                   (when (buffer-live-p http-response-buffer)
                     (kill-buffer http-response-buffer)))))))
        ;; Perform the asynchronous HTTP request
        (url-retrieve url login-callback nil t)))))

(defun splunk--generate-auth-header ()
  "Generate a Basic Authorization header value (string) from auth-source."
  (let* ((creds (splunk--get-credentials))

         (cred (car creds))
         (user (plist-get cred :user))
         (secret (plist-get cred :secret))
         (password (and secret (if (functionp secret) (funcall secret) secret))))
    (when (and user password)
      (concat "Basic " (base64-encode-string (concat user ":" password))))))

(defun splunk-create-search-job-callback (status &rest _cbargs)
  (ignore status)
  (let ((http-buf (current-buffer)))
    (unwind-protect
        (let* ((json (splunk--read-json-body))
               (sid (or (and json (alist-get 'sid json))
                        (let* ((xml (splunk--read-xml-body))
                               (root (car-safe xml))
                               (node (and root (car (xml-get-children root 'sid)))))
                          (and node (car (xml-node-children node)))))))
          (when splunk-debug
            (message "[splunk] job create headers: %s" (or splunk--last-http-headers "<none>"))
            (message "[splunk] job create body: %s" (or splunk--last-http-body "<none>")))
          (cond
           ((and sid (not (string-empty-p sid)))
            (message "Search submitted. SID=%s" sid)
            (splunk--poll-results sid 0))
           (t
            (let* ((status (splunk--http-status))
                   (code (car status))
                   (text (cdr status))
                   (body (splunk--truncate splunk--last-http-body 2000)))
              (message "Search job creation failed: %s %s\nBody: %s"
                       (or code "<unknown>") (or text "") body)))))
      (when (buffer-live-p http-buf)
        (kill-buffer http-buf)))))


(defun splunk-generate-auth-header (user password)
  (concat "Basic " (base64-encode-string (format "%s:%s" user password))))

(defun splunk-create-search-job (search-query)
  (interactive "sEnter search query: ")
  (let* ((credentials (splunk--get-credentials))
         (user (plist-get (car credentials) :user))
         (secret (plist-get (car credentials) :secret))
         (password (if (functionp secret) (funcall secret) secret))
         (url (format "https://%s:%s/services/search/jobs" splunk-host splunk-port))
         (url-user-and-password (format "%s:%s" user password))
         (url-request-method "POST")
         (auth-header (or splunk--auth-header
                          (cons "Authorization" (concat "Basic " (base64-encode-string url-user-and-password)))))
         (url-request-extra-headers (list (cons "Content-Type" "application/x-www-form-urlencoded")
                                          (cons "Accept" "application/json")
                                          auth-header))
         (url-request-data (mapconcat #'identity
                                      (delq nil
                                            (list
                                             (format "search=%s" (url-hexify-string (concat "search " search-query)))
                                             (when (and splunk-time-earliest (not (string-empty-p splunk-time-earliest)))
                                               (format "earliest_time=%s" (url-hexify-string splunk-time-earliest)))
                                             (when (and splunk-time-latest (not (string-empty-p splunk-time-latest)))
                                               (format "latest_time=%s" (url-hexify-string splunk-time-latest)))
                                             (when (and splunk-result-limit (> splunk-result-limit 0))
                                               (format "max_count=%s" (number-to-string splunk-result-limit)))
                                             "output_mode=json"))
                                      "&")))
    (push (list :query search-query :time (current-time)) splunk--search-history)
    (url-retrieve url #'splunk-create-search-job-callback nil t)))

(defun splunk--current-auth-header ()
  "Return a cons cell suitable for `url-request-extra-headers` Authorization."
  (or splunk--auth-header
      (let ((val (splunk--generate-auth-header)))
        (when val (cons "Authorization" val)))))

(defun splunk--parse-json-field (field)
  (save-excursion
    (goto-char (point-min))
    (when (re-search-forward "\r?\n\r?\n" nil t)
      (let* ((json-obj (ignore-errors (json-read))))
        (when (and (hash-table-p json-obj) (gethash field json-obj))
          (gethash field json-obj))))))

(defun splunk--parse-xml-tag (tag)
  (save-excursion
    (goto-char (point-min))
    (when (re-search-forward "\r?\n\r?\n" nil t)
      (let* ((xml (ignore-errors (xml-parse-region (point) (point-max))))
             (root (car-safe xml))
             (node (and root (car (xml-get-children root tag)))))
        (and node (car (xml-node-children node)))))))

(defun splunk--extract-sid ()
  (or (splunk--parse-json-field 'sid)
      (progn
        (goto-char (point-min))
        (when (re-search-forward "\\\"sid\\\"\\s-*:\\s-*\\\"\\([^\\\"]+\\)\\\"" nil t)
          (match-string 1)))
      (progn
        (goto-char (point-min))
        (when (re-search-forward "<sid>\\([^<]+\\)</sid>" nil t)
          (match-string 1)))
      (splunk--parse-xml-tag 'sid)))

;; Results rendering
(defun splunk--ensure-string (value)
  (cond
   ((stringp value) value)
   ((numberp value) (number-to-string value))
   ((eq value :json-false) "false")
   ((eq value t) "true")
   ((null value) "")
   ((listp value) (mapconcat #'splunk--ensure-string value ","))
   (t (format "%S" value))))

(defun splunk--extract-fields (results-json)
  (let ((fields (alist-get 'fields results-json)))
    (cond
     ;; fields provided as list of alists with (name . "...")
     ((and (listp fields) (consp (car fields)) (assq 'name (car fields)))
      (mapcar (lambda (f) (splunk--ensure-string (alist-get 'name f))) fields))
     ;; fields provided as list of strings
     ((and (listp fields) (stringp (car fields))) fields)
     ;; no fields → infer from first result
     (t
      (let* ((results (alist-get 'results results-json))
             (first (car results)))
        (and (listp first)
             (mapcar (lambda (kv) (splunk--ensure-string (car kv))) first)))))))

(defun splunk--select-display-fields (all-fields)
  (let* ((preferred (seq-filter (lambda (f) (member f all-fields)) splunk-visible-fields))
         (rest (seq-filter (lambda (f)
                             (and (not (member f splunk-visible-fields))
                                  (or (not splunk-hide-internal-fields)
                                      (not (and (> (length f) 1)
                                                (eq (aref f 0) ?_)
                                                (not (member f '("_time" "_raw"))))))))
                           all-fields))
         (full (seq-concatenate 'list preferred rest)))
    (cl-subseq full 0 (min (length full) splunk-max-columns))))

(defun splunk--row-for-fields (row fields)
  (vconcat (mapcar (lambda (fname)
                     (let ((kv (assq (intern fname) row)))
                       (splunk--ensure-string (if kv (cdr kv) ""))))
                   fields)))

(define-derived-mode splunk-results-mode tabulated-list-mode "Splunk-Results"
  "Mode for viewing Splunk search results."
  (setq-local truncate-lines t)
  (setq-local tabulated-list-padding 2)
  (setq-local tabulated-list-use-header-line t))

(defun splunk--render-results-tabulated (sid results-json)
  (let* ((results (alist-get 'results results-json))
         (raw-fields (or (splunk--extract-fields results-json)
                         '("_time" "host" "source" "sourcetype" "_raw")))
         (fields (splunk--select-display-fields raw-fields))
         (buf (get-buffer-create (format "*Splunk Results: %s*" sid))))
    (with-current-buffer buf
      (let* ((columns-list (mapcar (lambda (name)
                                     (let* ((base-width (if (string= name "_raw") splunk-column-max-width
                                                          (round (* 1.8 (max 10 (length name))))))
                                            (width (max splunk-column-min-width
                                                        (min splunk-column-max-width base-width))))
                                       (list name width t)))
                                   fields))
             (columns (apply 'vector columns-list))
             (entries (mapcar (lambda (row)
                                (list (or (cdr (assq '_cd row)) (format "%s" (random)))
                                      (splunk--row-for-fields row fields)))
                              results)))
        (setq tabulated-list-format columns
              tabulated-list-entries entries)
        (splunk-results-mode)
        (tabulated-list-init-header)
        (tabulated-list-print t)
        (goto-char (point-min))))
    (pop-to-buffer buf)))

(defun splunk--render-results-raw (sid results-json)
  (let* ((results (alist-get 'results results-json))
         (buf (get-buffer-create (format "*Splunk Raw: %s*" sid))))
    (with-current-buffer buf
      (erase-buffer)
      (let ((inhibit-message t))
        (dolist (row results)
          (let ((raw (cdr (assq '_raw row))))
            (insert (splunk--ensure-string raw) "\n"))))
      (goto-char (point-min))
      (view-mode 1))
    (pop-to-buffer buf)))

(defun splunk--render-results-buffer (sid results-json)
  (pcase splunk-result-format
    ('json
     (let ((buf (get-buffer-create (format "*Splunk JSON: %s*" sid))))
       (with-current-buffer buf
         (erase-buffer)
         (insert (pp-to-string results-json))
         (goto-char (point-min))
         (view-mode 1))
       (pop-to-buffer buf)))
    ('csv
     (let* ((fields (or (splunk--extract-fields results-json)
                        '("_time" "host" "source" "sourcetype" "_raw")))
            (results (alist-get 'results results-json))
            (buf (get-buffer-create (format "*Splunk CSV: %s*" sid))))
       (with-current-buffer buf
         (erase-buffer)
         (insert (mapconcat #'identity fields ",") "\n")
         (dolist (row results)
           (insert (mapconcat (lambda (f)
                                (let* ((kv (assq (intern f) row))
                                       (val (splunk--ensure-string (if kv (cdr kv) ""))))
                                  ;; basic CSV escaping
                                  (if (string-match-p ",[\"]" val)
                                      (concat "\"" (replace-regexp-in-string "\"" "\"\"" val) "\"")
                                    val)))
                              fields ",")
                   "\n"))
         (goto-char (point-min))
         (view-mode 1))
       (pop-to-buffer buf)))
    ('raw (splunk--render-results-raw sid results-json))
    (_ (splunk--render-results-tabulated sid results-json))))

(defun splunk--handle-results-response (sid _status)
  (let ((http-buf (current-buffer)))
    (unwind-protect
        (let* ((json (splunk--read-json-body))
               (preview (and json (alist-get 'preview json)))
               (has-results-key (and json (assq 'results json)))
               (results (and json (alist-get 'results json))))
          (when splunk-debug
            (message "[splunk] results headers: %s" (or splunk--last-http-headers "<none>"))
            (message "[splunk] results body: %s" (or splunk--last-http-body "<none>")))
          (cond
           ;; Final response (preview=false) with results key present (may be empty)
           ((and has-results-key (eq preview :json-false))
            (splunk--render-results-buffer sid json)
            (let* ((current (or (car splunk--search-history)
                                (list :query "" :time (current-time))))
                   (current (plist-put current :sid sid))
                   (current (plist-put current :results json)))
              (if (null splunk--search-history)
                  (setq splunk--search-history (list current))
                (setcar splunk--search-history current)))
            (when splunk-debug
              (message (if results
                           (format "Search complete: %s (%d result%s)" sid (length results) (if (= (length results) 1) "" "s"))
                         (format "Search complete: %s (0 results)" sid)))))
           ;; Not final yet → keep polling, unless we got an HTTP error (e.g., 502/503 with empty body)
           (t
            (let ((status (splunk--http-status)))
              (if (and status (>= (car status) 400))
                  (message "Results polling failed: %s %s" (car status) (cdr status))
                (run-at-time 1.0 nil #'splunk--poll-results sid 1))))))
      (when (buffer-live-p http-buf)
        (kill-buffer http-buf)))))

(defun splunk--handle-results-response-cb (status &rest cbargs)
  (let ((sid (car cbargs)))
    (splunk--handle-results-response sid status)))

(defun splunk--poll-results (sid attempt)
  (let* ((url-request-method "GET")
         (url-request-extra-headers (list (splunk--current-auth-header)
                                          (cons "Accept" "application/json")))
         (url (format "https://%s:%s/services/search/jobs/%s/results?output_mode=json&count=%s" splunk-host splunk-port sid splunk-result-limit)))
    (url-retrieve url #'splunk--handle-results-response-cb (list sid) t)))

(defun splunk-request (method endpoint params)
  (let* ((url (format "https://%s:%d%s" splunk-host splunk-port endpoint))
         (headers `(("Authorization" . ,(splunk--generate-auth-header))))
         (response (request url
                     :type method
                     :params params
                     :headers headers
                     :parser 'json-read
                     :sync t
                     :error (cl-function
                             (lambda (&key error-thrown &allow-other-keys)
                               (message "Got error: %S" error-thrown)))
                     :status-code '((401 . (lambda (&rest _) (message "Unauthorized. Please check your credentials."))))))
         (data (request-response-data response)))
    (progn
      (message "Response: %S" response)  ; Print the response
      data)))


(defun splunk-create-search-job-request (search-query)
  (splunk-request "POST" "/services/search/jobs" `(("search" . ,(concat "search " search-query)))))
;; Refactor with help from GPT4:1 ends here

;; [[file:splunk.org::*GUI Section][GUI Section:1]]
(require 'magit)

(defvar splunk-overview-buffer-name "*splunk-overview*"
  "Name of the Splunk overview buffer.")

(define-derived-mode splunk-overview-mode magit-mode "Splunk-Overview"
  "Major mode for interacting with Splunk."
  (read-only-mode -1))

(defun splunk-overview-placeholder ()
  "Placeholder function for unimplemented menu actions."
  (interactive)
  (splunk-overview))

(defun splunk-overview (&optional successor)
  "Display the Splunk overview buffer and optionally navigate to a specific section."
  (interactive)
  ;; Kill existing buffer with the same name, if any.
  (when-let ((existing-buffer (get-buffer splunk-overview-buffer-name)))
    (kill-buffer existing-buffer))
  (let ((buffer (get-buffer-create splunk-overview-buffer-name)))
    (with-current-buffer buffer
      (splunk-overview-mode)
      (setq-local magit-branch-buffer buffer)
      (setq-local magit-section-show-child-count t)

      ;; Clear the hook and add the function inside splunk-overview
      (setq-local splunk-overview-sections-hook nil)
      (add-hook 'splunk-overview-sections-hook 'splunk-overview-insert-menu)

      (magit-insert-section (splunk-overview)
        (run-hooks 'splunk-overview-sections-hook)
        (insert "Welcome to Splunk Overview.\n"))
      (when successor
        (magit-section-goto-successor successor)))
    (switch-to-buffer buffer)))

(defun splunk-overview-refresh ()
  "Refresh the Splunk overview buffer if visible."
  (when-let ((buf (get-buffer splunk-overview-buffer-name)))
    (with-current-buffer buf
      (let ((inhibit-read-only t))
        (erase-buffer)
        (setq-local splunk-overview-sections-hook nil)
        (add-hook 'splunk-overview-sections-hook 'splunk-overview-insert-menu)
        (magit-insert-section (splunk-overview)
          (run-hooks 'splunk-overview-sections-hook)
          (insert "Welcome to Splunk Overview.\n"))))))

(define-key splunk-overview-mode-map (kbd "1") 'splunk-create-search-job)
(define-key splunk-overview-mode-map (kbd "2") 'splunk-overview-placeholder)
(define-key splunk-overview-mode-map (kbd "3") 'splunk-overview-placeholder)

(defun splunk-overview-insert-menu ()
  "Insert the menu section in the Splunk overview buffer."
  (let ((inhibit-read-only t)) ; Allow writing to the buffer
    (magit-insert-section (menu nil)
      (magit-insert-heading "Server:")
      ;; Display the current server information
      (insert (format "Host: %s\n" splunk-host))
      (insert (format "Port: %s\n" splunk-port))
      (insert (format "Username: %s\n" splunk-username))
      (insert (format "Auth: %s\n" (if splunk-token "token" "none")))
      (insert "\n")

      (splunk-overview-insert-servers)

      (magit-insert-heading "Menu:")
      (magit-insert-section (search nil)
        (insert "1. Search (press d → s → s)\n"))
      (magit-insert-section (recent-searches nil)
        (insert "2. Recent Searches (TBD)\n"))
      (magit-insert-section (configure nil)
        (insert "3. Configure (TBD)\n"))
      (insert "\n"))))

(add-hook 'splunk-overview-sections-hook 'splunk-overview-insert-menu)
;; GUI Section:1 ends here

;; [[file:splunk.org::*Transient UI][Transient UI:1]]
;;
;; A Magit-like transient dispatcher for Splunk commands.

(transient-define-infix splunk--infix-earliest ()
  :class 'transient-lisp-variable
  :description "Earliest time"
  :key "e"
  :reader (lambda (&rest _)
            (read-string "Earliest time: " splunk-time-earliest))
  :variable 'splunk-time-earliest)

(transient-define-infix splunk--infix-latest ()
  :class 'transient-lisp-variable
  :description "Latest time"
  :key "l"
  :reader (lambda (&rest _)
            (read-string "Latest time: " splunk-time-latest))
  :variable 'splunk-time-latest)

(transient-define-infix splunk--infix-format ()
  :class 'transient-lisp-variable
  :description "Format"
  :key "f"
  :reader (lambda (&rest _)
            (intern (completing-read "Format: " '("table" "csv" "json" "raw")
                                     nil t (symbol-name splunk-result-format))))
  :variable 'splunk-result-format)

(transient-define-infix splunk--infix-limit ()
  :class 'transient-lisp-variable
  :description "Max results"
  :key "m"
  :reader (lambda (&rest _)
            (string-to-number (read-string "Max results: " (number-to-string splunk-result-limit))))
  :variable 'splunk-result-limit)

(defun splunk--run-search-with-query (query)
  "Submit a Splunk QUERY using current transient-configured variables."
  (interactive "sSearch: ")
  (splunk-create-search-job query))

;;;###autoload
(transient-define-prefix splunk-search-dispatch ()
  "Search-focused transient for Splunk."
  ["Arguments"
   (splunk--infix-earliest)
   (splunk--infix-latest)
   (splunk--infix-format)
   (splunk--infix-limit)]
  ["Actions"
   ("s" "Run search…" splunk--run-search-with-query)
   ("p" "Search at point" splunk-create-search-job)])


;; Testing
(defun splunk--queries-running ()
  (interactive)
  (message "Running queries: %s" splunk--pending-requests))

(defun splunk--queries-history ()
  (interactive)
  (if (null splunk--search-history)
      (message "No searches yet")
    (let ((buf (get-buffer-create "*Splunk Recent Searches*")))
      (with-current-buffer buf
        (erase-buffer)
        (insert "Recent Searches:\n\n")
        (dolist (h splunk--search-history)
          (insert (format "- %s  (sid: %s)\n" (plist-get h :query) (or (plist-get h :sid) "pending"))))
        (goto-char (point-min))
        (view-mode 1))
      (pop-to-buffer buf))))

;;;###autoload
(transient-define-prefix splunk-dispatch ()
  "Magit-like dispatcher for Splunk."
  ["Search"
   ("S" "Search…" splunk-search-dispatch)
   ("o" "Overview" splunk-overview)]
  ["Inspect"
   ("r" "Running" splunk--queries-running)
   ("h" "History" splunk--queries-history)]
  ["Servers"
   ("a" "Add server" splunk-hosts-add)
   ("s" "Switch server" splunk-hosts-switch)
   ("e" "Edit server" splunk-hosts-edit)
   ("x" "Remove server" splunk-hosts-remove)
   ("w" "Save current" splunk-hosts-save-current)]
  ["Auth/Server"
   ("H" "Change host (prompt)" splunk-change-host)
   ("L" "Login" splunk-login)])

;; Key bindings
(define-key splunk-overview-mode-map (kbd "?") #'splunk-dispatch)
(define-key splunk-overview-mode-map (kbd "d") #'splunk-dispatch)

;; Transient UI:1 ends here


;; [[file:splunk.org::*Footer][Footer:1]]
(provide 'splunk-mode)
;;; splunk-mode.el ends here
;; Footer:1 ends here

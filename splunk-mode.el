;; [[file:splunk.org::*License][License:1]]
;; Copyright (C) 2019 Sebastian Monia
;; Copyright (C) 2022 David Connett
;;
;; Author: Sebastian Monia <smonia@outlook.com>
;; Author: David Connett <dave.connett@gmail.com>
;;
;; URL: https://github.com/sebasmonia/splunk.git
;; Package-Requires: ((emacs "25") (csv "2.1"))
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
;; This buffer is for text that is not saved, and for Lisp evaluation.
;; To create a file, visit it with C-x C-f and enter text in its buffer.
;;
;; License:1 ends here

;; [[file:splunk.org::*Preamble][Preamble:1]]
(eval-when-compile (require 'cl))
(require 'cl-lib)
(require 'soap-client)
(require 'request)
(require 'json)
(require 'url-parse)
(require 'url-util)

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
(defvar splunk--auth-header nil "Cached credentials for Splunk.")
(defvar splunk--last-search-parameters nil)
;; Variables:1 ends here

;; [[file:splunk.org::*Basic URL Stuff and HTTP Request Stuff][Basic URL Stuff and HTTP Request Stuff:1]]
;; Create splunk url from host, port and endpoint
(defun splunk-generate-url (host port endpoint)
  "Create splunk url from HOST, PORT and ENDPOINT."
  (concat "https://" host ":" (number-to-string port) endpoint))

(splunk-generate-url "localhost" 8089 "/services/search/jobs")
;; Basic URL Stuff and HTTP Request Stuff:1 ends here

;; [[file:splunk.org::*Authinfo Handlers][Authinfo Handlers:1]]
;; This function is newer and should replace get password and add host.
(defun get-splunk-credentials ()
  (let ((credentials (auth-source-search
                      :host "splunk.myhost.com"
                      :port "8089"
                      :user "myusername"
                      :require '(:user :secret)
                      :max 1
                      :create t)))
    (when credentials
      (let* ((entry (car credentials))
             (user (plist-get entry :user))
             (password (let ((secret (plist-get entry :secret)))
                         (if (functionp secret)
                             (funcall secret)
                           secret))))
        (list user password)))))



;; Get password from authinfo given host and username
(defun splunk-get-password (host username)
  "Get password from authinfo given HOST and USERNAME."
  (let ((authinfo (auth-source-search :host host :user username)))
    (if authinfo
        (let ((secret (plist-get (car authinfo) :secret)))
          (if (functionp secret)
              (funcall secret)
            secret))
      ((let ((password (read-passwd "Password: ")))
         (auth-source-save :host host :user username :secret password)
         password)))))

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
(defun splunk-print-authsource ()
  "Print all hosts from authsource."
  (interactive)
  (let ((auth (auth-source-search :max 1000)))
    (when auth
      (dolist (host auth)
        (message "%s" host)))))
(splunk-print-authsource)
;; Authinfo Handlers:1 ends here

;; [[file:splunk.org::*Basic Login Test][Basic Login Test:1]]
(defun splunk--get-auth-header ()
  "Return the auth header.  Caches credentials per-session."
  (unless splunk--auth-header
    (let ((username (or splunk-username (read-string "Splunk username: ")))
          (password (nth 1 (splunk-get-password "localhost" "admin" splunk-port))))
      (setq splunk--auth-header (cons "Authorization"
                                      (concat "Basic "
                                              (base64-encode-string
                                               (format "%s:%s" username password)))))))
  splunk--auth-header)
(splunk--get-auth-header)
;; Basic Login Test:1 ends here

;; [[file:splunk.org::*Attempt to use jiralib.el:jiralib-call function for inspiration][Attempt to use jiralib.el:jiralib-call function for inspiration:1]]
;; Print all hosts from authsource non-interactively
(defun splunk-print-authsource-non-interactive ()
  "Print all hosts from authsource non-interactively."
  (let ((auth (auth-source-search :max 1000)))
    (when auth
      (dolist (host auth)
        (message "%s" host)))))

(splunk-print-authsource-non-interactive)
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

;; login to splunk host using select-host and splunk-authenticate
(defun splunk-login ()
  "Login to splunk host using select-host and splunk-authenticate."
  (interactive)
  (splunk-select-host))
;; Attempt to use jiralib.el:jiralib-call function for inspiration:1 ends here

;; [[file:splunk.org::*Refactor with help from GPT4][Refactor with help from GPT4:1]]
(defun splunk--get-credentials ()
  (let* ((auth-source-creation-prompts
          '((user . "Splunk user at %h: ")
            (secret . "Splunk password for %u@%h: ")
            (service . "Splunk service: ")))
         (credentials (auth-source-search
                       :service "splunk"
                       :require '(:user :secret :service)
                       :create t)))
    credentials))

(defun splunk--get-credentials ()
  (let* ((auth-source-creation-prompts
          '((user . "Splunk user at %h: ")
            (secret . "Splunk password for %u@%h: ")
            (service . "Splunk service: ")))
         (auth-source-cache-expiry 0) ; Force cache clear
         (credentials (auth-source-search
                       :service "splunk"
                       :require '(:user :secret :service)
                       :create t)))
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

(defun splunk--login ()
  (let* ((credentials (splunk--get-credentials))
         (selected-host (splunk-prompt-select-host credentials))
         (selected-creds (car (seq-filter (lambda (entry) (string= (plist-get entry :host) selected-host)) credentials)))
         (user (plist-get selected-creds :user))
         (password (let ((secret (plist-get selected-creds :secret)))
                     (if (functionp secret) (funcall secret) secret)))
         (port (plist-get selected-creds :port))
         (auth-header (splunk-generate-auth-header user password))
         (response (splunk-send-login-request selected-host port auth-header))
         (token (splunk-cache-login-token response)))
    token))

(splunk--login)
;; Refactor with help from GPT4:1 ends here

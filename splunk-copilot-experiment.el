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

(eval-when-compile (require 'cl))
(require 'cl-seq)
(require 'soap-client)
(require 'request)
(require 'json)
(require 'url-parse)
(require 'url-util)

(defgroup splunk nil
  "Splunk Mode"
  :group 'extensions)

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

(defvar splunk--pending-requests (make-vector 20 nil) "Holds data for the pending requests.")
(defvar splunk--request-history nil "Holds the list requests completed.")
(defvar splunk--auth-header nil "Cached credentials for Splunk.")
(defvar splunk--last-search-parameters nil)

;; Create Splunk rest api url from host and port
(defun splunk-url ()
  (if splunk-url
      splunk-url
    (setq splunk-url (format "https://%s:%s" splunk-host splunk-port))))



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

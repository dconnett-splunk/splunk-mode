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

(defun splunk--login ()
  (interactive)
  (let* ((credentials (splunk--get-credentials))
         (user (plist-get (car credentials) :user))
         (secret (plist-get (car credentials) :secret))
         (password (if (functionp secret) (funcall secret) secret)))
    (message "Logging in with user: %s and password: %s" user password)))


(defun splunk--generate-auth-header ()
  "Generate an Authorization header for Splunk requests."
  (let ((credentials (splunk--get-credentials)))
    (when credentials
      (let ((user (plist-get credentials :user))
            (secret (plist-get credentials :secret)))
        (when (and user secret)
          (let ((password (if (functionp secret) (funcall secret) secret)))
            (concat "Basic " (base64-encode-string (concat user ":" password)))))))))

(defun splunk-create-search-job-callback (status)
  (if (plist-get status :error)
      (message "Error creating search job: %s" (plist-get status :error))
    (message "Search job created successfully")))


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
         (url-request-extra-headers `(("Content-Type" . "application/x-www-form-urlencoded")
                                       ("Authorization" . ,(concat "Basic " (base64-encode-string url-user-and-password)))))
         (url-request-data (format "search=%s" (url-hexify-string (concat "search " search-query)))))
    (url-retrieve url #'splunk-create-search-job-callback)))

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

(defun splunk-create-search-job (search-query)
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

(define-key splunk-overview-mode-map (kbd "1") 'splunk-overview-placeholder)
(define-key splunk-overview-mode-map (kbd "2") 'splunk-overview-placeholder)
(define-key splunk-overview-mode-map (kbd "3") 'splunk-overview-placeholder)


(defun splunk-overview-insert-menu ()
  "Insert the menu section in the Splunk overview buffer."
  (let ((inhibit-read-only t)) ; Allow writing to the buffer
    (magit-insert-section (menu nil)
      (magit-insert-heading "Menu:")
      (magit-insert-section (search nil)
        (insert "1. Search\n"))
      (magit-insert-section (recent-searches nil)
        (insert "2. Recent Searches\n"))
      (magit-insert-section (configure nil)
        (insert "3. Configure\n"))
      (insert "\n"))))

(add-hook 'splunk-overview-sections-hook 'splunk-overview-insert-menu)
;; GUI Section:1 ends here

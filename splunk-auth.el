;; [[file:splunk.org::*License][License:1]]
;; Copyright (C) 2022 David Connett
;;
;; Author: David Connett <dave.connett@gmail.com>
;;

;; This file is not part of GNU Emacs.

;;; License: MIT

;;; Commentary:

;; License:1 ends here



(require 'auth-source)
(require 'base64)
(require 'seq)



;; auth-source-save function saves the credentials in authinfo
;; but it does not return the password
;; Authinfo Handlers:1 ends here

;; [[file:splunk.org::*Basic Login Test][Basic Login Test:1]]
(defun splunk--get-auth-header (username password)
  "Return the auth header.  Caches credentials per-session."
  (unless splunk--auth-header
    (setq splunk--auth-header (cons "Authorization"
                                    (concat "Basic "
                                            (base64-encode-string
                                             (format "%s:%s" username password))))))
  splunk--auth-header)
;; Basic Login Test:1 ends here


(defun splunk--authenticate (host username port)
  "Authenticate with the selected Splunk host using the provided username and password."
  (let* ((auth-source-creation-prompts
          '((user . "Splunk user at %h: ")
            (secret . "Splunk password for %u@%h: ")))
         (found-credential (nth 0 (auth-source-search
                                   :max 1
                                   :host host
                                   :port port
                                   :user username
                                   :require '(:user :secret)
                                   :create t))))
    (if found-credential
        (let ((secret (plist-get found-credential :secret)))
          (if (functionp secret)
              (funcall secret)
            secret))
      (error "No credentials found for the specified host"))))

;; [[file:splunk.org::*Authinfo Handlers][Authinfo Handlers:1]]
;; Get password from authinfo given host and username
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
(defun splunk--print-authsource ()
  "Print all hosts from authsource."
  (interactive)
  (let ((auth (auth-source-search :max 1000)))
    (when auth
      (dolist (host auth)
        (message "%s" host)))))
(splunk--print-authsource)

;; Given authinfo host, username, port, and password, save credentials in authinfo
(defun splunk--credentials (host username port)
  "Given authinfo HOST, USERNAME, PORT, and PASSWORD, save credentials in authinfo.")

;; auth-source-save function saves the credentials in authinfo
;; but it does not return the password
;; Authinfo Handlers:1 ends here

;; [[file:splunk.org::*Basic Login Test][Basic Login Test:1]]
(defun splunk--get-auth-header (username password)
  "Return the auth header.  Caches credentials per-session."
  (unless splunk--auth-header
    (setq splunk--auth-header (cons "Authorization"
                                    (concat "Basic "
                                            (base64-encode-string
                                             (format "%s:%s" username password))))))
  splunk--auth-header)
;; Basic Login Test:1 ends here


(defun splunk--select-host ()
  "Prompt the user to select a Splunk host from `splunk-hosts`."
  (let* ((hostnames (mapcar (lambda (host)
                              (format "%s:%s - %s" (nth 0 host) (nth 1 host) (nth 2 host)))
                            splunk-hosts))
         (selected-host (completing-read "Select Splunk host: " hostnames nil t)))
    (car (seq-filter (lambda (host)
                       (string= selected-host
                                (format "%s:%s - %s" (nth 0 host) (nth 1 host) (nth 2 host))))
                     splunk-hosts))))

(defun splunk--authenticate (host username port)
  "Authenticate with the selected Splunk host using the provided username and password."
  (let* ((auth-source-creation-prompts
          '((user . "Splunk user at %h: ")
            (secret . "Splunk password for %u@%h: ")))
         (found-credential (nth 0 (auth-source-search
                                    :max 1
                                    :host host
                                    :port port
                                    :user username
                                    :require '(:user :secret)
                                    :create t))))
    (if found-credential
        (let ((secret (plist-get found-credential :secret)))
          (if (functionp secret)
              (funcall secret)
            secret))
      (error "No credentials found for the specified host"))))

(defun splunk--change-host ()
  "Change current Splunk host and authenticate with it."
  (interactive)
  (let* ((host-info (splunk--select-host))
         (host (nth 0 host-info))
         (port (nth 1 host-info))
         (username (nth 2 host-info))
         (password (splunk--authenticate host username port))
         (auth-header (splunk--get-auth-header username password)))
    (message "Authenticated with host: %s:%s - %s" host port username)
    auth-header))


;; [[file:splunk.org::*Attempt to use jiralib.el:jiralib-call function for inspiration][Attempt to use jiralib.el:jiralib-call function for inspiration:1]]
;; Print all hosts from authsource non-interactively
(defun splunk--print-authsource-non-interactive ()
  (interactive)
  "Print all hosts from authsource non-interactively."
  (let ((auth (auth-source-search :max 1000)))
    (when auth
      (dolist (host auth)
        (message "%s" host)))))

(splunk--print-authsource-non-interactive)
;; print a list of saved splunk hosts
;; this is useful for debugging
(defun splunk--print-hosts ()
  "Print a list of saved splunk hosts consed together in a a lisr"
  (interactive)
  (message "%s" splunk-hosts))

(defun nnimap-credentials (address ports)
  (let* ((auth-source-creation-prompts '((user  . "IMAP user at %h: ") (secret . "IMAP password for %u@%h: ")))
         (found-credential (nth 0 (auth-source-search :max 1
                                           :host address
                                           :port ports
                                           :require '(:user :secret)
                                           :create t))))
    (if found-credential
        (list (plist-get found-credential :user)
              (let ((secret (plist-get found-credential :secret)))
                (if (functionp secret)
                    (funcall secret)
                  secret))
              (plist-get found-credential :save-function))
      nil)))

;; login to splunk host using select-host and splunk-authenticate
(defun splunk--login (host &optional username port)
  "Login to splunk host using select-host and splunk-authenticate."
  ;; if host exists in authinfo then use it
  (let* ((auth-source-creation-prompts
          '((user . "Splunk username at %h: ")
            (secret . "Splunk password at %u@%h: ")))
         (found (nth 0 (auth-source-search :max 1
                                           :host host
                                           :port port
                                           :require '(:user :secret)
                                           :create t))))
    (if found
        (list (plist-get found :user)
              (let ((secret (plist-get found :secret)))
                (if (functionp secret)
                    (funcall secret)
                  secret))
              (plist-get found :save-function))
      nil)))






(provide 'splunk-auth)

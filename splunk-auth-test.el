(require 'ert)
(require 'splunk-mode)
(require 'auth-source)

(ert-deftest splunk-mode-test ()
  "Test for `splunk-mode'."
  (with-temp-buffer
    (splunk-mode)
    (should (eq major-mode 'splunk-mode))))

(auth-source-store
  nil
  '("splunk.myhost.com"
    "splunk"
    "myusername"
    "mypassword"
    nil
    "8089"
    nil
    nil
    "app=splunk"))


(splunk--authenticate "https://localhost:8089" "admin" "changeme")


(defun get-splunk-credentials ()
  (let* ((auth-source-creation-prompts
          '((user  . "Splunk user at %h: ")
            (secret . "Splunk password for %u@%h: ")
            (service . "Splunk service: ")))
         (credentials (auth-source-search
                       :host "splunk.myhost.com"
                       :port "8089"
                       :service "splunk"
                       :require '(:user :secret :service)
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



(provide 'splunk-mode-test)

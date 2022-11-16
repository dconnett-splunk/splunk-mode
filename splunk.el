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

;;; Copyright (C) 2007-2009 LW Inc. <http://www.lw.com>
;;;  
;;; This program is free software; you can redistribute it and/or modify
;;; it under the terms of the GNU General Public License as published by
;;; the Free Software Foundation; either version 2 of the License, or
;;; (at your option) any later version.
;;;  
;;; This program is distributed in the hope that it will be useful,
;;; but WITHOUT ANY WARRANTY; without even the implied warranty of
;;; MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
;;; GNU General Public License for more details.
;;;  
;;; You should have received a copy of the GNU General Public License
;;; along with this program; if not, write to the Free Software
;;; Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
;;;  

(defvar lwfs-mode-hook nil)

;; (defvar lwfs-mode-map
;;   (let ((lwfs-mode-map (make-keymap)))
;;     (define-key lwfs-mode-map "\C-j" 'newline-and-indent)
;;     lwfs-mode-map)
;;   "Keymap for WPDL major mode")

(add-to-list 'auto-mode-alist '("\\.vol\\'" . lwfs-mode))

(defconst lwfs-font-lock-keywords-1
  (list
					; "cluster/{unify,afr,stripe}" 
					; "performance/{io-cache,io-threads,write-behind,read-ahead,stat-prefetch}"
					; "protocol/{client/server}"
					; "features/{trash,posix-locks,fixed-id,filter}"
					; "stroage/posix"
					; "encryption/rot-13"
					; "debug/trace"
    '("\\<\\(cluster/\\(unify\\|afr\\|replicate\\|stripe\\|ha\\|dht\\|distribute\\)\\|\\performance/\\(io-\\(cache\\|threads\\)\\|write-behind\\|read-ahead\\|symlink-cache\\)\\|protocol/\\(server\\|client\\)\\|features/\\(trash\\|posix-locks\\|locks\\|path-converter\\|filter\\)\\|storage/\\(posix\\|bdb\\)\\|encryption/rot-13\\|debug/trace\\)\\>" . font-lock-keyword-face))
"Additional Keywords to highlight in LWFS mode.")

(defconst lwfs-font-lock-keywords-2
  (append lwfs-font-lock-keywords-1
	  (list
      ; "replicate" "namespace" "scheduler" "remote-subvolume" "remote-host" 
      ; "auth.addr" "block-size" "remote-port" "listen-port" "transport-type"
      ; "limits.min-free-disk" "directory"
	; TODO: add all the keys here.
	   '("\\<\\(inode-lru-limit\\|replicate\\|namespace\\|scheduler\\|username\\|password\\|allow\\|reject\\|block-size\\|listen-port\\|transport-type\\|transport-timeout\\|directory\\|page-size\\|page-count\\|aggregate-size\\|non-blocking-io\\|client-volume-filename\\|bind-address\\|self-heal\\|read-only-subvolumes\\|read-subvolume\\|thread-count\\|cache-size\\|window-size\\|force-revalidate-timeout\\|priority\\|include\\|exclude\\|remote-\\(host\\|subvolume\\|port\\)\\|auth.\\(addr\\|login\\)\\|limits.\\(min-disk-free\\|transaction-size\\|ib-verbs-\\(work-request-\\(send-\\|recv-\\(count\\|size\\)\\)\\|port\\|mtu\\|device-name\\)\\)\\)\ \\>" . font-lock-constant-face)))
  "option keys in LWFS mode.")

(defconst lwfs-font-lock-keywords-3
  (append lwfs-font-lock-keywords-2
	  (list
					; "option" "volume" "end-volume" "subvolumes" "type"
	   '("\\<\\(option\ \\|volume\ \\|subvolumes\ \\|type\ \\|end-volume\\)\\>" . font-lock-builtin-face)))
					;'((regexp-opt (" option " "^volume " "^end-volume" "subvolumes " " type ") t) . font-lock-builtin-face))
  "Minimal highlighting expressions for LWFS mode.")


(defvar lwfs-font-lock-keywords lwfs-font-lock-keywords-3
  "Default highlighting expressions for LWFS mode.")

(defvar lwfs-mode-syntax-table
  (let ((lwfs-mode-syntax-table (make-syntax-table)))
    (modify-syntax-entry ?\# "<"  lwfs-mode-syntax-table)
    (modify-syntax-entry ?* ". 23"  lwfs-mode-syntax-table)
    (modify-syntax-entry ?\n ">#"  lwfs-mode-syntax-table)
    lwfs-mode-syntax-table)
  "Syntax table for lwfs-mode")

;; TODO: add an indentation table

(defun lwfs-indent-line ()
  "Indent current line as LWFS code"
  (interactive)
  (beginning-of-line)
  (if (bobp)
      (indent-line-to 0)   ; First line is always non-indented
    (let ((not-indented t) cur-indent)
      (if (looking-at "^[ \t]*volume\ ")
	  (progn
	    (save-excursion
	      (forward-line -1)
	      (setq not-indented nil)
	      (setq cur-indent 0))))
      (if (looking-at "^[ \t]*end-volume")
	  (progn
	    (save-excursion
	      (forward-line -1)
	      (setq cur-indent 0))
	    (if (< cur-indent 0) ; We can't indent past the left margin
		(setq cur-indent 0)))
	(save-excursion
	  (while not-indented ; Iterate backwards until we find an indentation hint
	    (progn
	      (setq cur-indent 2) ; Do the actual indenting
	      (setq not-indented nil)))))
      (if cur-indent
	  (indent-line-to cur-indent)
	(indent-line-to 0)))))

(defun lwfs-mode ()
  (interactive)
  (kill-all-local-variables)
  ;; (use-local-map lwfs-mode-map)
  (set-syntax-table lwfs-mode-syntax-table)
  (set (make-local-variable 'indent-line-function) 'lwfs-indent-line)  
  (set (make-local-variable 'font-lock-defaults) '(lwfs-font-lock-keywords))
  (setq major-mode 'lwfs-mode)
  (setq mode-name "LWFS")
  (run-hooks 'lwfs-mode-hook))

(provide 'lwfs-mode)

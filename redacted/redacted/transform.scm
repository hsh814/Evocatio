;;; Package recipe transformations
;;;
;;; SPDX-FileCopyrightText: 2025 SymRadar authors
;;; SPDX-License-Identifier: GPL-3.0-or-later

(define-module (redacted transform)
  #:use-module (ice-9 match)
  #:use-module (ice-9 receive)
  #:use-module (srfi srfi-1)
  #:export (append-env
            append-make-flag))

(define (append-env name addition default)
  (setenv name
          (let ((value (or (getenv name) default)))
            (if value
                (string-append value " " addition)
                addition))))

(define (append-make-flag original additions)
  (let ((orig-ls (map (lambda (flag)
                        (let ((ls (string-split flag #\=)))
                          (list (car ls)
                                (string-join (cdr ls)
                                             "="))))
                      original)))
    (receive (existing new) (partition (lambda (addition)
                                         (assoc (car addition)
                                                orig-ls))
                                       additions)
      (append (map (match-lambda
                     ((name value)
                      (match (assoc name existing)
                        ((or (addition)
                             (addition default))
                         (string-append name "=" value " " addition))
                        (else (string-append name "=" value)))))
                   orig-ls)
              (map (match-lambda
                     ((name addition)
                      (string-append name "=" addition))
                     ((name addition default)
                      (string-append name "=" default " " addition)))
                   new)))))

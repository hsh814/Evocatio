;;; Packages for software fuzzing
;;;
;;; SPDX-FileCopyrightText: 2024-2025 SymRadar authors
;;; SPDX-License-Identifier: GPL-3.0-or-later

(define-module (redacted fuzzing)
  #:use-module (gnu packages)
  #:use-module (gnu packages admin)
  #:use-module (gnu packages commencement)
  #:use-module (gnu packages gcc)
  #:use-module (gnu packages debug)
  #:use-module (gnu packages instrumentation)
  #:use-module (gnu packages man)
  #:use-module (gnu packages m4)
  #:use-module (gnu packages virtualization)
  #:use-module (guix build gnu-build-system)
  #:use-module (guix build-system gnu)
  #:use-module (guix download)
  #:use-module (guix gexp)
  #:use-module (guix git-download)
  #:use-module ((guix licenses) #:prefix license:)
  #:use-module (guix packages)
  #:use-module (guix utils)
  #:export (for-evocatio))

(define-public evocatio
  (let ((commit "fc8f6dc5bbdf5f49cf1231e746a7944efa09dcc7")
        (revision "0"))
    (package
      (inherit aflplusplus)
      (name "evocatio")
      (version (git-version "3.15a" revision commit))
      (source (origin
                (method git-fetch)
                (uri (git-reference
                      (url "https://github.com/HexHive/Evocatio")
                      (commit commit)))
                (file-name (git-file-name name version))
                (sha256
                 (base32
                  "16kc2xa4dk9lq1sg7sl5489n7r3p8kc6hmfgy0gh7i1n6h269bry"))
                (patches
                 (search-patches
                   "patches/evocatio-argv-fuzz-amd64-only.patch"
                   "patches/evocatio-keep-all-crashes.patch"))))
      (arguments
        (substitute-keyword-arguments (package-arguments aflplusplus)
          ((#:make-flags make-flags)
           #~(cons* "-C" "bug-severity-AFLplusplus"
                    "CFLAGS=-O2 -g -fcommon"
                    "NO_SPLICING=1"
                    #$make-flags))
          ((#:build-target _) "source-only")
          ((#:modules modules %default-gnu-modules)
           `((ice-9 string-fun) ,@modules))
          ((#:phases phases)
           #~(modify-phases #$phases
               (replace 'patch-gcc-path
                 (lambda* (#:key inputs #:allow-other-keys)
                   ;; AFL++ is prefixed with bug-severity-AFLplusplus
                   (substitute* "bug-severity-AFLplusplus/src/afl-cc.c"
                     (("alt_cc = \"gcc\";")
                      (format #f "alt_cc = \"~a\";"
                              (search-input-file inputs "bin/gcc")))
                     (("alt_cxx = \"g\\+\\+\";")
                      (format #f "alt_cxx = \"~a\";"
                              (search-input-file inputs "bin/g++"))))))
               (add-after 'build 'build-argv-fuzzing
                 (lambda* (#:key make-flags #:allow-other-keys)
                   (apply invoke
                     "make" "-C" "bug-severity-AFLplusplus/utils/argv_fuzzing"
                     (cdddr make-flags))))
               (add-after 'install 'install-argv-fuzzing
                 (lambda* (#:key make-flags #:allow-other-keys)
                   (apply invoke
                     "make" "-C" "bug-severity-AFLplusplus/utils/argv_fuzzing"
                     "install" (cdddr make-flags))))
               (add-after 'install 'install-scripts
                 (lambda* (#:key outputs #:allow-other-keys)
                   (let ((bin (string-append (assoc-ref outputs "out")
                                             "/bin")))
                     (for-each
                       (lambda (script)
                         (let ((file (string-append
                                       bin "/evocatio-"
                                       (string-replace-substring script
                                         "_" "-"))))
                           (copy-file (string-append "scripts/" script ".py")
                                      file)
                           (chmod file #o755)))
                       '("calculate_severity_score"
                         "gen_raw_data_for_cve")))))))))
      (home-page "https://github.com/HexHive/Evocatio")
      (description
        "Evocatio is a bug analyzer built on top of AFL++ and AddressSanitizer.
It automatically discovers a bug's capabilities: analyzing a crashing test case
(i.e., an input exposing a bug) to understand the full extent
of how an attacker can exploit a bug.

Evocatio leverages a capability-guided fuzzer to efficiently uncover
new bug capabilities (rather than only generating a single crashing test case
for a given bug, as a traditional greybox fuzzer does)."))))

(define (for-evocatio base)
  (package
    (inherit base)
    (name (string-append (package-name base) "-for-evocatio"))
    (arguments
     (substitute-keyword-arguments (package-arguments base)
       ((#:configure-flags flags #~'())
        #~(cons (string-append "CC=" #$evocatio "/bin/afl-cc")
                #$flags))
       ((#:phases phases #~%standard-phases)
        #~(modify-phases #$phases
            (add-before 'configure 'set-env
              (lambda _
                (setenv "CC" #$(file-append evocatio "/bin/afl-cc"))
                (setenv "AFL_USE_ASAN" "1")
                (setenv "AFL_USE_UBSAN" "1")
                (setenv "ASAN_OPTIONS" "detect_leaks=0")))))
       ((#:tests? _ #f)
        #f)))
    (native-inputs
      (modify-inputs (package-native-inputs base)
        (append evocatio)))))

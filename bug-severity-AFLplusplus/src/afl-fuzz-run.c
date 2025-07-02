/*
   american fuzzy lop++ - target execution related routines
   --------------------------------------------------------

   Originally written by Michal Zalewski

   Now maintained by Marc Heuse <mh@mh-sec.de>,
                        Heiko Eißfeldt <heiko.eissfeldt@hexco.de> and
                        Andrea Fioraldi <andreafioraldi@gmail.com> and
                        Dominik Maier <mail@dmnk.co>

   Copyright 2016, 2017 Google Inc. All rights reserved.
   Copyright 2019-2020 AFLplusplus Project. All rights reserved.

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at:

     http://www.apache.org/licenses/LICENSE-2.0

   This is the real deal: the program takes an instrumented binary and
   attempts a variety of basic fuzzing tricks, paying close attention to
   how they affect the execution path.

 */

#include "afl-fuzz.h"
#include <sys/time.h>
#include <signal.h>
#include <limits.h>
#if !defined NAME_MAX
  #define NAME_MAX _XOPEN_NAME_MAX
#endif

#include "cmplog.h"

#ifdef PROFILING
u64 time_spent_working = 0;
#endif

/* Execute target application, monitoring for timeouts. Return status
   information. The called program will update afl->fsrv->trace_bits. */

fsrv_run_result_t __attribute__((hot))
fuzz_run_target(afl_state_t *afl, afl_forkserver_t *fsrv, u32 timeout) {

#ifdef PROFILING
  static u64      time_spent_start = 0;
  struct timespec spec;
  if (time_spent_start) {

    u64 current;
    clock_gettime(CLOCK_REALTIME, &spec);
    current = (spec.tv_sec * 1000000000) + spec.tv_nsec;
    time_spent_working += (current - time_spent_start);

  }

#endif

  fsrv_run_result_t res = afl_fsrv_run_target(fsrv, timeout, &afl->stop_soon);

#ifdef PROFILING
  clock_gettime(CLOCK_REALTIME, &spec);
  time_spent_start = (spec.tv_sec * 1000000000) + spec.tv_nsec;
#endif

  return res;

}

/* Write modified data to file for testing. If afl->fsrv.out_file is set, the
   old file is unlinked and a new one is created. Otherwise, afl->fsrv.out_fd is
   rewound and truncated. */

void __attribute__((hot))
write_to_testcase(afl_state_t *afl, void *mem, u32 len) {

#ifdef _AFL_DOCUMENT_MUTATIONS
  s32  doc_fd;
  char fn[PATH_MAX];
  snprintf(fn, PATH_MAX, "%s/mutations/%09u:%s", afl->out_dir,
           afl->document_counter++,
           describe_op(afl, 0, NAME_MAX - strlen("000000000:")));

  if ((doc_fd = open(fn, O_WRONLY | O_CREAT | O_TRUNC, DEFAULT_PERMISSION)) >=
      0) {

    if (write(doc_fd, mem, len) != len)
      PFATAL("write to mutation file failed: %s", fn);
    close(doc_fd);

  }

#endif

  if (unlikely(afl->custom_mutators_count)) {

    ssize_t new_size = len;
    u8 *    new_mem = mem;
    u8 *    new_buf = NULL;

    LIST_FOREACH(&afl->custom_mutator_list, struct custom_mutator, {

      if (el->afl_custom_post_process) {

        new_size =
            el->afl_custom_post_process(el->data, new_mem, new_size, &new_buf);

        if (unlikely(!new_buf && new_size <= 0)) {

          FATAL("Custom_post_process failed (ret: %lu)",
                (long unsigned)new_size);

        }

        new_mem = new_buf;

      }

    });

    /* everything as planned. use the potentially new data. */
    afl_fsrv_write_to_testcase(&afl->fsrv, new_mem, new_size);

  } else {

    /* boring uncustom. */
    afl_fsrv_write_to_testcase(&afl->fsrv, mem, len);

  }

}

/* The same, but with an adjustable gap. Used for trimming. */

static void write_with_gap(afl_state_t *afl, u8 *mem, u32 len, u32 skip_at,
                           u32 skip_len) {

  s32 fd = afl->fsrv.out_fd;
  u32 tail_len = len - skip_at - skip_len;

  /*
  This memory is used to carry out the post_processing(if present) after copying
  the testcase by removing the gaps. This can break though
  */
  u8 *mem_trimmed = afl_realloc(AFL_BUF_PARAM(out_scratch), len - skip_len + 1);
  if (unlikely(!mem_trimmed)) { PFATAL("alloc"); }

  ssize_t new_size = len - skip_len;
  u8 *    new_mem = mem;

  bool post_process_skipped = true;

  if (unlikely(afl->custom_mutators_count)) {

    u8 *new_buf = NULL;
    new_mem = mem_trimmed;

    LIST_FOREACH(&afl->custom_mutator_list, struct custom_mutator, {

      if (el->afl_custom_post_process) {

        // We copy into the mem_trimmed only if we actually have custom mutators
        // *with* post_processing installed

        if (post_process_skipped) {

          if (skip_at) { memcpy(mem_trimmed, (u8 *)mem, skip_at); }

          if (tail_len) {

            memcpy(mem_trimmed + skip_at, (u8 *)mem + skip_at + skip_len,
                   tail_len);

          }

          post_process_skipped = false;

        }

        new_size =
            el->afl_custom_post_process(el->data, new_mem, new_size, &new_buf);

        if (unlikely(!new_buf || new_size <= 0)) {

          FATAL("Custom_post_process failed (ret: %lu)",
                (long unsigned)new_size);

        }

        new_mem = new_buf;

      }

    });

  }

  if (likely(afl->fsrv.use_shmem_fuzz)) {

    if (!post_process_skipped) {

      // If we did post_processing, copy directly from the new_mem buffer

      memcpy(afl->fsrv.shmem_fuzz, new_mem, new_size);

    } else {

      memcpy(afl->fsrv.shmem_fuzz, mem, skip_at);

      memcpy(afl->fsrv.shmem_fuzz, mem + skip_at + skip_len, tail_len);

    }

    *afl->fsrv.shmem_fuzz_len = new_size;

#ifdef _DEBUG
    if (afl->debug) {

      fprintf(
          stderr, "FS crc: %16llx len: %u\n",
          hash64(afl->fsrv.shmem_fuzz, *afl->fsrv.shmem_fuzz_len, HASH_CONST),
          *afl->fsrv.shmem_fuzz_len);
      fprintf(stderr, "SHM :");
      for (u32 i = 0; i < *afl->fsrv.shmem_fuzz_len; i++)
        fprintf(stderr, "%02x", afl->fsrv.shmem_fuzz[i]);
      fprintf(stderr, "\nORIG:");
      for (u32 i = 0; i < *afl->fsrv.shmem_fuzz_len; i++)
        fprintf(stderr, "%02x", (u8)((u8 *)mem)[i]);
      fprintf(stderr, "\n");

    }

#endif

    return;

  } else if (unlikely(!afl->fsrv.use_stdin)) {

    if (unlikely(afl->no_unlink)) {

      fd = open(afl->fsrv.out_file, O_WRONLY | O_CREAT | O_TRUNC,
                DEFAULT_PERMISSION);

    } else {

      unlink(afl->fsrv.out_file);                         /* Ignore errors. */
      fd = open(afl->fsrv.out_file, O_WRONLY | O_CREAT | O_EXCL,
                DEFAULT_PERMISSION);

    }

    if (fd < 0) { PFATAL("Unable to create '%s'", afl->fsrv.out_file); }

  } else {

    lseek(fd, 0, SEEK_SET);

  }

  if (!post_process_skipped) {

    ck_write(fd, new_mem, new_size, afl->fsrv.out_file);

  } else {

    ck_write(fd, mem, skip_at, afl->fsrv.out_file);

    ck_write(fd, mem + skip_at + skip_len, tail_len, afl->fsrv.out_file);

  }

  if (afl->fsrv.use_stdin) {

    if (ftruncate(fd, new_size)) { PFATAL("ftruncate() failed"); }
    lseek(fd, 0, SEEK_SET);

  } else {

    close(fd);

  }

}

/* Calibrate a new test case. This is done when processing the input directory
   to warn about flaky or otherwise problematic test cases early on; and when
   new paths are discovered to detect variable behavior and so on. */

u8 calibrate_case(afl_state_t *afl, struct queue_entry *q, u8 *use_mem,
                  u32 handicap, u8 from_queue) {

  if (unlikely(afl->shm.cmplog_mode)) { q->exec_cksum = 0; }

  u8 fault = 0;
  u32 use_tmout = afl->fsrv.exec_tmout;

  /* Be a bit more generous about timeouts when resuming sessions, or when
     trying to calibrate already-added finds. This helps avoid trouble due
     to intermittent latency. */

  if (!from_queue || afl->resuming_fuzz) {

    use_tmout = MAX(afl->fsrv.exec_tmout + CAL_TMOUT_ADD,
                    afl->fsrv.exec_tmout * CAL_TMOUT_PERC / 100);

  }

  ++q->cal_failed;

  afl->stage_name = "calibration";
  afl->stage_max = afl->afl_env.afl_cal_fast ? 3 : CAL_CYCLES;

  /* Make sure the forkserver is up before we do anything, and let's not
     count its spin-up time toward binary calibration. */

  if (!afl->fsrv.fsrv_pid) {

    if (afl->fsrv.cmplog_binary &&
        afl->fsrv.init_child_func != cmplog_exec_child) {

      FATAL("BUG in afl-fuzz detected. Cmplog mode not set correctly.");

    }

    afl_fsrv_start(&afl->fsrv, afl->argv, &afl->stop_soon,
                   afl->afl_env.afl_debug_child);

    if (afl->fsrv.support_shmem_fuzz && !afl->fsrv.use_shmem_fuzz) {

      afl_shm_deinit(afl->shm_fuzz);
      ck_free(afl->shm_fuzz);
      afl->shm_fuzz = NULL;
      afl->fsrv.support_shmem_fuzz = 0;
      afl->fsrv.shmem_fuzz = NULL;

    }

  }

  write_to_testcase(afl, use_mem, q->len);

  fault = fuzz_run_target(afl, &afl->fsrv, use_tmout);

  /*****************************************************
  * Capability Guided Fuzzing!
  *****************************************************/
  if (first_dry_run) {

    /* we only do the scan for only one time */
    scan_seed_capability(afl, q, use_mem);

  }

  q->cal_failed = 0;
  
  return fault;

}

/* Grab interesting test cases from other fuzzers. */

void sync_fuzzers(afl_state_t *afl) {

  DIR *          sd;
  struct dirent *sd_ent;
  u32            sync_cnt = 0, synced = 0, entries = 0;
  u8             path[PATH_MAX + 1 + NAME_MAX];

  sd = opendir(afl->sync_dir);
  if (!sd) { PFATAL("Unable to open '%s'", afl->sync_dir); }

  afl->stage_max = afl->stage_cur = 0;
  afl->cur_depth = 0;

  /* Look at the entries created for every other fuzzer in the sync directory.
   */

  while ((sd_ent = readdir(sd))) {

    u8  qd_synced_path[PATH_MAX], qd_path[PATH_MAX];
    u32 min_accept = 0, next_min_accept = 0;

    s32 id_fd;

    /* Skip dot files and our own output directory. */

    if (sd_ent->d_name[0] == '.' || !strcmp(afl->sync_id, sd_ent->d_name)) {

      continue;

    }

    entries++;

    // secondary nodes only syncs from main, the main node syncs from everyone
    if (likely(afl->is_secondary_node)) {

      sprintf(qd_path, "%s/%s/is_main_node", afl->sync_dir, sd_ent->d_name);
      int res = access(qd_path, F_OK);
      if (unlikely(afl->is_main_node)) {  // an elected temporary main node

        if (likely(res == 0)) {  // there is another main node? downgrade.

          afl->is_main_node = 0;
          sprintf(qd_path, "%s/is_main_node", afl->out_dir);
          unlink(qd_path);

        }

      } else {

        if (likely(res != 0)) { continue; }

      }

    }

    synced++;

    /* document the attempt to sync to this instance */

    sprintf(qd_synced_path, "%s/.synced/%s.last", afl->out_dir, sd_ent->d_name);
    id_fd =
        open(qd_synced_path, O_RDWR | O_CREAT | O_TRUNC, DEFAULT_PERMISSION);
    if (id_fd >= 0) close(id_fd);

    /* Skip anything that doesn't have a queue/ subdirectory. */

    sprintf(qd_path, "%s/%s/queue", afl->sync_dir, sd_ent->d_name);

    struct dirent **namelist = NULL;
    int             m = 0, n, o;

    n = scandir(qd_path, &namelist, NULL, alphasort);

    if (n < 1) {

      if (namelist) free(namelist);
      continue;

    }

    /* Retrieve the ID of the last seen test case. */

    sprintf(qd_synced_path, "%s/.synced/%s", afl->out_dir, sd_ent->d_name);

    id_fd = open(qd_synced_path, O_RDWR | O_CREAT, DEFAULT_PERMISSION);

    if (id_fd < 0) { PFATAL("Unable to create '%s'", qd_synced_path); }

    if (read(id_fd, &min_accept, sizeof(u32)) == sizeof(u32)) {

      next_min_accept = min_accept;
      lseek(id_fd, 0, SEEK_SET);

    }

    /* Show stats */

    snprintf(afl->stage_name_buf, STAGE_BUF_SIZE, "sync %u", ++sync_cnt);

    afl->stage_name = afl->stage_name_buf;
    afl->stage_cur = 0;
    afl->stage_max = 0;

    /* For every file queued by this fuzzer, parse ID and see if we have
       looked at it before; exec a test case if not. */

    u8 entry[12];
    sprintf(entry, "id:%06u", next_min_accept);

    while (m < n) {

      if (strncmp(namelist[m]->d_name, entry, 9)) {

        m++;

      } else {

        break;

      }

    }

    if (m >= n) { goto close_sync; }  // nothing new

    for (o = m; o < n; o++) {

      s32         fd;
      struct stat st;

      snprintf(path, sizeof(path), "%s/%s", qd_path, namelist[o]->d_name);
      afl->syncing_case = next_min_accept;
      next_min_accept++;

      /* Allow this to fail in case the other fuzzer is resuming or so... */

      fd = open(path, O_RDONLY);

      if (fd < 0) { continue; }

      if (fstat(fd, &st)) { WARNF("fstat() failed"); }

      /* Ignore zero-sized or oversized files. */

      if (st.st_size && st.st_size <= MAX_FILE) {

        u8  fault;
        u8 *mem = mmap(0, st.st_size, PROT_READ, MAP_PRIVATE, fd, 0);

        if (mem == MAP_FAILED) { PFATAL("Unable to mmap '%s'", path); }

        /* See what happens. We rely on save_if_interesting() to catch major
           errors and save the test case. */

        write_to_testcase(afl, mem, st.st_size);

        fault = fuzz_run_target(afl, &afl->fsrv, afl->fsrv.exec_tmout);

        if (afl->stop_soon) { goto close_sync; }

        afl->syncing_party = sd_ent->d_name;
        afl->queued_imported +=
            save_if_interesting(afl, mem, st.st_size, fault);
        afl->syncing_party = 0;

        munmap(mem, st.st_size);

      }

      close(fd);

    }

    ck_write(id_fd, &next_min_accept, sizeof(u32), qd_synced_path);

  close_sync:
    close(id_fd);
    if (n > 0)
      for (m = 0; m < n; m++)
        free(namelist[m]);
    free(namelist);

  }

  closedir(sd);

  // If we are a secondary and no main was found to sync then become the main
  if (unlikely(synced == 0) && likely(entries) &&
      likely(afl->is_secondary_node)) {

    // there is a small race condition here that another secondary runs at the
    // same time. If so, the first temporary main node running again will demote
    // themselves so this is not an issue

    //    u8 path2[PATH_MAX];
    afl->is_main_node = 1;
    sprintf(path, "%s/is_main_node", afl->out_dir);
    int fd = open(path, O_CREAT | O_RDWR, 0644);
    if (fd >= 0) { close(fd); }

  }

  if (afl->foreign_sync_cnt) read_foreign_testcases(afl, 0);

  afl->last_sync_time = get_cur_time();
  afl->last_sync_cycle = afl->queue_cycle;

}

/* Trim all new test cases to save cycles when doing deterministic checks. The
   trimmer uses power-of-two increments somewhere between 1/16 and 1/1024 of
   file size, to keep the stage short and sweet. */

u8 trim_case(afl_state_t *afl, struct queue_entry *q, u8 *in_buf) {

  u32 orig_len = q->len;

  /* Custom mutator trimmer */
  if (afl->custom_mutators_count) {

    u8   trimmed_case = 0;
    bool custom_trimmed = false;

    LIST_FOREACH(&afl->custom_mutator_list, struct custom_mutator, {

      if (el->afl_custom_trim) {

        trimmed_case = trim_case_custom(afl, q, in_buf, el);
        custom_trimmed = true;

      }

    });

    if (orig_len != q->len || custom_trimmed) {

      queue_testcase_retake(afl, q, orig_len);

    }

    if (custom_trimmed) return trimmed_case;

  }

  u8  needs_write = 0, fault = 0;
  u32 trim_exec = 0;
  u32 remove_len;
  u32 len_p2;

  u8 val_bufs[2][STRINGIFY_VAL_SIZE_MAX];

  /* Although the trimmer will be less useful when variable behavior is
     detected, it will still work to some extent, so we don't check for
     this. */

  if (q->len < 5) { return 0; }

  afl->stage_name = afl->stage_name_buf;
  afl->bytes_trim_in += q->len;

  /* Select initial chunk len, starting with large steps. */

  len_p2 = next_pow2(q->len);

  remove_len = MAX(len_p2 / TRIM_START_STEPS, (u32)TRIM_MIN_BYTES);

  /* Continue until the number of steps gets too high or the stepover
     gets too small. */

  while (remove_len >= MAX(len_p2 / TRIM_END_STEPS, (u32)TRIM_MIN_BYTES)) {

    u32 remove_pos = remove_len;

    sprintf(afl->stage_name_buf, "trim %s/%s",
            u_stringify_int(val_bufs[0], remove_len),
            u_stringify_int(val_bufs[1], remove_len));

    afl->stage_cur = 0;
    afl->stage_max = q->len / remove_len;

    while (remove_pos < q->len) {

      u32 trim_avail = MIN(remove_len, q->len - remove_pos);
      u64 cksum;

      write_with_gap(afl, in_buf, q->len, remove_pos, trim_avail);

      fault = fuzz_run_target(afl, &afl->fsrv, afl->fsrv.exec_tmout);

      if (afl->stop_soon || fault == FSRV_RUN_ERROR) { goto abort_trimming; }

      /* Note that we don't keep track of crashes or hangs here; maybe TODO?
       */

      ++afl->trim_execs;
      classify_counts(&afl->fsrv);
      cksum = hash64(afl->fsrv.trace_bits, afl->fsrv.map_size, HASH_CONST);

      /* If the deletion had no impact on the trace, make it permanent. This
         isn't perfect for variable-path inputs, but we're just making a
         best-effort pass, so it's not a big deal if we end up with false
         negatives every now and then. */

      if (cksum == q->exec_cksum) {

        u32 move_tail = q->len - remove_pos - trim_avail;

        q->len -= trim_avail;
        len_p2 = next_pow2(q->len);

        memmove(in_buf + remove_pos, in_buf + remove_pos + trim_avail,
                move_tail);

        /* Let's save a clean trace, which will be needed by
           update_bitmap_score once we're done with the trimming stuff. */

        if (!needs_write) {

          needs_write = 1;
          memcpy(afl->clean_trace, afl->fsrv.trace_bits, afl->fsrv.map_size);

        }

      } else {

        remove_pos += remove_len;

      }

      /* Since this can be slow, update the screen every now and then. */

      if (!(trim_exec++ % afl->stats_update_freq)) { show_stats(afl); }
      ++afl->stage_cur;

    }

    remove_len >>= 1;

  }

  /* If we have made changes to in_buf, we also need to update the on-disk
     version of the test case. */

  if (needs_write) {

    s32 fd;

    if (unlikely(afl->no_unlink)) {

      fd = open(q->fname, O_WRONLY | O_CREAT | O_TRUNC, DEFAULT_PERMISSION);

      if (fd < 0) { PFATAL("Unable to create '%s'", q->fname); }

      u32 written = 0;
      while (written < q->len) {

        ssize_t result = write(fd, in_buf, q->len - written);
        if (result > 0) written += result;

      }

    } else {

      unlink(q->fname);                                    /* ignore errors */
      fd = open(q->fname, O_WRONLY | O_CREAT | O_EXCL, DEFAULT_PERMISSION);

      if (fd < 0) { PFATAL("Unable to create '%s'", q->fname); }

      ck_write(fd, in_buf, q->len, q->fname);

    }

    close(fd);

    queue_testcase_retake_mem(afl, q, in_buf, q->len, orig_len);

    memcpy(afl->fsrv.trace_bits, afl->clean_trace, afl->fsrv.map_size);
    update_bitmap_score(afl, q);

  }

abort_trimming:

  afl->bytes_trim_out += q->len;
  return fault;

}

/* Write a modified test case, run program, process results. Handle
   error conditions, returning 1 if it's time to bail out. This is
   a helper function for fuzz_one(). */

u8 __attribute__((hot))
common_fuzz_stuff(afl_state_t *afl, u8 *out_buf, u32 len) {

  u8 fault;

  write_to_testcase(afl, out_buf, len);

  // PACAPR
  setenv("PAC_INTERNAL_PATCH_ID", "0", 1);

  fault = fuzz_run_target(afl, &afl->fsrv, afl->fsrv.exec_tmout);

  // PACAPR
  if (fault == FSRV_RUN_OK) {
    u8 has_unique_state = 0;
    if (access(afl->state_file_path, F_OK) == 0) {
      has_unique_state = 1;
    }

    u8 has_branch_trace = 0;
    u8 original_branch_trace[1000] = {'\0'};
    if (access(afl->branch_file_path, F_OK) == 0) {
      FILE* file = fopen(afl->branch_file_path, "r");
      if (file == NULL) {
        PFATAL("File exist, but failed to open branch file: %s", afl->branch_file_path);
      }
      fgets(original_branch_trace, sizeof(original_branch_trace), file);
      fclose(file);
      has_branch_trace = 1;
    }

    // Run patched program and collect the result, program state and branch trace
    if (has_unique_state || has_branch_trace) {
      u8 patch_id_str[12];
      sprintf(patch_id_str, "%d", afl->patch_id);
      setenv("PAC_INTERNAL_PATCH_ID", patch_id_str, 1); // Set patch ID to run patched version
      u8* trace_bits_backup = ck_alloc(afl->fsrv.map_size);
      memcpy(trace_bits_backup, afl->fsrv.trace_bits, afl->fsrv.map_size); // Backup previous trace bits
      write_to_testcase(afl, out_buf, len); // Write testcase again
      fsrv_run_result_t patched_result = fuzz_run_target(afl, &afl->fsrv, afl->fsrv.exec_tmout);
      memcpy(afl->fsrv.trace_bits, trace_bits_backup, afl->fsrv.map_size);
      free(trace_bits_backup); // Restore previous trace bits

      if (patched_result == FSRV_RUN_OK) {
        // 1. Check program state. If the state is unique, store it. If max unique state found, stop fuzzing.
        if (access(afl->state_file_path, F_OK) == 0) {
          // Get program state from state file
          FILE* file = fopen(afl->state_file_path, "r");
          if (file == NULL) {
            PFATAL("File exist, but failed to open state file: %s", afl->state_file_path);
          }
          u8 patched_state[256];
          fgets(patched_state, sizeof(patched_state), file);
          fclose(file);

          // Check current program state is unique
          if (set_contains(afl->patch_loc_reached_set, patched_state) == SET_FALSE) {
            afl->patch_loc_reached_count++;
            set_add(afl->patch_loc_reached_set, patched_state);
            has_unique_state = 1;

            // Store unique program state
            u8 fn[PATH_MAX];
            #ifndef SIMPLE_FILES
            snprintf(fn, PATH_MAX, "%s/unique-states/id:%06u,time:%llu", afl->out_dir,
                    afl->patch_loc_reached_count, get_cur_time() + afl->prev_run_time - afl->start_time);
            #else
            snprintf(fn, PATH_MAX, "%s/unique-states/id_%06u", afl->out_dir,
                    afl->patch_loc_reached_count);
            #endif
            s32 fd = open(fn, O_WRONLY | O_CREAT | O_EXCL, DEFAULT_PERMISSION);
            if (unlikely(fd < 0)) { PFATAL("Unable to create '%s'", fn); }
            ck_write(fd, out_buf, len, fn);
            close(fd);

            // Check max patch location reached
            if (afl->patch_loc_reached_count >= afl->max_patch_loc_reached) {
              OKF("Reached patched location %u times, stopping fuzzing.", afl->patch_loc_reached_count);
              afl->stop_soon = 2;
            }
          }
        }

        // 2. Check branch trace. If the branch trace is different from the original binary, it is regression error.
        if (access(afl->branch_file_path, F_OK) == 0) {
          FILE* file = fopen(afl->branch_file_path, "r");
          if (file == NULL) {
            PFATAL("File exist, but failed to open branch file: %s", afl->branch_file_path);
          }
          u8 cur_branch_trace[1000];
          fgets(cur_branch_trace, sizeof(cur_branch_trace), file);
          fclose(file);

          if (strcmp(cur_branch_trace, original_branch_trace) != 0) {
            // Buggy and patched program has different branch trace. Patch is unsafe; stop fuzzer here.
            OKF("Program has regression error. Patched and buggy program has different branch trace. Stopping fuzzer.");
            // Store crashed input
            u8 fn[PATH_MAX];
#ifndef SIMPLE_FILES
            snprintf(fn, PATH_MAX, "%s/crashes/id:%06llu,sig:%02u,%s", afl->out_dir,
                    afl->saved_crashes, afl->fsrv.last_kill_signal,
                    describe_op(afl, 0, NAME_MAX - strlen("id:000000,sig:00,")));
#else
            snprintf(fn, PATH_MAX, "%s/crashes/id_%06llu_%02u", afl->out_dir,
                    afl->saved_crashes, afl->fsrv.last_kill_signal);
#endif
            ++afl->saved_crashes;
            s32 fd = open(fn, O_WRONLY | O_CREAT | O_EXCL, DEFAULT_PERMISSION);
            if (unlikely(fd < 0)) { PFATAL("Unable to create '%s'", fn); }
            ck_write(fd, out_buf, len, fn);
            close(fd);
            afl->stop_soon = 2;
          }
        }
        else {
          // Should not happen. If the input executed patched location, the branch file should exist in buggy program too.
          WARNF("Branch file exists in patched program, but not in buggy program! Skip.");
        }
      }
      // 3. Check the input passes buggy program
      //    If the input crashes the patched program but not the buggy program, it is regression error.
      else if (patched_result == FSRV_RUN_CRASH) {
        OKF("Program has regression error. Test input crashed in patched program, but not in original program. Stopping fuzzer.");
        // Store crashed input
        u8 fn[PATH_MAX];
#ifndef SIMPLE_FILES
        snprintf(fn, PATH_MAX, "%s/crashes/id:%06llu,sig:%02u,%s", afl->out_dir,
                afl->saved_crashes, afl->fsrv.last_kill_signal,
                describe_op(afl, 0, NAME_MAX - strlen("id:000000,sig:00,")));
#else
        snprintf(fn, PATH_MAX, "%s/crashes/id_%06llu_%02u", afl->out_dir,
                afl->saved_crashes, afl->fsrv.last_kill_signal);
#endif
        ++afl->saved_crashes;
        s32 fd = open(fn, O_WRONLY | O_CREAT | O_EXCL, DEFAULT_PERMISSION);
        if (unlikely(fd < 0)) { PFATAL("Unable to create '%s'", fn); }
        ck_write(fd, out_buf, len, fn);
        close(fd);
        afl->stop_soon = 2;
      }
      else if (patched_result == FSRV_RUN_TMOUT) {
        OKF("Program has regression error. Test input timed out in patched program, but not in original program. Stopping fuzzer.");
        // Store crashed input
        u8 fn[PATH_MAX];
#ifndef SIMPLE_FILES
        snprintf(fn, PATH_MAX, "%s/crashes/id:%06llu,sig:%02u,%s", afl->out_dir,
                afl->saved_crashes, afl->fsrv.last_kill_signal,
                describe_op(afl, 0, NAME_MAX - strlen("id:000000,sig:00,")));
#else
        snprintf(fn, PATH_MAX, "%s/crashes/id_%06llu_%02u", afl->out_dir,
                afl->saved_crashes, afl->fsrv.last_kill_signal);
#endif
        ++afl->saved_crashes;
        s32 fd = open(fn, O_WRONLY | O_CREAT | O_EXCL, DEFAULT_PERMISSION);
        if (unlikely(fd < 0)) { PFATAL("Unable to create '%s'", fn); }
        ck_write(fd, out_buf, len, fn);
        close(fd);

        afl->stop_soon = 2;
      }
    }
    setenv("PAC_INTERNAL_PATCH_ID", "0", 1); // Reset patch ID to run buggy version
  }

  if (afl->stop_soon) { return 1; }

  if (fault == FSRV_RUN_TMOUT) {

    if (afl->subseq_tmouts++ > TMOUT_LIMIT) {

      ++afl->cur_skipped_paths;
      return 1;

    }

  } else {

    afl->subseq_tmouts = 0;

  }

  /* Users can hit us with SIGUSR1 to request the current input
     to be abandoned. */

  if (afl->skip_requested) {

    afl->skip_requested = 0;
    ++afl->cur_skipped_paths;
    return 1;

  }

  /* This handles FAULT_ERROR for us: */

  afl->queued_discovered += save_if_interesting(afl, out_buf, len, fault);

  if (!(afl->stage_cur % afl->stats_update_freq) ||
      afl->stage_cur + 1 == afl->stage_max) {

    show_stats(afl);

  }

  return 0;

}


// Copyright 2022 Google LLC

#include <errno.h>
#include <limits.h>
#include <poll.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/inotify.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

extern char **environ;

// poll() timeout for inotify events, in milliseconds;
// run callback after this delay since the last run, even if there're no events.
const int kPollTimeout = 2000;

char buf[1024 * (sizeof(struct inotify_event) + NAME_MAX + 1)];

void run_callback_internal(char** callback) {
  fflush(stdout);  // avoid mixing with callback output.

  pid_t pid = fork();
  if (pid == -1) {
    perror("fork");
    return;  // let it retry at the next event or timeout.
  }

  if (pid == 0) {
    execve(callback[0], callback, environ);
    perror("execve");
    exit(EXIT_FAILURE);
  }

  int status;
  do {
    int w = waitpid(pid, &status, 0);
    if (w == -1) {
      if (errno == EINTR) {
        continue;
      }
      perror("waitpid");
      exit(EXIT_FAILURE);  // shouldn't happen; don't risk leaking zombies.
    }
  } while (!WIFEXITED(status) && !WIFSIGNALED(status));

  if (WIFEXITED(status)) {
    printf("inotify: %s exited with status %d (exit: %d)\n",
           callback[0], status, WEXITSTATUS(status));
  } else if (WIFSIGNALED(status)) {
    printf("inotify: %s exited with status %d (signal: %d)\n",
           callback[0], status, WTERMSIG(status));
  } else {
    printf("inotify: %s exited with status %d\n", callback[0], status);
  }

  if (WIFEXITED(status) && WEXITSTATUS(status) == EXIT_SUCCESS) {
    exit(EXIT_SUCCESS);
  }
}

// run_callback runs the callback if always is true, or it has been kPollTimeout
// milliseconds since 'last', which is updated after callback runs.
void run_callback(char** callback, struct timespec *last, bool always) {
  if (!always) {
    struct timespec tp;
    int ret = clock_gettime(CLOCK_MONOTONIC, &tp);
    if (ret != 0) {
      perror("clock_gettime");
      exit(EXIT_FAILURE);
    }

    int diff_milliseconds = (tp.tv_sec - last->tv_sec) * 1000 \
                   + (tp.tv_nsec - last->tv_nsec) / 1000000;
    if (diff_milliseconds < kPollTimeout) {
      return;
    }

    printf("inotify: calling %s after %dms since the last run\n",
           callback[0], diff_milliseconds);
  }

  run_callback_internal(callback);

  int ret = clock_gettime(CLOCK_MONOTONIC, last);
  if (ret != 0) {
    perror("clock_gettime");
    exit(EXIT_FAILURE);
  }
}

int main(int argc, char* argv[]) {
  if (argc < 4) {
    printf("Usage: %s path file callback [callback-arg]...\n", argv[0]);
    printf("This utility watches inotify events at 'path', "
           "optionally filtered by file name 'file',\n"
           "and calls 'callback' with 'callback-arg' "
           "upon inotify events firing. Additionally,\n"
           "'callback' is also called at start up or "
           "every %d milliseconds if no inotify event fires.\n"
           "This program exits as success when 'callback' "
           "exits as success, or keeps running otherwise.\n",
           kPollTimeout);
    exit(EXIT_FAILURE);
  }

  char** callback = argv + 3;
  struct pollfd fds;

  fds.fd = inotify_init1(IN_NONBLOCK | IN_CLOEXEC);
  if (fds.fd == -1) {
    perror("inotify_init1");
    exit(EXIT_FAILURE);
  }

  fds.events = POLLIN;

  // flags taken from Golang fsnotify.
  uint32_t flags = IN_MOVED_TO | IN_MOVED_FROM | IN_CREATE | IN_ATTRIB
                   | IN_MODIFY | IN_MOVE_SELF | IN_DELETE | IN_DELETE_SELF;
  int wd = inotify_add_watch(fds.fd, argv[1], flags);
  if (wd == -1) {
    perror("inotify_add_watch");
    exit(EXIT_FAILURE);
  }

  struct timespec tp;
  printf("inotify: calling %s as initial run\n", callback[0]);
  run_callback(callback, &tp, true);

  for (;;) {
    // inotify(7) states several limitations and polling the filesystem (or
    // calling the callback in our case) in addition to inotify is required.
    // We utilize the 'timeout' parameter to poll(2) to achieve it by running
    // the callback at each time out event.
    int ret = poll(&fds, 1, kPollTimeout);
    if (ret == -1) {
      if (errno == EINTR) {
        run_callback(callback, &tp, false);
        continue;
      }
      perror("poll");
      exit(EXIT_FAILURE);
    }

    if (ret == 0) {
      run_callback(callback, &tp, false);
      continue;
    }

    int matches = 0;
    for (;;) {
      ssize_t len = read(fds.fd, buf, sizeof(buf));
      if (len == -1) {
        if (errno == EINTR) {
          continue;
        }
        if (errno == EAGAIN) {
          break;
        }
        perror("read");
        exit(EXIT_FAILURE);
      }

      const struct inotify_event *event;
      for (char *ptr = buf; ptr < buf + len;
           ptr += sizeof(struct inotify_event) + event->len) {
        event = (const struct inotify_event *)ptr;

        if (argv[2][0] == '\0' ||
            (event->len > 0 && strcmp(event->name, argv[2]) == 0)) {
          matches++;
        }
      }
    }

    if (matches == 0) {
      run_callback(callback, &tp, false);
      continue;
    }

    printf("inotify: calling %s for %d matching event(s)\n",
           callback[0], matches);
    run_callback(callback, &tp, true);
  }
}

/* Test-only POSIX fault hook, compiled into a private temporary directory.
 * SQLite's Unix VFS deletes the super-journal at the multi-file commit point:
 * https://www.sqlite.org/atomiccommit.html#delete_the_super_journal_file
 * Stop BEFORE that unlink; never manufacture a journal or replace SQLite I/O.
 * A missing compiler, ignored loader injection, or changed VFS must fail the
 * calling test. This source and its compiled library are not shipped.
 */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>
#ifndef __APPLE__
#include <dlfcn.h>
#endif

static void marker(const char *value) {
  size_t size = strlen(value);
  if (write(3, value, size) != (ssize_t)size) _exit(190);
}

__attribute__((constructor)) static void loaded(void) {
  if (getenv("AGENT_GUARD_TEST_MJ_DATABASE")) marker("HOOK_LOADED\n");
}

static void before_unlink(int directory, const char *path, int flags) {
  int saved_errno = errno;
  const char *armed = getenv("AGENT_GUARD_TEST_MJ_ARMED");
  const char *database = getenv("AGENT_GUARD_TEST_MJ_DATABASE");
  if (armed && strcmp(armed, "1") == 0 && database && path &&
      database[0] == '/' && path[0] == '/' && flags == 0) {
    size_t prefix = strlen(database), length = strlen(path);
    /* The suffix is deliberately bounded, not a promise about future SQLite
     * names. The parent also verifies the real journal's two-way references. */
    int matches = length > prefix + 3 && length <= prefix + 35 &&
      memcmp(path, database, prefix) == 0 && memcmp(path + prefix, "-mj", 3) == 0;
    if (matches) {
      for (size_t i = prefix + 3; i < length; i++) {
        char c = path[i];
        if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') ||
              (c >= 'A' && c <= 'F'))) matches = 0;
      }
    }
    if (matches) {
      struct stat held, named;
      int fd = openat(directory, path, O_RDONLY | O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK);
      if (fd < 0 || fstat(fd, &held) != 0 ||
          fstatat(directory, path, &named, AT_SYMLINK_NOFOLLOW) != 0 ||
          !S_ISREG(held.st_mode) || !S_ISREG(named.st_mode) ||
          held.st_uid != geteuid() || held.st_nlink != 1 ||
          held.st_size <= 0 || held.st_size > 65536 ||
          held.st_dev != named.st_dev || held.st_ino != named.st_ino) {
        marker("HOOK_INVALID_JOURNAL\n");
        _exit(191);
      }
      marker("HOOK_BEFORE_SUPER_JOURNAL_UNLINK\n");
      /* Keep the verified descriptor open until process death. No return to
       * SQLite, signal handler, parent callback, sleep, or filesystem watcher. */
      kill(getpid(), SIGKILL);
      _exit(192);
    }
  }
  errno = saved_errno;
}

#ifdef __APPLE__
static int guarded_unlink(const char *path) {
  before_unlink(AT_FDCWD, path, 0);
  return unlink(path);
}
static int guarded_unlinkat(int directory, const char *path, int flags) {
  before_unlink(directory, path, flags);
  return unlinkat(directory, path, flags);
}
__attribute__((used, section("__DATA,__interpose")))
static const struct { const void *replacement; const void *original; } hooks[] = {
  { (const void *)guarded_unlink, (const void *)unlink },
  { (const void *)guarded_unlinkat, (const void *)unlinkat },
};
#else
int unlink(const char *path) {
  int saved_errno = errno;
  int (*original)(const char *) = (int (*)(const char *))dlsym(RTLD_NEXT, "unlink");
  if (!original) _exit(193);
  errno = saved_errno;
  before_unlink(AT_FDCWD, path, 0);
  return original(path);
}
int unlinkat(int directory, const char *path, int flags) {
  int saved_errno = errno;
  int (*original)(int, const char *, int) = (int (*)(int, const char *, int))dlsym(RTLD_NEXT, "unlinkat");
  if (!original) _exit(194);
  errno = saved_errno;
  before_unlink(directory, path, flags);
  return original(directory, path, flags);
}
#endif

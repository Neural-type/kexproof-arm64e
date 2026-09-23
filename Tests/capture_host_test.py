#!/usr/bin/env python3
"""Exercise the actual portable capture functions, without UIKit or exploit code.

Run on a POSIX host with Python 3 and a C11 compiler:
    python3 Tests/capture_host_test.py
Only the Objective-C line decoder is replaced by a draining/forwarding reader.
"""
import os
from pathlib import Path
import subprocess
import tempfile


source = (Path(__file__).resolve().parents[1] / "Sources/KPRunner.m").read_text()
capture = source[source.index("static int gOrigStdout") : source.index("static void kpAppendCapturedLine")]
capture += source[source.index("static void kpStartCapture(void)") : source.index("void KPForwardToOriginalStderr(NSString *line)")]

prefix = r'''
#define _GNU_SOURCE
#include <assert.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <signal.h>
#include <stdarg.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>
typedef int BOOL;
#define YES 1
#define NO 0
enum { DUPLICATE = 1, PIPE, SET_FLAGS, REPLACE, CREATE, READ, WRITE };
static atomic_int failure_kind, failure_remaining, failure_errno;
static atomic_int reader_count, bytes_read;
static atomic_int write_chunk_limit;
static int report_fd;
static void fail_check(const char *condition, int line) {
    dprintf(report_fd, "FAIL at line %d: %s\n", line, condition);
    _exit(1);
}
#define CHECK(condition) do { if (!(condition)) fail_check(#condition, __LINE__); } while (0)
static int inject(int kind) {
    if (atomic_load(&failure_kind) != kind) return 0;
    if (atomic_fetch_sub(&failure_remaining, 1) != 1) return 0;
    errno = atomic_load(&failure_errno);
    return 1;
}
static void arm(int kind, int nth, int error) {
    atomic_store(&failure_remaining, nth);
    atomic_store(&failure_errno, error);
    atomic_store(&failure_kind, kind);
}
static int test_fcntl(int fd, int command, ...) {
    va_list arguments;
    va_start(arguments, command);
    int value = va_arg(arguments, int);
    va_end(arguments);
    if (inject(command == F_DUPFD_CLOEXEC ? DUPLICATE : SET_FLAGS)) return -1;
    return fcntl(fd, command, value);
}
static int test_pipe(int fds[2]) {
    if (inject(PIPE)) return -1;
    return pipe(fds);
}
static int test_dup2(int source_fd, int destination) {
    if (inject(REPLACE)) return -1;
    return dup2(source_fd, destination);
}
static int test_pthread_create(pthread_t *thread, const pthread_attr_t *attributes,
                               void *(*function)(void *), void *argument) {
    if (inject(CREATE)) return EAGAIN;
    return pthread_create(thread, attributes, function, argument);
}
static ssize_t test_read(int fd, void *buffer, size_t length) {
    if (inject(READ)) return -1;
    return read(fd, buffer, length);
}
static ssize_t test_write(int fd, const void *buffer, size_t length) {
    if (inject(WRITE)) return -1;
    int limit = atomic_load(&write_chunk_limit);
    if (limit > 0 && length > (size_t)limit) length = (size_t)limit;
    return write(fd, buffer, length);
}
static void *kpReaderMain(void *argument);
#define fcntl test_fcntl
#define pipe test_pipe
#define dup2 test_dup2
#define pthread_create test_pthread_create
#define read test_read
#define write test_write
'''

suffix = r'''
#undef fcntl
#undef pipe
#undef dup2
#undef pthread_create
#undef read
#undef write
static void *kpReaderMain(void *argument) {
    atomic_fetch_add(&reader_count, 1);
    unsigned char buffer[2048];
    ssize_t count;
    while ((count = kpReadCapture((int)(intptr_t)argument, buffer, sizeof(buffer))) > 0) {
        atomic_fetch_add(&bytes_read, (int)count);
        // Exercise the same reentry used by KPLog.append during flush/join.
        kpWriteOriginalStderr("reader-forward");
    }
    atomic_fetch_sub(&reader_count, 1);
    return NULL;
}
static int descriptor_count(void) {
    DIR *directory = opendir("/proc/self/fd");
    CHECK(directory != NULL);
    int count = 0;
    struct dirent *entry;
    while ((entry = readdir(directory))) {
        if (entry->d_name[0] != '.') count++;
    }
    closedir(directory);
    return count;
}
static void check_inactive(void) {
    CHECK(!gCapturing);
    CHECK(gOrigStdout == -1 && gOrigStderr == -1);
    CHECK(gPipeFds[0] == -1 && gPipeFds[1] == -1);
    CHECK(atomic_load(&reader_count) == 0);
}
static void check_same_descriptor(int first, int second) {
    struct stat a, b;
    CHECK(fstat(first, &a) == 0 && fstat(second, &b) == 0);
    CHECK(a.st_dev == b.st_dev && a.st_ino == b.st_ino);
}
static void *forward_stress(void *argument) {
    (void)argument;
    for (int i = 0; i < 15000; ++i) kpWriteOriginalStderr("concurrent forward");
    return NULL;
}
static void *lifecycle_stress(void *argument) {
    (void)argument;
    for (int i = 0; i < 300; ++i) {
        kpStartCapture();
        CHECK(write(STDOUT_FILENO, "capture\n", 8) == 8);
        kpStopCapture();
    }
    return NULL;
}
int main(void) {
    alarm(30); // A join/pipe deadlock must fail the test, never hang indefinitely.
    report_fd = dup(STDOUT_FILENO);
    CHECK(report_fd >= 3);
    int sink = open("/dev/null", O_WRONLY);
    CHECK(sink >= 3);
    CHECK(dup2(sink, STDOUT_FILENO) >= 0 && dup2(sink, STDERR_FILENO) >= 0);
    static char stdout_buffer[65536];
    CHECK(setvbuf(stdout, stdout_buffer, _IOFBF, sizeof(stdout_buffer)) == 0);
    int baseline = descriptor_count();

    const int failures[][2] = {
        {DUPLICATE, 1}, {DUPLICATE, 2}, {PIPE, 1}, {SET_FLAGS, 1},
        {SET_FLAGS, 2}, {CREATE, 1}, {REPLACE, 1}, {REPLACE, 2}
    };
    for (size_t i = 0; i < sizeof(failures) / sizeof(failures[0]); ++i) {
        arm(failures[i][0], failures[i][1], EIO);
        kpStartCapture();
        arm(0, 0, 0);
        check_inactive();
        check_same_descriptor(STDOUT_FILENO, sink);
        check_same_descriptor(STDERR_FILENO, sink);
        CHECK(descriptor_count() == baseline);
    }
    dprintf(report_fd, "PASS: eight startup failures restore descriptors without leaks\n");

    CHECK(close(STDERR_FILENO) == 0);
    kpStartCapture();
    check_inactive();
    CHECK(fcntl(STDERR_FILENO, F_GETFD) == -1 && errno == EBADF);
    CHECK(dup2(sink, STDERR_FILENO) >= 0);
    CHECK(descriptor_count() == baseline);
    dprintf(report_fd, "PASS: closed stderr is not mistaken for a duplicate of stdout\n");

    for (int which = 1; which <= 2; ++which) {
        kpStartCapture();
        CHECK(gCapturing);
        arm(REPLACE, which, EIO);
        kpStopCapture();
        arm(0, 0, 0);
        check_inactive();
        CHECK(fcntl(which, F_GETFD) < 0 && errno == EBADF);
        CHECK(dup2(sink, which) >= 0);
        CHECK(descriptor_count() == baseline);
    }
    dprintf(report_fd, "PASS: either restore failure closes its pipe alias and join finishes\n");

    for (int operation = DUPLICATE; operation <= REPLACE; operation += REPLACE - DUPLICATE) {
        arm(operation, 1, EINTR);
        kpStartCapture();
        CHECK(gCapturing);
        arm(0, 0, 0);
        kpStopCapture();
        check_inactive();
    }
    int retry_pipe[2];
    CHECK(pipe(retry_pipe) == 0);
    CHECK(write(retry_pipe[1], "x", 1) == 1);
    arm(READ, 1, EINTR);
    char byte = 0;
    CHECK(kpReadCapture(retry_pipe[0], &byte, 1) == 1 && byte == 'x');
    arm(0, 0, 0);
    close(retry_pipe[0]);
    close(retry_pipe[1]);
    dprintf(report_fd, "PASS: duplicate, redirect and read retry EINTR\n");

    FILE *output = tmpfile();
    CHECK(output != NULL);
    CHECK(dup2(fileno(output), STDERR_FILENO) >= 0);
    arm(WRITE, 1, EINTR);
    atomic_store(&write_chunk_limit, 2);
    kpWriteOriginalStderr("complete line");
    arm(0, 0, 0);
    atomic_store(&write_chunk_limit, 0);
    CHECK(fseek(output, 0, SEEK_SET) == 0);
    char record[32] = {0};
    CHECK(fread(record, 1, sizeof(record), output) == 14);
    CHECK(strcmp(record, "complete line\n") == 0);
    CHECK(dup2(sink, STDERR_FILENO) >= 0);
    fclose(output);
    dprintf(report_fd, "PASS: forwarding handles partial writes and EINTR\n");

    kpStartCapture();
    CHECK(gCapturing);
    int saved_stderr = gOrigStderr;
    int active_count = descriptor_count();
    kpStartCapture();
    CHECK(descriptor_count() == active_count);
    atomic_store(&bytes_read, 0);
    char block[8192];
    memset(block, 'x', sizeof(block));
    for (int i = 0; i < 128; ++i) CHECK(fwrite(block, 1, sizeof(block), stdout) == sizeof(block));
    kpStopCapture();
    CHECK(atomic_load(&bytes_read) == 128 * (int)sizeof(block));
    kpStopCapture();
    check_inactive();
    CHECK(descriptor_count() == baseline);
    output = tmpfile();
    CHECK(output != NULL);
    CHECK(dup2(fileno(output), saved_stderr) == saved_stderr);
    kpWriteOriginalStderr("must not reach reused fd");
    CHECK(lseek(fileno(output), 0, SEEK_END) == 0);
    if (fileno(output) != saved_stderr) close(saved_stderr);
    fclose(output);
    CHECK(descriptor_count() == baseline);
    dprintf(report_fd, "PASS: full-pipe flush/join, idempotence and reused-fd regression\n");

    pthread_t forwarders[4], lifecycles[2];
    for (int i = 0; i < 4; ++i) CHECK(pthread_create(&forwarders[i], NULL, forward_stress, NULL) == 0);
    for (int i = 0; i < 2; ++i) CHECK(pthread_create(&lifecycles[i], NULL, lifecycle_stress, NULL) == 0);
    for (int i = 0; i < 4; ++i) CHECK(pthread_join(forwarders[i], NULL) == 0);
    for (int i = 0; i < 2; ++i) CHECK(pthread_join(lifecycles[i], NULL) == 0);
    check_inactive();
    CHECK(descriptor_count() == baseline);
    dprintf(report_fd, "PASS: concurrent lifecycle and 60000 forwards, no descriptor leaks\n");
    return 0;
}
'''

with tempfile.TemporaryDirectory(prefix="kexproof-capture-test-") as directory:
    test_source = Path(directory) / "capture_test.c"
    executable = Path(directory) / "capture_test"
    test_source.write_text(prefix + capture + suffix)
    subprocess.run([
        os.environ.get("CC", "cc"), "-std=c11", "-Wall", "-Wextra", "-Werror",
        "-pthread", str(test_source), "-o", str(executable),
    ], check=True)
    subprocess.run([str(executable)], check=True, timeout=40)

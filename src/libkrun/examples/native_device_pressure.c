/* Explicit standalone helper, built by Main with cc -O2 -pthread -static.
 * Its memory and open files are part of the actual ordinary-kernel capture.
 */
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <linux/vm_sockets.h>
#include <linux/fs.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>

#define PACKET_MAGIC UINT64_C(0x5052455353555245)
#define ECHO_MAGIC UINT64_C(0x484f53544543484f)
#define RECORD_WORDS 512
#define RECORD_SLOTS 64
struct packet { uint64_t magic, token, sequence, phase, sent_ns, echo; };
struct context {
    pthread_mutex_t lock;
    pthread_mutex_t output;
    atomic_int failed;
    atomic_int stop;
    uint64_t disk[2], disk_checks;
    uint64_t disk_capacity[2];
    int disk_readonly[2];
    char disk_serial[2][129];
    uint64_t network_token, network_phase, tx[3], rx[3], stale_rx;
    uint64_t network_generation, network_seen_generation;
    uint64_t injected_rx, injected_last, injected_faults;
    unsigned host_port;
    uint64_t guest_connects, guest_bytes;
    uint64_t retained_probes, reset_observed;
    int retained_fd;
};
struct disk_argument { struct context *context; unsigned index; };
static uint64_t now_ns(void) {
    struct timespec value;
    if (clock_gettime(CLOCK_MONOTONIC, &value)) return 0;
    return (uint64_t)value.tv_sec * UINT64_C(1000000000) + (uint64_t)value.tv_nsec;
}
static void pause_ms(unsigned milliseconds) {
    struct timespec wait = {milliseconds / 1000, (long)(milliseconds % 1000) * 1000000};
    while (nanosleep(&wait, &wait) && errno == EINTR) {}
}
static void emit_record(struct context *context, const char *format, ...)
    __attribute__((format(printf, 2, 3)));
static void emit_record(struct context *context, const char *format, ...) {
    char record[2048];
    va_list arguments;
    va_start(arguments, format);
    int length = vsnprintf(record, sizeof(record), format, arguments);
    va_end(arguments);
    if (length < 0 || (size_t)length >= sizeof(record)) {
        atomic_store(&context->failed, 1);
        _exit(120);
    }
    pthread_mutex_lock(&context->output);
    ssize_t written = write(STDOUT_FILENO, record, (size_t)length);
    if (written != length) {
        atomic_store(&context->failed, 1);
        _exit(121);
    }
    pthread_mutex_unlock(&context->output);
}

static void failure(struct context *context, const char *operation) {
    int error = errno;
    atomic_store(&context->failed, 1);
    emit_record(context, "FAIL pressure-%s errno=%d\n", operation, error);
}
static uint64_t word(unsigned disk, uint64_t sequence, unsigned index) {
    return UINT64_C(0xd15c53494c4f0000) ^ ((uint64_t)disk << 48) ^ sequence ^ ((uint64_t)index << 32);
}
static int disk_open(unsigned index) {
    char path[80];
    snprintf(path, sizeof(path), "/disk%u/numbered-records", index);
    if (access(path, F_OK)) return -1;
    snprintf(path, sizeof(path), "/disk%u/pressure-records", index);
    return open(path, O_CREAT | O_RDWR | O_CLOEXEC | O_DSYNC, 0600);
}
static void *disk_work(void *opaque) {
    struct disk_argument *argument = opaque;
    struct context *context = argument->context;
    unsigned disk = argument->index;
    int fd;
    do {
        fd = disk_open(disk);
        if (fd >= 0) break;
        if (errno != ENOENT) { failure(context, "disk-open"); return NULL; }
        pause_ms(10);
    } while (!atomic_load(&context->stop));
    if (fd < 0) return NULL;
    while (!atomic_load(&context->stop)) {
        uint64_t record[RECORD_WORDS], observed[RECORD_WORDS];
        pthread_mutex_lock(&context->lock);
        uint64_t sequence = context->disk[disk] + 1;
        for (unsigned i = 0; i < RECORD_WORDS; ++i) record[i] = word(disk, sequence, i);
        off_t offset = (off_t)((sequence % RECORD_SLOTS) * sizeof(record));
        if (pwrite(fd, record, sizeof(record), offset) != sizeof(record)
            || fdatasync(fd)
            || pread(fd, observed, sizeof(observed), offset) != sizeof(observed)
            || memcmp(record, observed, sizeof(record))) {
            pthread_mutex_unlock(&context->lock);
            failure(context, "disk-numbered-write-read-flush"); break;
        }
        context->disk[disk] = sequence;
        pthread_mutex_unlock(&context->lock);
        pause_ms(1);
    }
    close(fd); return NULL;
}
static int verify_disks(struct context *context) {
    for (unsigned disk = 0; disk < 2; ++disk) {
        int fd = disk_open(disk);
        if (fd < 0) return -1;
        uint64_t newest = context->disk[disk];
        uint64_t oldest = newest >= RECORD_SLOTS ? newest - RECORD_SLOTS + 1 : 1;
        for (uint64_t sequence = oldest; sequence <= newest; ++sequence) {
            uint64_t observed[RECORD_WORDS];
            off_t offset = (off_t)((sequence % RECORD_SLOTS) * sizeof(observed));
            if (pread(fd, observed, sizeof(observed), offset) != sizeof(observed)) { close(fd); return -1; }
            for (unsigned i = 0; i < RECORD_WORDS; ++i) {
                if (observed[i] != word(disk, sequence, i)) { close(fd); errno = EILSEQ; return -1; }
            }
            ++context->disk_checks;
        }
        close(fd);
    }
    return 0;
}
static void *network_work(void *opaque) {
    struct context *context = opaque;
    int fd = socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0);
    if (fd < 0) { failure(context, "network-socket"); return NULL; }
    struct sockaddr_in local = {.sin_family = AF_INET, .sin_port = htons(34567), .sin_addr.s_addr = INADDR_ANY};
    if (bind(fd, (struct sockaddr *)&local, sizeof(local))) { failure(context, "network-bind"); close(fd); return NULL; }
    struct timeval timeout = {0, 10000};
    if (setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout))) { failure(context, "network-timeout"); close(fd); return NULL; }
    uint64_t sequence = 0;
    while (!atomic_load(&context->stop)) {
        pthread_mutex_lock(&context->lock);
        unsigned port = context->host_port;
        uint64_t generation = context->network_generation;
        struct packet packet = {PACKET_MAGIC, context->network_token, ++sequence,
                                context->network_phase, now_ns(), 0};
        pthread_mutex_unlock(&context->lock);
        if (!port) { pause_ms(10); continue; }
        struct sockaddr_in peer = {.sin_family = AF_INET, .sin_port = htons((uint16_t)port)};
        inet_pton(AF_INET, "192.168.127.254", &peer.sin_addr);
        ssize_t sent = sendto(fd, &packet, sizeof(packet), MSG_NOSIGNAL, (struct sockaddr *)&peer, sizeof(peer));
        if (sent != sizeof(packet)) { if (errno == EINTR || errno == ENETUNREACH) continue; failure(context, "network-send"); break; }
        pthread_mutex_lock(&context->lock);
        ++context->tx[packet.phase]; context->network_seen_generation = generation;
        pthread_mutex_unlock(&context->lock);
        struct packet received;
        ssize_t count = recv(fd, &received, sizeof(received), 0);
        if (count == sizeof(received) && received.magic == PACKET_MAGIC
            && received.echo == ECHO_MAGIC && received.phase <= 2) {
            pthread_mutex_lock(&context->lock);
            ++context->rx[received.phase];
            if (received.token != context->network_token) ++context->stale_rx;
            if (received.sequence & (UINT64_C(1) << 63)) {
                uint64_t expected = (UINT64_C(1) << 63) + context->injected_rx;
                if (received.sequence != expected) ++context->injected_faults;
                ++context->injected_rx; context->injected_last = received.sequence;
            }
            pthread_mutex_unlock(&context->lock);
        } else if (count >= 0 || (errno != EAGAIN && errno != EWOULDBLOCK && errno != EINTR && errno != ECONNREFUSED)) {
            failure(context, "network-receive"); break;
        }
        pause_ms(1);
    }
    close(fd); return NULL;
}
static int disk_identity(struct context *context) {
    const char hex[] = "0123456789abcdef";
    for (unsigned index = 0; index < 2; ++index) {
        char path[80]; unsigned char serial[64];
        snprintf(path, sizeof(path), "/dev/vd%c", 'a' + index);
        int fd = open(path, O_RDONLY | O_CLOEXEC);
        if (fd < 0) return -1;
        int result = ioctl(fd, BLKGETSIZE64, &context->disk_capacity[index])
            || ioctl(fd, BLKROGET, &context->disk_readonly[index]);
        close(fd);
        if (result) return -1;
        snprintf(path, sizeof(path), "/sys/block/vd%c/serial", 'a' + index);
        fd = open(path, O_RDONLY | O_CLOEXEC);
        if (fd < 0) return -1;
        ssize_t length = read(fd, serial, sizeof(serial));
        close(fd);
        if (length <= 0 || length == sizeof(serial)) { errno = EOVERFLOW; return -1; }
        for (ssize_t i = 0; i < length; ++i) {
            context->disk_serial[index][2 * i] = hex[serial[i] >> 4];
            context->disk_serial[index][2 * i + 1] = hex[serial[i] & 15];
        }
        context->disk_serial[index][2 * length] = 0;
    }
    return 0;
}

static void snapshot(struct context *context, uint64_t token) {
    pthread_mutex_lock(&context->lock);
    int result = verify_disks(context);
    if (result) { pthread_mutex_unlock(&context->lock); failure(context, "persisted-ring-verification"); return; }
    if (disk_identity(context)) { pthread_mutex_unlock(&context->lock); failure(context, "actual-disk-identity"); return; }
    emit_record(context, "{\"fixture\":\"production-linux-pressure\",\"operation\":\"snapshot\",\"token\":%" PRIu64 ",\"monotonic_ns\":%" PRIu64 ",\"disk0\":%" PRIu64 ",\"disk1\":%" PRIu64 ",\"disk_checks\":%" PRIu64 ",\"disk_capacity\":[%" PRIu64 ",%" PRIu64 "],\"disk_readonly\":[%d,%d],\"disk_serial_hex\":[\"%s\",\"%s\"],\"net_tx\":[%" PRIu64 ",%" PRIu64 ",%" PRIu64 "],\"net_rx\":[%" PRIu64 ",%" PRIu64 ",%" PRIu64 "],\"stale_rx\":%" PRIu64 ",\"guest_connects\":%" PRIu64 ",\"guest_bytes\":%" PRIu64 ",\"injected_rx\":%" PRIu64 ",\"injected_last\":%" PRIu64 ",\"injected_faults\":%" PRIu64 ",\"retained_probes\":%" PRIu64 ",\"reset_observed\":%" PRIu64 ",\"failed\":%d}\n",
            token, now_ns(), context->disk[0], context->disk[1], context->disk_checks,
            context->disk_capacity[0], context->disk_capacity[1], context->disk_readonly[0], context->disk_readonly[1],
            context->disk_serial[0], context->disk_serial[1],
            context->tx[0], context->tx[1], context->tx[2], context->rx[0], context->rx[1], context->rx[2],
            context->stale_rx, context->guest_connects, context->guest_bytes,
            context->injected_rx, context->injected_last, context->injected_faults,
            context->retained_probes, context->reset_observed, atomic_load(&context->failed));
    pthread_mutex_unlock(&context->lock);
}
static void guest_connect(struct context *context, uint64_t token, unsigned port, int hold) {
    int fd = socket(AF_VSOCK, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (fd < 0) { failure(context, "outgoing-vsock-socket"); return; }
    struct timeval timeout = {2, 0};
    if (setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout))
        || setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout))) {
        failure(context, "outgoing-vsock-timeout"); close(fd); return;
    }
    struct sockaddr_vm peer = {.svm_family = AF_VSOCK, .svm_cid = VMADDR_CID_HOST, .svm_port = port};
    if (connect(fd, (struct sockaddr *)&peer, sizeof(peer))) { failure(context, "outgoing-vsock-connect"); close(fd); return; }
    struct packet packet = {PACKET_MAGIC, token, 1, 0, now_ns(), 0}, reply;
    if (send(fd, &packet, sizeof(packet), MSG_NOSIGNAL) != sizeof(packet)
        || recv(fd, &reply, sizeof(reply), MSG_WAITALL) != sizeof(reply)
        || memcmp(&packet, &reply, sizeof(packet))) {
        failure(context, "outgoing-vsock-exact-echo"); close(fd); return;
    }
    pthread_mutex_lock(&context->lock);
    ++context->guest_connects; context->guest_bytes += sizeof(packet);
    pthread_mutex_unlock(&context->lock);
    if (hold) {
        if (context->retained_fd >= 0) close(context->retained_fd);
        context->retained_fd = fd;
    } else close(fd);
    snapshot(context, token);
}
static void retained_probe(struct context *context, uint64_t token, int reset) {
    int fd = context->retained_fd;
    if (fd < 0) { errno = EBADF; failure(context, "retained-vsock-owner"); return; }
    if (reset) {
        uint64_t deadline = now_ns() + UINT64_C(2000000000);
        for (;;) {
            unsigned char byte;
            ssize_t result = recv(fd, &byte, 1, MSG_DONTWAIT);
            if (result == 0 || (result < 0 && (errno == ECONNRESET || errno == ENOTCONN))) break;
            if (result > 0 || (errno != EAGAIN && errno != EWOULDBLOCK && errno != EINTR) || now_ns() >= deadline) {
                failure(context, "guest-transport-reset-not-observed"); return;
            }
            pause_ms(1);
        }
        close(fd); context->retained_fd = -1; ++context->reset_observed;
    } else {
        struct packet packet = {PACKET_MAGIC, token, 1, 0, now_ns(), 0}, reply;
        if (send(fd, &packet, sizeof(packet), MSG_NOSIGNAL) != sizeof(packet)
            || recv(fd, &reply, sizeof(reply), MSG_WAITALL) != sizeof(reply)
            || memcmp(&packet, &reply, sizeof(packet))) {
            failure(context, "source-retained-session-echo"); return;
        }
        ++context->retained_probes;
    }
    snapshot(context, token);
}

int main(void) {
    struct context context = {.lock = PTHREAD_MUTEX_INITIALIZER, .output = PTHREAD_MUTEX_INITIALIZER, .retained_fd = -1};
    pthread_t disks[2], network;
    struct disk_argument arguments[2] = {{&context, 0}, {&context, 1}};
    for (unsigned i = 0; i < 2; ++i) {
        int error = pthread_create(&disks[i], NULL, disk_work, &arguments[i]);
        if (error) { errno = error; failure(&context, "disk-thread"); _exit(2); }
    }
    int error = pthread_create(&network, NULL, network_work, &context);
    if (error) { errno = error; failure(&context, "network-thread"); _exit(3); }
    char line[160];
    while (fgets(line, sizeof(line), stdin)) {
        char command[16], trailing;
        uint64_t token; unsigned port, phase;
        if (sscanf(line, "NET %" SCNu64 " %u %u %c", &token, &port, &phase, &trailing) == 3 && port > 0 && port <= 65535 && phase <= 2) {
            pthread_mutex_lock(&context.lock);
            context.network_token = token; context.host_port = port; context.network_phase = phase;
            uint64_t generation = ++context.network_generation;
            pthread_mutex_unlock(&context.lock);
            uint64_t deadline = now_ns() + UINT64_C(5000000000);
            for (;;) {
                pthread_mutex_lock(&context.lock);
                int observed = context.network_seen_generation >= generation;
                pthread_mutex_unlock(&context.lock);
                if (observed) break;
                if (now_ns() >= deadline) { errno = ETIMEDOUT; failure(&context, "network-generation-handshake"); break; }
                pause_ms(1);
            }
            snapshot(&context, token);
        } else if (sscanf(line, "SNAP %" SCNu64 " %c", &token, &trailing) == 1) {
            snapshot(&context, token);
        } else if (sscanf(line, "CONNECT %" SCNu64 " %u %c", &token, &port, &trailing) == 2 && port > 0) {
            guest_connect(&context, token, port, 0);
        } else if (sscanf(line, "HOLD %" SCNu64 " %u %c", &token, &port, &trailing) == 2 && port > 0) {
            guest_connect(&context, token, port, 1);
        } else if (sscanf(line, "PROBE %" SCNu64 " %c", &token, &trailing) == 1) {
            retained_probe(&context, token, 0);
        } else if (sscanf(line, "RESET %" SCNu64 " %c", &token, &trailing) == 1) {
            retained_probe(&context, token, 1);
        } else if (sscanf(line, "%15s", command) == 1 && strcmp(command, "STOP") == 0) {
            break;
        } else { errno = EINVAL; failure(&context, "command"); break; }
    }
    atomic_store(&context.stop, 1);
    if (context.retained_fd >= 0) close(context.retained_fd);
    pthread_join(network, NULL);
    for (unsigned i = 0; i < 2; ++i) pthread_join(disks[i], NULL);
    pthread_mutex_destroy(&context.lock); pthread_mutex_destroy(&context.output);
    return atomic_load(&context.failed) ? 1 : 0;
}

/* Explicit static PID-1 workload for the standalone ordinary-kernel gate.
 * Build separately with cc -O2 -pthread -static. No hypervisor Cargo test.
 */
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <limits.h>
#include <net/if.h>
#include <sys/socket.h>
#include <linux/vm_sockets.h>
#include <net/if_arp.h>
#include <pthread.h>
#include <poll.h>
#include <sched.h>
#include <stdatomic.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/sysmacros.h>
#include <sys/uio.h>
#include <sys/wait.h>
#include <signal.h>
#include <time.h>
#include <unistd.h>

static atomic_uint_fast64_t disks[2], entropy, console_tx, console_rx, net_tx, net_rx, vsock_io, reclaim;
static atomic_uint_fast64_t net_replies, net_mismatches, net_timeouts, net_refused, net_interrupted, net_full_replies, net_last_reply_sequence;
static atomic_int failure;
static atomic_uint vsock_listeners;
static atomic_bool console_burst;
static int output;
static unsigned echo_port;
static int emit_bytes(int fd, const void *record, size_t length) {
    ssize_t written = write(fd, record, length);
    if (written < 0 || (size_t)written != length) {
        if (written >= 0) errno = EIO;
        atomic_store(&failure, 1);
        return -1;
    }
    return 0;
}
static int emit_record(int fd, const char *format, ...) {
    char record[2048];
    va_list arguments;
    va_start(arguments, format);
    int length = vsnprintf(record, sizeof(record), format, arguments);
    va_end(arguments);
    if (length < 0 || (size_t)length >= sizeof(record)) {
        errno = EOVERFLOW; atomic_store(&failure, 1); return -1;
    }
    return emit_bytes(fd, record, (size_t)length);
}
static void fail(const char *name) { int error = errno; atomic_store(&failure, 1); emit_record(output, "FAIL %s errno=%d\n", name, error); }
static void emit_buffered_record(FILE *stream, char **record, size_t *length) {
    int error = ferror(stream);
    if (fclose(stream)) error = 1;
    if (error) { errno = EIO; fail("profile-buffer"); }
    else if (*length > 16 * 1024 * 1024 + 1024) { errno = EFBIG; fail("profile-record-bound"); }
    else if (emit_bytes(output, *record, *length)) fail("profile-output");
    free(*record);
}
static void delay(void) { struct timespec t = {0, 1000000}; nanosleep(&t, NULL); }
static void *disk_worker(void *opaque) {
    unsigned disk = (unsigned)(uintptr_t)opaque;
    char directory[32], device[32], path[64];
    snprintf(directory, sizeof(directory), "/disk%u", disk);
    snprintf(device, sizeof(device), "/dev/vd%c", 'a' + disk);
    if (mkdir(directory, 0700) && errno != EEXIST) { fail("disk-mkdir"); return NULL; }
    if (mount(device, directory, "ext4", 0, NULL)) { fail("ordinary-ext4-mount"); return NULL; }
    snprintf(path, sizeof(path), "%s/numbered-records", directory);
    int fd = open(path, O_CREAT | O_RDWR | O_CLOEXEC, 0600);
    if (fd < 0) { fail("disk-open"); return NULL; }
    uint64_t record[512];
    for (;;) {
        uint64_t next = atomic_load(&disks[disk]) + 1;
        for (unsigned i = 0; i < 512; ++i) record[i] = next;
        off_t offset = (off_t)((next % 256) * sizeof(record));
        if (pwrite(fd, record, sizeof(record), offset) != sizeof(record)) { fail("disk-write"); break; }
        uint64_t observed[512];
        if (pread(fd, observed, sizeof(observed), offset) != sizeof(observed) || memcmp(record, observed, sizeof(record))) { fail("disk-read"); break; }
        if (next % 8 == 0 && fdatasync(fd)) { fail("disk-flush"); break; }
        atomic_store(&disks[disk], next);
        delay();
    }
    close(fd); return NULL;
}
static int rng_fd = -1;
/* rng0 plus ten real shared-IRQ line-padding RNG devices. */
#define RNG_PROVIDER_LIMIT 11
static char rng_providers[RNG_PROVIDER_LIMIT][64], rng_initial[512];
static unsigned rng_provider_count, rng_active;
static uint64_t rng_bytes[RNG_PROVIDER_LIMIT];
static pthread_mutex_t rng_lock = PTHREAD_MUTEX_INITIALIZER;
static int rng_attribute(const char *name, char *value, size_t capacity) {
    char path[128];
    snprintf(path, sizeof(path), "/sys/class/misc/hw_random/%s", name);
    int fd = open(path, O_RDONLY | O_CLOEXEC);
    if (fd < 0) return -1;
    ssize_t count = read(fd, value, capacity - 1);
    int error = errno;
    close(fd);
    if (count < 0) { errno = error; return -1; }
    if (count == 0 || (size_t)count == capacity - 1) { errno = EOVERFLOW; return -1; }
    value[count] = '\0';
    return 0;
}
static int rng_device_identity(void) {
    DIR *directory = opendir("/sys/bus/virtio/devices");
    if (!directory) return -1;
    unsigned matches = 0;
    int error = 0;
    char *record = NULL; size_t length = 0;
    FILE *stream = open_memstream(&record, &length);
    if (!stream) { int saved = errno; closedir(directory); errno = saved; return -1; }
    fputs("OBS-BEGIN rng-virtio-device\n", stream);
    for (;;) {
        errno = 0;
        struct dirent *entry = readdir(directory);
        if (!entry) { error = errno; break; }
        if (entry->d_name[0] == '.') continue;
        char path[512], value[64], resolved[PATH_MAX], driver[PATH_MAX];
        snprintf(path, sizeof(path), "/sys/bus/virtio/devices/%s/device", entry->d_name);
        int fd = open(path, O_RDONLY | O_CLOEXEC);
        if (fd < 0) { error = errno; break; }
        ssize_t count = read(fd, value, sizeof(value) - 1);
        int read_error = errno;
        close(fd);
        if (count <= 0 || count == sizeof(value) - 1) { error = count < 0 ? read_error : EIO; break; }
        value[count] = '\0';
        unsigned device;
        char extra;
        if (sscanf(value, "%x %c", &device, &extra) != 1) { error = EINVAL; break; }
        if (device != 4) continue;
        snprintf(path, sizeof(path), "/sys/bus/virtio/devices/%s", entry->d_name);
        if (!realpath(path, resolved)) { error = errno; break; }
        snprintf(path, sizeof(path), "/sys/bus/virtio/devices/%s/driver", entry->d_name);
        if (!realpath(path, driver)) { error = errno; break; }
        const char *name = strrchr(driver, '/');
        if (!name || strcmp(name + 1, "virtio_rng")) { error = ENODEV; break; }
        if (++matches > RNG_PROVIDER_LIMIT) { error = EOVERFLOW; break; }
        fprintf(stream, "virtio_device=%s device_id=4 sysfs_path=%s driver=%s\n",
            entry->d_name, resolved, driver);
    }
    closedir(directory);
    if (error || matches != rng_provider_count) {
        fclose(stream); free(record); errno = error ? error : ENODEV; return -1;
    }
    for (unsigned index = 0; index < rng_provider_count; ++index)
        fprintf(stream, "provider=%s completed_read_bytes=%" PRIu64 "\n", rng_providers[index], rng_bytes[index]);
    fputs("OBS-END rng-virtio-device\n", stream);
    emit_buffered_record(stream, &record, &length);
    return 0;
}
static int rng_observations_locked(void) {
    char current[512], available[512], selected[512], device[512];
    if (rng_attribute("rng_current", current, sizeof(current)) ||
        rng_attribute("rng_available", available, sizeof(available)) ||
        rng_attribute("rng_selected", selected, sizeof(selected)) ||
        rng_attribute("dev", device, sizeof(device))) return -1;
    struct stat node;
    if (fstat(rng_fd, &node)) return -1;
    emit_record(output, "OBS-BEGIN rng-initial\n%s\nOBS-END rng-initial\n", rng_initial);
    emit_record(output, "OBS-BEGIN rng-current\n%s\nOBS-END rng-current\n", current);
    emit_record(output, "OBS-BEGIN rng-available\n%s\nOBS-END rng-available\n", available);
    emit_record(output, "OBS-BEGIN rng-selected\n%s\nOBS-END rng-selected\n", selected);
    emit_record(output, "OBS-BEGIN rng-node\npath=/dev/hwrng\nmode=%o\nmajor=%u\nminor=%u\nsysfs_dev=%s\nOBS-END rng-node\n",
        (unsigned)node.st_mode, major(node.st_rdev), minor(node.st_rdev), device);
    unsigned device_major, device_minor;
    char extra;
    current[strcspn(current, "\n")] = '\0';
    if (strcmp(current, rng_providers[rng_active]) || strcmp(selected, "1\n") ||
        !S_ISCHR(node.st_mode) || sscanf(device, "%u:%u %c", &device_major, &device_minor, &extra) != 2 ||
        major(node.st_rdev) != device_major || minor(node.st_rdev) != device_minor) {
        errno = ENODEV; return -1;
    }
    return rng_device_identity();
}
static int rng_observations(void) {
    pthread_mutex_lock(&rng_lock);
    int result = rng_observations_locked();
    int error = errno;
    pthread_mutex_unlock(&rng_lock);
    errno = error;
    return result;
}
static int rng_verify(unsigned index) {
    char current[512];
    if (rng_attribute("rng_current", current, sizeof(current))) return -1;
    current[strcspn(current, "\n")] = '\0';
    if (strcmp(current, rng_providers[index])) { errno = ENODEV; return -1; }
    return 0;
}
static int rng_select(unsigned index) {
    int fd = open("/sys/class/misc/hw_random/rng_current", O_WRONLY | O_CLOEXEC);
    if (fd < 0) return -1;
    const char *provider = rng_providers[index];
    ssize_t count = write(fd, provider, strlen(provider));
    int error = errno;
    close(fd);
    if (count != (ssize_t)strlen(provider)) { errno = count < 0 ? error : EIO; return -1; }
    if (rng_verify(index)) return -1;
    rng_active = index;
    return 0;
}
static int rng_setup(void) {
    char available[512], candidates[512];
    if (rng_attribute("rng_current", rng_initial, sizeof(rng_initial)) ||
        rng_attribute("rng_available", available, sizeof(available))) return -1;
    emit_record(output, "OBS-BEGIN rng-initial\n%s\nOBS-END rng-initial\n", rng_initial);
    emit_record(output, "OBS-BEGIN rng-available\n%s\nOBS-END rng-available\n", available);
    strcpy(candidates, available);
    char *state;
    for (char *name = strtok_r(candidates, " \t\n", &state); name; name = strtok_r(NULL, " \t\n", &state)) {
        if (strncmp(name, "virtio_rng.", 11) || !name[11] ||
            strspn(name + 11, "0123456789") != strlen(name + 11)) continue;
        if (rng_provider_count == RNG_PROVIDER_LIMIT || strlen(name) >= sizeof(rng_providers[0])) {
            errno = EOVERFLOW; return -1;
        }
        for (unsigned index = 0; index < rng_provider_count; ++index) {
            if (!strcmp(name, rng_providers[index])) { errno = EINVAL; return -1; }
        }
        strcpy(rng_providers[rng_provider_count++], name);
    }
    if (!rng_provider_count) { errno = ENODEV; return -1; }
    if (rng_select(0)) return -1;
    rng_fd = open("/dev/hwrng", O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (rng_fd < 0) return -1;
    return rng_observations();
}
static void *rng_worker(void *unused) {
    (void)unused;
    int fd = rng_fd;
    unsigned char bytes[4096];
    unsigned index = 0;
    for (;;) {
        pthread_mutex_lock(&rng_lock);
        int error = rng_select(index) ? errno : 0;
        size_t total = 0;
        /* Drain more than both kernel caches while keeping this provider selected. */
        while (!error && total < sizeof(bytes)) {
            ssize_t count = read(fd, bytes + total, sizeof(bytes) - total);
            if (count < 0 && errno == EINTR) continue;
            if (count <= 0) { error = count < 0 ? errno : EIO; break; }
            total += (size_t)count;
        }
        if (!error && rng_verify(index)) error = errno;
        if (!error) {
            rng_bytes[index] += total;
            atomic_fetch_add(&entropy, total);
        }
        pthread_mutex_unlock(&rng_lock);
        errno = error;
        if (error) { fail("real-virtio-rng-read"); break; }
        index = (index + 1) % rng_provider_count;
        delay();
    }
    close(fd); return NULL;
}
static int report_setup(void) {
    /* Ordinary mmap churn guarantees base pages, not the default pageblock-order
     * free blocks. Make those real frees eligible for the kernel reporting driver. */
    const char *path = "/sys/module/page_reporting/parameters/page_reporting_order";
    int fd = open(path, O_RDONLY | O_CLOEXEC);
    if (fd < 0) return -1;
    char original[16] = {0};
    ssize_t count = read(fd, original, sizeof(original) - 1);
    int error = count < 0 ? errno : count == 0 || count == sizeof(original) - 1 ? EIO : 0;
    if (close(fd) && !error) error = errno;
    if (error) { errno = error; return -1; }
    if (emit_record(output, "OBS-BEGIN page-reporting-order-original\n%sOBS-END page-reporting-order-original\n", original)) return -1;
    fd = open(path, O_WRONLY | O_CLOEXEC);
    if (fd < 0) return -1;
    count = write(fd, "0\n", 2);
    error = count < 0 ? errno : count != 2 ? EIO : 0;
    if (close(fd) && !error) error = errno;
    if (error) { errno = error; return -1; }
    fd = open(path, O_RDONLY | O_CLOEXEC);
    if (fd < 0) return -1;
    char value[16] = {0};
    count = read(fd, value, sizeof(value) - 1);
    error = count < 0 ? errno : 0;
    if (close(fd) && !error) error = errno;
    if (error) { errno = error; return -1; }
    if (count != 2 || strcmp(value, "0\n")) { errno = EINVAL; return -1; }
    return emit_record(output, "OBS-BEGIN page-reporting-order\n%sOBS-END page-reporting-order\n", value);
}
static void *report_worker(void *unused) {
    (void)unused;
    for (;;) {
        size_t size = 32 * 1024 * 1024;
        unsigned char *memory = mmap(NULL, size, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        if (memory == MAP_FAILED) { fail("report-mmap"); return NULL; }
        for (size_t i = 0; i < size; i += 4096) memory[i] = 0xa5;
        if (munmap(memory, size)) { fail("report-munmap"); return NULL; }
        atomic_fetch_add(&reclaim, 1);
        struct timespec t = {0, 100000000}; nanosleep(&t, NULL);
    }
}
static void *console_writer(void *unused) {
    (void)unused;
    int fd = open("/dev/vport0p2", O_WRONLY | O_CLOEXEC);
    if (fd < 0) { fail("console-output-only"); return NULL; }
    unsigned burst_remaining = 0;
    for (;;) {
        uint64_t next = atomic_load(&console_tx) + 1;
        char message[80]; int length = snprintf(message, sizeof(message), "CONSOLE %" PRIu64 "\n", next);
        ssize_t done = 0;
        while (done < length) {
            ssize_t count = write(fd, message + done, (size_t)(length - done));
            if (count < 0 && errno == EINTR) continue;
            if (count <= 0) { fail("console-partial-output"); close(fd); return NULL; }
            done += count;
        }
        atomic_store(&console_tx, next);
        if (atomic_exchange(&console_burst, 0)) burst_remaining = 65536;
        if (burst_remaining) --burst_remaining;
        else delay();
    }
}
static void *console_reader(void *unused) {
    (void)unused;
    int fd = open("/dev/vport0p1", O_RDONLY | O_CLOEXEC);
    if (fd < 0) { fail("console-input-only"); return NULL; }
    unsigned char bytes[4096];
    for (;;) {
        ssize_t count = read(fd, bytes, sizeof(bytes));
        if (count < 0 && errno == EINTR) continue;
        if (count <= 0) { fail("console-input"); break; }
        atomic_fetch_add(&console_rx, (uint64_t)count);
    }
    close(fd); return NULL;
}
static int network_neighbor(int fd, int destination) {
    struct arpreq request = {0};
    struct sockaddr_in *address = (struct sockaddr_in *)&request.arp_pa;
    address->sin_family = AF_INET;
    inet_pton(AF_INET, "192.168.127.254", &address->sin_addr);
    const unsigned char mac[6] = {0x5a, 0x94, 0xef, 0xe4, 0x0c, 0xdd};
    request.arp_ha.sa_family = ARPHRD_ETHER;
    memcpy(request.arp_ha.sa_data, mac, sizeof(mac));
    request.arp_flags = ATF_COM | ATF_PERM;
    strcpy(request.arp_dev, "eth0");
    /* The fence must exercise Ethernet frames, not unresolved guest ARP queues.
     * This is netd's configured gateway MAC for its .254 host virtual IP. */
    if (ioctl(fd, SIOCSARP, &request)) return -1;
    memset(&request.arp_ha, 0, sizeof(request.arp_ha));
    request.arp_flags = 0;
    if (ioctl(fd, SIOCGARP, &request)) return -1;
    if ((request.arp_flags & (ATF_COM | ATF_PERM)) != (ATF_COM | ATF_PERM)
        || request.arp_ha.sa_family != ARPHRD_ETHER
        || memcmp(request.arp_ha.sa_data, mac, sizeof(mac))) {
        errno = EPROTO; return -1;
    }
    return emit_record(output, "{\"fixture\":\"production-linux-neighbor\",\"interface\":\"eth0\",\"ip\":\"192.168.127.254\",\"mac\":\"5a:94:ef:e4:0c:dd\",\"flags\":%d,\"destination\":%d}\n",
                       request.arp_flags, destination);
}
static int network_mac(int destination) {
    int fd = socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0);
    if (fd < 0) return -1;
    struct ifreq request = {0}; strcpy(request.ifr_name, "eth0");
    request.ifr_hwaddr.sa_family = ARPHRD_ETHER;
    unsigned char mac[6] = {2, 0, 0, 0, 0, destination ? 2 : 1};
    memcpy(request.ifr_hwaddr.sa_data, mac, sizeof(mac));
    int result = ioctl(fd, SIOCSIFHWADDR, &request);
    if (!result && destination) result = network_neighbor(fd, 1);
    close(fd); return result;
}
static int network_up(void) {
    int fd = socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0);
    if (fd < 0) return -1;
    struct ifreq request = {0}; strcpy(request.ifr_name, "eth0");
    struct sockaddr_in *address = (struct sockaddr_in *)&request.ifr_addr;
    address->sin_family = AF_INET; inet_pton(AF_INET, "192.168.127.2", &address->sin_addr);
    if (ioctl(fd, SIOCSIFADDR, &request)) { close(fd); return -1; }
    address = (struct sockaddr_in *)&request.ifr_netmask;
    address->sin_family = AF_INET; inet_pton(AF_INET, "255.255.255.0", &address->sin_addr);
    if (ioctl(fd, SIOCSIFNETMASK, &request)) { close(fd); return -1; }
    request.ifr_flags = IFF_UP | IFF_RUNNING;
    int result = ioctl(fd, SIOCSIFFLAGS, &request);
    if (!result) result = network_neighbor(fd, 0);
    close(fd); return result;
}
static void *network_worker(void *unused) {
    (void)unused;
    if (network_mac(0) || network_up()) { fail("network-configure"); return NULL; }
    int fd = socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0);
    if (fd < 0) { fail("network-socket"); return NULL; }
    struct sockaddr_in peer = {.sin_family = AF_INET, .sin_port = htons(echo_port)};
    inet_pton(AF_INET, "192.168.127.254", &peer.sin_addr);
    if (connect(fd, (struct sockaddr *)&peer, sizeof(peer))) { fail("network-connect"); goto done; }
    for (;;) {
        uint64_t packet[2] = {UINT64_C(0x53494c4f4e455431), atomic_load(&net_tx) + 1};
        if (send(fd, packet, sizeof(packet), 0) != sizeof(packet)) { fail("network-send"); break; }
        atomic_store(&net_tx, packet[1]);
        struct timespec now;
        if (clock_gettime(CLOCK_MONOTONIC, &now)) { fail("network-clock"); break; }
        uint64_t deadline = (uint64_t)now.tv_sec * UINT64_C(1000000000) + (uint64_t)now.tv_nsec + UINT64_C(100000000);
        for (;;) {
            if (clock_gettime(CLOCK_MONOTONIC, &now)) { fail("network-clock"); goto done; }
            uint64_t current = (uint64_t)now.tv_sec * UINT64_C(1000000000) + (uint64_t)now.tv_nsec;
            if (current >= deadline) { atomic_fetch_add(&net_timeouts, 1); break; }
            uint64_t left = deadline - current;
            struct timespec remaining = {
                .tv_sec = (time_t)(left / UINT64_C(1000000000)),
                .tv_nsec = (long)(left % UINT64_C(1000000000)),
            };
            struct pollfd pending = {.fd = fd, .events = POLLIN};
            int ready = ppoll(&pending, 1, &remaining, NULL);
            if (ready < 0) {
                if (errno == EINTR) { atomic_fetch_add(&net_interrupted, 1); continue; }
                fail("network-poll"); goto done;
            }
            if (!ready) continue;
            if (clock_gettime(CLOCK_MONOTONIC, &now)) { fail("network-clock"); goto done; }
            current = (uint64_t)now.tv_sec * UINT64_C(1000000000) + (uint64_t)now.tv_nsec;
            if (current >= deadline) { atomic_fetch_add(&net_timeouts, 1); break; }
            uint64_t reply[2];
            ssize_t count = recv(fd, reply, sizeof(reply), MSG_DONTWAIT | MSG_TRUNC);
            if (count >= 0) {
                atomic_fetch_add(&net_replies, 1);
                if (count == sizeof(reply)) {
                    atomic_store(&net_last_reply_sequence, reply[1]);
                    atomic_fetch_add(&net_full_replies, 1);
                }
                if (count == sizeof(reply) && memcmp(packet, reply, sizeof(packet)) == 0) {
                    if (clock_gettime(CLOCK_MONOTONIC, &now)) { fail("network-clock"); goto done; }
                    current = (uint64_t)now.tv_sec * UINT64_C(1000000000) + (uint64_t)now.tv_nsec;
                    if (current >= deadline) { atomic_fetch_add(&net_timeouts, 1); break; }
                    atomic_fetch_add(&net_rx, 1);
                    break;
                }
                atomic_fetch_add(&net_mismatches, 1);
            } else if (errno == EAGAIN) {
                continue;
            } else if (errno == ECONNREFUSED) {
                atomic_fetch_add(&net_refused, 1);
            } else if (errno == EINTR) {
                atomic_fetch_add(&net_interrupted, 1);
            } else {
                fail("network-receive"); goto done;
            }
        }
        delay();
    }
done:
    close(fd); return NULL;
}
static void *vsock_connection(void *opaque) {
    int fd = (int)(intptr_t)opaque;
    unsigned char bytes[4096];
    for (;;) {
        ssize_t length = read(fd, bytes, sizeof(bytes));
        if (length < 0 && errno == EINTR) continue;
        if (length <= 0) break;
        ssize_t offset = 0;
        while (offset < length) {
            ssize_t count = send(fd, bytes + offset, (size_t)(length - offset), MSG_NOSIGNAL);
            if (count < 0 && errno == EINTR) continue;
            if (count <= 0) { close(fd); return NULL; }
            offset += count;
        }
        atomic_fetch_add(&vsock_io, (uint64_t)offset);
    }
    close(fd); return NULL;
}
static void *vsock_worker(void *opaque) {
    unsigned port = (unsigned)(uintptr_t)opaque;
    int listener = socket(AF_VSOCK, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (listener < 0) { fail("vsock-socket"); return NULL; }
    struct sockaddr_vm address = {.svm_family = AF_VSOCK, .svm_cid = VMADDR_CID_ANY, .svm_port = port};
    if (bind(listener, (struct sockaddr *)&address, sizeof(address)) || listen(listener, 8)) { fail("vsock-listen"); close(listener); return NULL; }
    atomic_fetch_or(&vsock_listeners, 1u << (port - 1027));
    for (;;) {
        int fd = accept4(listener, NULL, NULL, SOCK_CLOEXEC);
        if (fd < 0) { if (errno == EINTR) continue; fail("vsock-accept"); break; }
        pthread_t connection;
        int error = pthread_create(&connection, NULL, vsock_connection, (void *)(intptr_t)fd);
        if (error) { close(fd); errno = error; fail("vsock-connection"); break; }
        error = pthread_detach(connection);
        if (error) { errno = error; fail("vsock-connection-detach"); break; }
    }
    close(listener); return NULL;
}
static void dump_file(const char *tag, const char *path) {
    int fd = open(path, O_RDONLY | O_CLOEXEC);
    if (fd < 0) {
        int error = errno;
        if (error == ENOENT && strcmp(path, "/proc/modules") == 0) {
            emit_record(output, "OBS-BEGIN %s\n{\"path\":\"/proc/modules\",\"status\":\"absent\",\"errno\":%d}\nOBS-END %s\n", tag, error, tag);
        } else {
            fail(path);
        }
        return;
    }
    char *record = NULL; size_t length = 0;
    FILE *stream = open_memstream(&record, &length);
    if (!stream) { int error = errno; close(fd); errno = error; fail("profile-buffer"); return; }
    fprintf(stream, "OBS-BEGIN %s\n", tag);
    char bytes[4096]; ssize_t count; size_t bytes_read = 0; int error = 0;
    while ((count = read(fd, bytes, sizeof(bytes))) > 0) {
        if ((size_t)count > 16 * 1024 * 1024 - 1 - bytes_read) { error = EFBIG; break; }
        bytes_read += (size_t)count;
        if (fwrite(bytes, 1, (size_t)count, stream) != (size_t)count) { error = EIO; break; }
    }
    if (count < 0) error = errno;
    close(fd);
    if (error) { fclose(stream); free(record); errno = error; fail(path); return; }
    fprintf(stream, "\nOBS-END %s\n", tag);
    emit_buffered_record(stream, &record, &length);
    if (strcmp(tag, "broadcast-clockevent") == 0) {
        emit_record(output, "OBS-BEGIN broadcast-clockevent-state\npath=/sys/devices/system/clockevents/broadcast/current_device\nread_complete=1\nbytes_read=%zu\nkind=%s\nOBS-END broadcast-clockevent-state\n", bytes_read, bytes_read == 0 ? "no-device" : "device");
    }
}
static void observations(void) {
    if (rng_observations()) fail("real-virtio-rng-identity");
    dump_file("kernel-identity", "/proc/version");
    dump_file("boot-identity", "/proc/sys/kernel/random/boot_id");
    dump_file("clocksource", "/sys/devices/system/clocksource/clocksource0/current_clocksource");
    dump_file("clockevent0", "/sys/devices/system/clockevents/clockevent0/current_device");
    dump_file("clockevent1", "/sys/devices/system/clockevents/clockevent1/current_device");
    dump_file("broadcast-clockevent", "/sys/devices/system/clockevents/broadcast/current_device");
    dump_file("interrupts", "/proc/interrupts");
    dump_file("modules", "/proc/modules");
    char *record = NULL; size_t length = 0;
    FILE *stream = open_memstream(&record, &length);
    if (!stream) { fail("speaker-buffer"); return; }
    fputs("OBS-BEGIN speaker-consumers\n", stream);
    if (access("/sys/devices/platform/pcspkr/driver", F_OK) == 0) fputs("pcspkr\n", stream);
    if (access("/sys/devices/platform/pcspkr.0/driver", F_OK) == 0) fputs("pcspkr.0\n", stream);
    DIR *directory = opendir("/sys/class/input");
    int error = !directory && errno != ENOENT ? errno : 0;
    if (directory) {
        struct dirent *entry;
        while ((entry = readdir(directory))) {
            if (strncmp(entry->d_name, "input", 5)) continue;
            char path[512], name[256] = {0};
            snprintf(path, sizeof(path), "/sys/class/input/%s/name", entry->d_name);
            int fd = open(path, O_RDONLY | O_CLOEXEC);
            if (fd < 0) { error = errno; break; }
            ssize_t count = read(fd, name, sizeof(name) - 1);
            if (count < 0) error = errno;
            close(fd);
            if (error) break;
            if (strstr(name, "Speaker") || strstr(name, "speaker")) fputs(name, stream);
            long size = ftell(stream);
            if (size < 0 || size > 16 * 1024 * 1024) { error = EFBIG; break; }
        }
        closedir(directory);
    }
    if (error) { fclose(stream); free(record); errno = error; fail("speaker-inventory"); return; }
    fputs("OBS-END speaker-consumers\n", stream);
    emit_buffered_record(stream, &record, &length);
}

struct clock_sample { atomic_uint_fast64_t request, ack, tsc, monotonic; };
static struct clock_sample clock_sample;
static uint64_t timestamp(void) {
    unsigned low, high;
    __asm__ volatile ("lfence; rdtsc" : "=a"(low), "=d"(high) : : "memory");
    return (uint64_t)high << 32 | low;
}
static uint64_t monotonic(void) {
    struct timespec value;
    if (clock_gettime(CLOCK_MONOTONIC, &value)) { fail("clock-monotonic"); return 0; }
    return (uint64_t)value.tv_sec * UINT64_C(1000000000) + (uint64_t)value.tv_nsec;
}
static int pin(unsigned cpu) {
    cpu_set_t set;
    CPU_ZERO(&set); CPU_SET(cpu, &set);
    int error = pthread_setaffinity_np(pthread_self(), sizeof(set), &set);
    if (error) { errno = error; fail("clock-affinity"); return -1; }
    return 0;
}
static void *clock_secondary(void *unused) {
    (void)unused;
    if (pin(1)) return NULL;
    for (;;) {
        uint64_t request = atomic_load_explicit(&clock_sample.request, memory_order_acquire);
        if (request != atomic_load(&clock_sample.ack)) {
            atomic_store(&clock_sample.tsc, timestamp());
            atomic_store(&clock_sample.monotonic, monotonic());
            atomic_store_explicit(&clock_sample.ack, request, memory_order_release);
        }
        __asm__ volatile ("pause");
    }
}
static void *clock_primary(void *unused) {
    (void)unused;
    if (pin(0)) return NULL;
    uint64_t sequence = 0;
    for (;;) {
        uint64_t mono_before = monotonic(), before = timestamp();
        atomic_store_explicit(&clock_sample.request, ++sequence, memory_order_release);
        while (atomic_load_explicit(&clock_sample.ack, memory_order_acquire) != sequence) __asm__ volatile ("pause");
        uint64_t after = timestamp(), mono_after = monotonic();
        emit_record(output, "{\"fixture\":\"production-linux-clock-bracket\",\"sequence\":%" PRIu64 ",\"tsc_before\":%" PRIu64 ",\"tsc_ap\":%" PRIuFAST64 ",\"tsc_after\":%" PRIu64 ",\"mono_before\":%" PRIu64 ",\"mono_ap\":%" PRIuFAST64 ",\"mono_after\":%" PRIu64 "}\n",
            sequence, before, atomic_load(&clock_sample.tsc), after, mono_before, atomic_load(&clock_sample.monotonic), mono_after);
        struct timespec wait = {0, 100000000}; nanosleep(&wait, NULL);
    }
}
static void emit_devices(uint64_t sequence, const char *token) {
    struct timespec now; clock_gettime(CLOCK_MONOTONIC, &now);
    uint64_t full_replies = atomic_load(&net_full_replies);
    char reply_sequence[32];
    if (full_replies) snprintf(reply_sequence, sizeof(reply_sequence), "%" PRIuFAST64, atomic_load(&net_last_reply_sequence));
    else strcpy(reply_sequence, "null");
    emit_record(output, "{\"fixture\":\"production-linux-devices\",\"request_token\":\"%s\",\"sequence\":%" PRIu64 ",\"monotonic_ns\":%" PRIu64 ",\"disk0\":%" PRIuFAST64 ",\"disk1\":%" PRIuFAST64 ",\"rng\":%" PRIuFAST64 ",\"report\":%" PRIuFAST64 ",\"console_tx\":%" PRIuFAST64 ",\"console_rx\":%" PRIuFAST64 ",\"net_tx\":%" PRIuFAST64 ",\"net_rx\":%" PRIuFAST64 ",\"net_replies\":%" PRIuFAST64 ",\"net_mismatches\":%" PRIuFAST64 ",\"net_timeouts\":%" PRIuFAST64 ",\"net_refused\":%" PRIuFAST64 ",\"net_interrupted\":%" PRIuFAST64 ",\"net_full_replies\":%" PRIu64 ",\"net_last_full_reply_sequence\":%s,\"vsock\":%" PRIuFAST64 ",\"vsock_listeners\":%u,\"failed\":%d}\n", token, sequence, (uint64_t)now.tv_sec * UINT64_C(1000000000) + now.tv_nsec, atomic_load(&disks[0]), atomic_load(&disks[1]), atomic_load(&entropy), atomic_load(&reclaim), atomic_load(&console_tx), atomic_load(&console_rx), atomic_load(&net_tx), atomic_load(&net_rx), atomic_load(&net_replies), atomic_load(&net_mismatches), atomic_load(&net_timeouts), atomic_load(&net_refused), atomic_load(&net_interrupted), full_replies, reply_sequence, atomic_load(&vsock_io), atomic_load(&vsock_listeners), atomic_load(&failure));
}

/* The undrained vmsplice pipe retains real page references, not just virtual
 * mlock residency. No fork follows allocation, and no pipe reader consumes them.
 * Only D/Z write the CPU page; the host page is never reused by Linux or workers. */
static unsigned char *memory_pages;
static int memory_pin_pipe[2] = {-1, -1};
static uint64_t memory_gpa[2];
static unsigned memory_cpu_byte = 0x43, memory_cpu_generation;
static int memory_buffers(const char *token, int cpu_write, int cpu_zero) {
    const size_t page = 4096;
    if (!memory_pages) {
        if (sysconf(_SC_PAGESIZE) != (long)page) { errno = ENOTSUP; return -1; }
        void *mapping = mmap(NULL, 2 * page, PROT_READ | PROT_WRITE,
            MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        if (mapping == MAP_FAILED) return -1;
        if (madvise(mapping, 2 * page, MADV_NOHUGEPAGE) || mlock(mapping, 2 * page)) {
            int error = errno; munmap(mapping, 2 * page); errno = error; return -1;
        }
        memset(mapping, 0x48, page);
        memset((unsigned char *)mapping + page, memory_cpu_byte, page);
        int pin_pipe[2];
        if (pipe2(pin_pipe, O_CLOEXEC | O_NONBLOCK)) {
            int error = errno; munmap(mapping, 2 * page); errno = error; return -1;
        }
        struct iovec pinned = {.iov_base = mapping, .iov_len = 2 * page};
        ssize_t held = vmsplice(pin_pipe[1], &pinned, 1, SPLICE_F_NONBLOCK);
        if (held != (ssize_t)(2 * page)) {
            int error = held < 0 ? errno : EIO;
            close(pin_pipe[0]); close(pin_pipe[1]); munmap(mapping, 2 * page);
            errno = error; return -1;
        }
        int fd = open("/proc/self/pagemap", O_RDONLY | O_CLOEXEC);
        if (fd < 0) {
            int error = errno; close(pin_pipe[0]); close(pin_pipe[1]);
            munmap(mapping, 2 * page); errno = error; return -1;
        }
        int error = 0;
        for (unsigned index = 0; index < 2; ++index) {
            uint64_t entry;
            uintptr_t address = (uintptr_t)mapping + index * page;
            if (pread(fd, &entry, sizeof(entry), (off_t)((address / page) * sizeof(entry))) != sizeof(entry)) {
                error = EIO; break;
            }
            uint64_t pfn = entry & ((UINT64_C(1) << 55) - 1);
            if (!(entry & (UINT64_C(1) << 63)) || (entry & (UINT64_C(1) << 62)) ||
                !pfn || pfn > UINT64_MAX / page) {
                error = ENOTSUP; break;
            }
            memory_gpa[index] = pfn * page;
        }
        close(fd);
        if (error) {
            close(pin_pipe[0]); close(pin_pipe[1]); munmap(mapping, 2 * page);
            errno = error; return -1;
        }
        memory_pin_pipe[0] = pin_pipe[0]; memory_pin_pipe[1] = pin_pipe[1];
        memory_pages = mapping;
    }
    int held_bytes = 0;
    if (ioctl(memory_pin_pipe[0], FIONREAD, &held_bytes)) return -1;
    if (held_bytes != (int)(2 * page)) { errno = EIO; return -1; }
    if (cpu_write || cpu_zero) {
        if (memory_cpu_generation == UINT_MAX || (cpu_write && memory_cpu_byte == 255)) {
            errno = EOVERFLOW; return -1;
        }
        memory_cpu_byte = cpu_zero ? 0 : memory_cpu_byte + 1;
        ++memory_cpu_generation;
        memset(memory_pages + page, memory_cpu_byte, page);
    }
    const volatile unsigned char *bytes = memory_pages;
    unsigned host_byte = bytes[0];
    for (size_t index = 0; index < page; ++index) {
        if (bytes[index] != host_byte || bytes[page + index] != memory_cpu_byte) {
            errno = EIO; return -1;
        }
    }
    return emit_record(output,
        "OBS-BEGIN memory-buffer\n"
        "{\"request_token\":\"%s\",\"host_gpa\":%" PRIu64 ",\"cpu_gpa\":%" PRIu64
        ",\"bytes\":4096,\"host_byte\":%u,\"cpu_byte\":%u,\"cpu_generation\":%u,"
        "\"mlocked\":true,\"pipe_page_refs_retained\":true,\"pipe_bytes\":8192,"
        "\"pagemap_present\":true}\nOBS-END memory-buffer\n",
        token, memory_gpa[0], memory_gpa[1], host_byte, memory_cpu_byte, memory_cpu_generation);
}

enum {
    SHARING_PAGE_SIZE = 4096,
    SHARING_PAGES = 16384,
    SHARING_SLOT_PAGES = SHARING_PAGES / 4,
    SHARING_BYTES = SHARING_PAGE_SIZE * SHARING_PAGES,
    SHARING_INITIALIZE = 6,
    SHARING_VERIFY = 7,
    SHARING_WRITE_FIRST = 8,
    SHARING_WRITE_LAST = SHARING_WRITE_FIRST + 3,
};
struct sharing_memory {
    unsigned char *bytes;
    int write_slot;
    uint64_t baseline_checksum, first_gpa;
};
static int sharing_time_left(uint64_t deadline) {
    struct timespec now;
    if (clock_gettime(CLOCK_MONOTONIC, &now)) return -1;
    uint64_t current = (uint64_t)now.tv_sec * UINT64_C(1000000000) + (uint64_t)now.tv_nsec;
    if (current >= deadline) { errno = ETIMEDOUT; return -1; }
    return 0;
}
static unsigned char sharing_byte(unsigned page, unsigned offset, unsigned variant) {
    if (offset < 8) return (unsigned char)((uint64_t)page >> (offset * 8));
    return (unsigned char)(1 + (page * 17 + offset * 29 + variant * 47) % 255);
}
static unsigned sharing_variant(unsigned page, int slot) {
    return slot >= 0 && (page == 0 || page / SHARING_SLOT_PAGES == (unsigned)slot)
        ? (unsigned)slot + 1 : 0;
}
static int sharing_fill(struct sharing_memory *memory, int slot, uint64_t deadline) {
    for (unsigned page = 0; page < SHARING_PAGES; ++page) {
        unsigned variant = sharing_variant(page, slot);
        if (slot >= 0 && !variant) continue;
        if (sharing_time_left(deadline)) return -1;
        for (unsigned offset = 0; offset < SHARING_PAGE_SIZE; ++offset)
            memory->bytes[(size_t)page * SHARING_PAGE_SIZE + offset] = sharing_byte(page, offset, variant);
    }
    return 0;
}
static int sharing_scan(const struct sharing_memory *memory, uint64_t deadline, uint64_t *checksum) {
    const volatile unsigned char *bytes = memory->bytes;
    uint64_t hash = UINT64_C(14695981039346656037), mismatches = 0;
    for (unsigned page = 0; page < SHARING_PAGES; ++page) {
        if (sharing_time_left(deadline)) return -1;
        unsigned variant = sharing_variant(page, memory->write_slot);
        for (unsigned offset = 0; offset < SHARING_PAGE_SIZE; ++offset) {
            unsigned char actual = bytes[(size_t)page * SHARING_PAGE_SIZE + offset];
            mismatches += actual != sharing_byte(page, offset, variant);
            hash = (hash ^ actual) * UINT64_C(1099511628211);
        }
    }
    if (mismatches) { errno = EIO; return -1; }
    *checksum = hash;
    return sharing_time_left(deadline);
}
static int sharing_identity(const unsigned char *bytes, uint64_t *gpa) {
    int fd = open("/proc/self/pagemap", O_RDONLY | O_CLOEXEC);
    if (fd < 0) return -1;
    uint64_t entry = 0;
    off_t offset = (off_t)(((uintptr_t)bytes / SHARING_PAGE_SIZE) * sizeof(entry));
    ssize_t count = pread(fd, &entry, sizeof(entry), offset);
    int error = count < 0 ? errno : count != sizeof(entry) ? EIO : 0;
    if (close(fd) && !error) error = errno;
    if (error) { errno = error; return -1; }
    uint64_t pfn = entry & ((UINT64_C(1) << 55) - 1);
    if (!(entry & (UINT64_C(1) << 63)) || (entry & (UINT64_C(1) << 62)) ||
        !pfn || pfn > UINT64_MAX / SHARING_PAGE_SIZE) {
        errno = ENOTSUP; return -1;
    }
    *gpa = pfn * SHARING_PAGE_SIZE;
    return 0;
}
static int sharing_initialize(struct sharing_memory *memory, uint64_t deadline) {
    if (sysconf(_SC_PAGESIZE) != SHARING_PAGE_SIZE) { errno = ENOTSUP; return -1; }
    void *mapping = mmap(NULL, SHARING_BYTES, PROT_READ | PROT_WRITE,
        MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (mapping == MAP_FAILED) return -1;
    struct sharing_memory initialized = {.bytes = mapping, .write_slot = -1};
    if (madvise(mapping, SHARING_BYTES, MADV_NOHUGEPAGE) ||
        mlock(mapping, SHARING_BYTES) ||
        sharing_fill(&initialized, -1, deadline) ||
        sharing_scan(&initialized, deadline, &initialized.baseline_checksum) ||
        sharing_identity(initialized.bytes, &initialized.first_gpa)) {
        int error = errno;
        if (munmap(mapping, SHARING_BYTES)) return -1;
        errno = error; return -1;
    }
    *memory = initialized;
    return 0;
}
static int sharing_observation(struct sharing_memory *memory, const char *token,
    int command, uint64_t deadline) {
    if (sharing_time_left(deadline)) return -1;
    int initialized = !memory->bytes;
    if (!memory->bytes) {
        if (command != SHARING_INITIALIZE) { errno = ENODATA; return -1; }
        if (sharing_initialize(memory, deadline)) return -1;
    }
    if (command == SHARING_INITIALIZE && memory->write_slot >= 0) {
        errno = EBUSY; return -1;
    }
    int slot = command >= SHARING_WRITE_FIRST ? command - SHARING_WRITE_FIRST : -1;
    if (slot >= 0 && memory->write_slot >= 0 && slot != memory->write_slot) {
        errno = EBUSY; return -1;
    }
    uint64_t checksum = memory->baseline_checksum, first_gpa;
    if (sharing_identity(memory->bytes, &first_gpa)) return -1;
    if (first_gpa != memory->first_gpa) { errno = ESTALE; return -1; }
    /* Verify before writing so a damaged sibling/baseline cannot be repaired
     * into a successful acknowledgment by a later write command. */
    if (!initialized && sharing_scan(memory, deadline, &checksum)) return -1;
    if (slot >= 0) {
        memory->write_slot = slot;
        if (sharing_fill(memory, slot, deadline) ||
            sharing_scan(memory, deadline, &checksum)) return -1;
    }
    if (sharing_identity(memory->bytes, &first_gpa)) return -1;
    if (first_gpa != memory->first_gpa) { errno = ESTALE; return -1; }
    if (sharing_time_left(deadline)) return -1;
    char write_slot[16];
    if (memory->write_slot < 0) strcpy(write_slot, "null");
    else snprintf(write_slot, sizeof(write_slot), "%d", memory->write_slot);
    return emit_record(output,
        "OBS-BEGIN memory-sharing\n"
        "{\"schema\":1,\"request_token\":\"%s\",\"bytes\":67108864,"
        "\"page_size\":4096,\"pages\":16384,\"write_slot\":%s,"
        "\"verified_bytes\":67108864,\"mismatches\":0,\"checksum\":\"%016" PRIx64
        "\",\"baseline_checksum\":\"%016" PRIx64 "\",\"first_gpa\":%" PRIu64
        ",\"mlocked\":true}\nOBS-END memory-sharing\n",
        token, write_slot, checksum, memory->baseline_checksum, first_gpa);
}

enum {
    RECLAIM_PREPARE = SHARING_WRITE_LAST + 1,
    RECLAIM_DONATE,
    RECLAIM_REUSE,
    RECLAIM_VERIFY,
    RECLAIM_PAGE = 4096,
};
struct reclaim_status {
    char state[9], operation[8], token[33], checksum[17];
    uint64_t gpa, mismatches;
    unsigned abi, bytes, submitted, used_seen, verified_bytes, error;
};
static int reclaim_now(uint64_t *now) {
    struct timespec value;
    if (clock_gettime(CLOCK_MONOTONIC, &value)) return -1;
    *now = (uint64_t)value.tv_sec * UINT64_C(1000000000) + (uint64_t)value.tv_nsec;
    return 0;
}
static int reclaim_attribute(char *path, size_t capacity) {
    const char *root = "/sys/bus/virtio/devices";
    DIR *directory = opendir(root);
    if (!directory) return -1;
    unsigned found = 0;
    int error = 0;
    struct dirent *entry;
    errno = 0;
    while ((entry = readdir(directory))) {
        if (entry->d_name[0] == '.') continue;
        char candidate[PATH_MAX], device[PATH_MAX], identity[32] = {0};
        if (snprintf(candidate, sizeof(candidate), "%s/%s/silo_reclaim", root, entry->d_name) >= (int)sizeof(candidate) ||
            snprintf(device, sizeof(device), "%s/%s/device", root, entry->d_name) >= (int)sizeof(device)) {
            error = ENAMETOOLONG; break;
        }
        struct stat metadata;
        if (stat(candidate, &metadata)) {
            if (errno == ENOENT) { errno = 0; continue; }
            error = errno; break;
        }
        int fd = open(device, O_RDONLY | O_CLOEXEC);
        if (fd < 0) { error = errno; break; }
        ssize_t count = read(fd, identity, sizeof(identity) - 1);
        error = count < 0 ? errno : 0;
        if (close(fd) && !error) error = errno;
        if (error) break;
        if (strcmp(identity, "0x0005\n") || !S_ISREG(metadata.st_mode) ||
            (metadata.st_mode & 0777) != 0600 || metadata.st_uid != 0) {
            error = ENOTSUP; break;
        }
        if (++found != 1) { error = EEXIST; break; }
        if (strlen(candidate) >= capacity) { error = ENAMETOOLONG; break; }
        strcpy(path, candidate);
        errno = 0;
    }
    if (!error && errno) error = errno;
    if (closedir(directory) && !error) error = errno;
    if (!error && found != 1) error = ENODEV;
    if (error) { errno = error; return -1; }
    return 0;
}
static int reclaim_status_read(const char *path, struct reclaim_status *status) {
    char line[512] = {0}, canonical[512];
    int fd = open(path, O_RDONLY | O_CLOEXEC);
    if (fd < 0) return -1;
    ssize_t count = read(fd, line, sizeof(line) - 1);
    int error = count < 0 ? errno : 0;
    if (close(fd) && !error) error = errno;
    if (error) { errno = error; return -1; }
    int consumed = 0;
    int fields = sscanf(line,
        "abi=%u state=%8[a-z-] operation=%7[a-z] token=%32[0-9a-f] gpa=%" SCNu64
        " bytes=%u submitted=%u used_seen=%u verified_bytes=%u mismatches=%" SCNu64
        " checksum=%16[0-9a-f] error=%u%n",
        &status->abi, status->state, status->operation, status->token, &status->gpa,
        &status->bytes, &status->submitted, &status->used_seen, &status->verified_bytes,
        &status->mismatches, status->checksum, &status->error, &consumed);
    if (fields != 12 || count <= 0 || count >= (ssize_t)sizeof(line) - 1 ||
        consumed != count - 1 || line[consumed] != '\n' ||
        strlen(status->token) != 32 || strlen(status->checksum) != 16) {
        errno = EPROTO; return -1;
    }
    int length = snprintf(canonical, sizeof(canonical),
        "abi=%u state=%s operation=%s token=%s gpa=%" PRIu64
        " bytes=%u submitted=%u used_seen=%u verified_bytes=%u mismatches=%" PRIu64
        " checksum=%s error=%u\n",
        status->abi, status->state, status->operation, status->token, status->gpa,
        status->bytes, status->submitted, status->used_seen, status->verified_bytes,
        status->mismatches, status->checksum, status->error);
    if (length != count || strcmp(line, canonical) || status->abi != 1 ||
        status->bytes != RECLAIM_PAGE || status->submitted > 1 || status->used_seen > 1 ||
        (strcmp(status->state, "empty") && strcmp(status->state, "owned") &&
         strcmp(status->state, "inflight") && strcmp(status->state, "acked") &&
         strcmp(status->state, "c-ready") && strcmp(status->state, "failed")) ||
        (strcmp(status->operation, "none") && strcmp(status->operation, "prepare") &&
         strcmp(status->operation, "donate") && strcmp(status->operation, "reuse") &&
         strcmp(status->operation, "verify")) ||
        (status->verified_bytes != 0 && status->verified_bytes != RECLAIM_PAGE)) {
        errno = EPROTO; return -1;
    }
    if (status->error || !strcmp(status->state, "failed")) {
        errno = status->error && status->error <= INT_MAX ? (int)status->error : EIO;
        return -1;
    }
    return 0;
}
static int reclaim_write(const char *path, const char *request, size_t length) {
    int fd = open(path, O_WRONLY | O_CLOEXEC);
    if (fd < 0) return -1;
    ssize_t count = write(fd, request, length);
    int error = count < 0 ? errno : count != (ssize_t)length ? EIO : 0;
    if (close(fd) && !error) error = errno;
    if (error) { errno = error; return -1; }
    return 0;
}
static int reclaim_request(const char *request, size_t length, int complete,
    int command, uint64_t deadline) {
    char token[33] = {0}, path[PATH_MAX] = {0}, line[128];
    uint64_t target = 0;
    struct reclaim_status before = {0}, after = {0};
    int error;
    const char *stage = "request";
    const char *operation = command == RECLAIM_PREPARE ? "prepare" :
        command == RECLAIM_DONATE ? "donate" : command == RECLAIM_REUSE ? "reuse" : "verify";
    if (length < 32 || strlen(request) != length) { errno = EINVAL; goto failed; }
    for (unsigned index = 0; index < 32; ++index) {
        char byte = request[index];
        if (!((byte >= '0' && byte <= '9') || (byte >= 'a' && byte <= 'f'))) {
            errno = EINVAL; goto failed;
        }
    }
    memcpy(token, request, 32);
    if (command == RECLAIM_PREPARE) {
        if (length != 32) { errno = EINVAL; goto failed; }
    } else {
        if (length < 34 || request[32] != ' ') { errno = EINVAL; goto failed; }
        for (const char *digit = request + 33; *digit; ++digit) {
            if (*digit < '0' || *digit > '9') { errno = EINVAL; goto failed; }
        }
        errno = 0;
        char *end;
        target = strtoull(request + 33, &end, 10);
        if (errno || *end || !target || target % RECLAIM_PAGE) {
            if (!errno) errno = EINVAL;
            goto failed;
        }
    }
    stage = "request-deadline";
    if (sharing_time_left(deadline)) goto failed;
    if (!complete) { errno = EINVAL; stage = "incomplete-request"; goto failed; }
    stage = "required-diagnostic-balloon-attribute";
    if (reclaim_attribute(path, sizeof(path))) goto failed;
    stage = "kernel-status-before";
    if (reclaim_status_read(path, &before)) goto failed;
    stage = "kernel-ownership-before";
    int valid_state = 0;
    if (command == RECLAIM_PREPARE) {
        valid_state = !strcmp(before.state, "empty") && !strcmp(before.operation, "none") &&
            !before.gpa && !before.submitted && !before.used_seen;
    } else if (before.gpa == target) {
        if (command == RECLAIM_DONATE) {
            valid_state = !strcmp(before.state, "owned") && !strcmp(before.operation, "prepare") &&
                !before.submitted && !before.used_seen;
        } else if (command == RECLAIM_REUSE) {
            valid_state = (!strcmp(before.state, "inflight") || !strcmp(before.state, "acked")) &&
                !strcmp(before.operation, "donate") && before.submitted == 1 &&
                (!strcmp(before.state, "acked") == (before.used_seen == 1));
        } else {
            valid_state = !strcmp(before.state, "c-ready") && before.submitted == 1 &&
                before.used_seen == 1 &&
                (!strcmp(before.operation, "reuse") || !strcmp(before.operation, "verify"));
        }
    }
    if (!valid_state || !strcmp(before.token, token)) { errno = ESTALE; goto failed; }
    int line_length = command == RECLAIM_PREPARE ?
        snprintf(line, sizeof(line), "%s %s\n", operation, token) :
        snprintf(line, sizeof(line), "%s %s %" PRIu64 "\n", operation, token, target);
    if (line_length < 0 || line_length >= (int)sizeof(line)) { errno = EOVERFLOW; goto failed; }
    stage = "kernel-command";
    for (;;) {
        if (sharing_time_left(deadline)) goto failed;
        if (!reclaim_write(path, line, (size_t)line_length)) break;
        if (command != RECLAIM_REUSE || errno != EAGAIN) goto failed;
        delay();
    }
    stage = "kernel-status-after";
    if (reclaim_status_read(path, &after)) goto failed;
    stage = "kernel-transition";
    if (strcmp(after.token, token) || strcmp(after.operation, operation) ||
        !after.gpa || after.gpa % RECLAIM_PAGE ||
        (command != RECLAIM_PREPARE && after.gpa != target) ||
        (command == RECLAIM_PREPARE ?
            (strcmp(after.state, "owned") || after.submitted || after.used_seen) :
         command == RECLAIM_DONATE ?
            ((strcmp(after.state, "inflight") && strcmp(after.state, "acked")) ||
             after.submitted != 1 || (!strcmp(after.state, "acked") != (after.used_seen == 1))) :
            (strcmp(after.state, "c-ready") || after.submitted != 1 || after.used_seen != 1 ||
             after.verified_bytes != RECLAIM_PAGE || after.mismatches)) ||
        (command <= RECLAIM_DONATE &&
            (after.verified_bytes || after.mismatches || strcmp(after.checksum, "0000000000000000")))) {
        errno = EPROTO; goto failed;
    }
    stage = "request-deadline";
    if (sharing_time_left(deadline)) goto failed;
    return emit_record(output,
        "OBS-BEGIN memory-reclaim\n"
        "{\"schema\":1,\"ownership\":\"kernel-order0-retained\",\"request_token\":\"%s\","
        "\"operation\":\"%s\",\"success\":true,\"target_gpa\":%" PRIu64
        ",\"gpa_before\":%" PRIu64 ",\"gpa_after\":%" PRIu64
        ",\"sysfs_attribute\":\"%s\",\"kernel\":{\"abi\":%u,\"state\":\"%s\","
        "\"operation\":\"%s\",\"token\":\"%s\",\"gpa\":%" PRIu64
        ",\"bytes\":%u,\"submitted\":%u,\"used_seen\":%u,\"verified_bytes\":%u,"
        "\"mismatches\":%" PRIu64 ",\"checksum\":\"%s\",\"error\":%u}}\nOBS-END memory-reclaim\n",
        token, operation, after.gpa, before.gpa, after.gpa, path, after.abi, after.state,
        after.operation, after.token, after.gpa, after.bytes, after.submitted, after.used_seen,
        after.verified_bytes, after.mismatches, after.checksum, after.error);
failed:
    error = errno;
    emit_record(output,
        "OBS-BEGIN memory-reclaim\n"
        "{\"schema\":1,\"ownership\":\"kernel-order0-retained\",\"request_token\":\"%s\","
        "\"operation\":\"%s\",\"success\":false,\"target_gpa\":%" PRIu64
        ",\"error\":\"%s\",\"errno\":%d}\nOBS-END memory-reclaim\n",
        token, operation, target, stage, error);
    errno = error;
    return -1;
}

int main(void) {
    if (getpid() != 1) return 2;
    signal(SIGPIPE, SIG_IGN);
    mkdir("/dev", 0755); mkdir("/proc", 0755); mkdir("/sys", 0755);
    if (mount("devtmpfs", "/dev", "devtmpfs", 0, NULL) || mount("proc", "/proc", "proc", 0, NULL) || mount("sysfs", "/sys", "sysfs", 0, NULL)) return 3;
    output = open("/dev/hvc0", O_WRONLY | O_CLOEXEC);
    int control_input = open("/dev/hvc0", O_RDONLY | O_CLOEXEC | O_NONBLOCK);
    if (output < 0 || control_input < 0) return 4;
    if (rng_setup()) { fail("real-virtio-rng-setup"); return 15; }
    if (report_setup()) { fail("real-balloon-reporting-setup"); return 16; }
    char cmdline[4096] = {0}; int command = open("/proc/cmdline", O_RDONLY | O_CLOEXEC);
    if (command < 0 || read(command, cmdline, sizeof(cmdline) - 1) <= 0) return 5;
    close(command);
    char *port = strstr(cmdline, "probe.echo_port=");
    if (!port || !(echo_port = (unsigned)strtoul(port + strlen("probe.echo_port="), NULL, 10)) || echo_port > 65535) return 6;
    pid_t registers = fork();
    if (registers == 0) { dup2(output, STDOUT_FILENO); dup2(output, STDERR_FILENO); execl("/register-fixture", "register-fixture", (char *)NULL); _exit(127); }
    if (registers < 0) return 7;
    int pressure_pipe[2] = {-1, -1};
    pid_t pressure = -1;
    if (access("/device-pressure", X_OK) == 0) {
        if (pipe2(pressure_pipe, O_CLOEXEC)) return 10;
        pressure = fork();
        if (pressure == 0) {
            dup2(pressure_pipe[0], STDIN_FILENO); dup2(output, STDOUT_FILENO); dup2(output, STDERR_FILENO);
            close(pressure_pipe[0]); close(pressure_pipe[1]);
            execl("/device-pressure", "device-pressure", (char *)NULL); _exit(127);
        }
        if (pressure < 0) return 11;
        close(pressure_pipe[0]);
    }
    pthread_t clocks[2];
    if (pthread_create(&clocks[0], NULL, clock_secondary, NULL) || pthread_create(&clocks[1], NULL, clock_primary, NULL)) return 12;
    pthread_t threads[9];
    void *(*functions[9])(void *) = {disk_worker, disk_worker, rng_worker, report_worker, console_writer, console_reader, network_worker, vsock_worker, vsock_worker};
    for (unsigned index = 0; index < 9; ++index) {
        uintptr_t argument = index == 1 ? 1 : index == 7 ? 1027 : index == 8 ? 1028 : 0;
        int error = pthread_create(&threads[index], NULL, functions[index], (void *)argument);
        if (error) { errno = error; fail("pthread-create"); return 8; }
    }
    uint64_t sequence = 0;
    char pressure_command[1024]; size_t pressure_length = 0; int pressure_forward = 0;
    struct sharing_memory sharing = {.write_slot = -1};
    uint64_t reclaim_deadline = 0;
    uint64_t sharing_deadline = 0;
    for (;;) {
        int status;
        if (waitpid(registers, &status, WNOHANG) == registers) { fail("live-register-fixture-exited"); return 9; }
        if (pressure > 0 && waitpid(pressure, &status, WNOHANG) == pressure) { fail("pressure-fixture-exited"); return 13; }
        if (pressure_forward >= RECLAIM_PREPARE && sharing_time_left(reclaim_deadline)) {
            pressure_command[pressure_length] = '\0';
            reclaim_request(pressure_command, pressure_length, 0,
                pressure_forward, reclaim_deadline);
            fail("memory-reclaim"); return 19;
        }
        if (pressure_forward >= SHARING_INITIALIZE &&
            pressure_forward <= SHARING_WRITE_LAST && sharing_time_left(sharing_deadline)) {
            fail("memory-sharing-request"); return 18;
        }
        char input[64]; ssize_t count = read(control_input, input, sizeof(input));
        for (ssize_t i = 0; i < count; ++i) {
            if (pressure_forward) {
                if (input[i] == '\n') {
                    if (pressure_forward == 1) {
                        pressure_command[pressure_length++] = '\n';
                        if (write(pressure_pipe[1], pressure_command, pressure_length) != (ssize_t)pressure_length) fail("pressure-command-write");
                    } else if (pressure_forward >= RECLAIM_PREPARE) {
                        pressure_command[pressure_length] = '\0';
                        if (reclaim_request(pressure_command, pressure_length, 1,
                            pressure_forward, reclaim_deadline)) {
                            fail("memory-reclaim"); return 19;
                        }
                    } else {
                        if (pressure_length != 32) {
                            errno = EINVAL;
                            fail(pressure_forward >= SHARING_INITIALIZE ? "memory-sharing-request" : "device-counter-request");
                            return pressure_forward >= SHARING_INITIALIZE ? 18 : 14;
                        }
                        pressure_command[pressure_length] = '\0';
                        for (size_t index = 0; index < pressure_length; ++index) {
                            char byte = pressure_command[index];
                            if (!((byte >= '0' && byte <= '9') || (byte >= 'a' && byte <= 'f'))) {
                                errno = EINVAL;
                                fail(pressure_forward >= SHARING_INITIALIZE ? "memory-sharing-request" : "device-counter-request");
                                return pressure_forward >= SHARING_INITIALIZE ? 18 : 14;
                            }
                        }
                        if (pressure_forward == 2) emit_devices(++sequence, pressure_command);
                        else if (pressure_forward >= SHARING_INITIALIZE) {
                            if (sharing_observation(&sharing, pressure_command, pressure_forward, sharing_deadline)) {
                                fail("memory-sharing"); return 18;
                            }
                        } else if (memory_buffers(pressure_command, pressure_forward == 4, pressure_forward == 5)) {
                            fail("memory-buffer"); return 17;
                        }
                    }
                    pressure_length = 0; pressure_forward = 0;
                } else if (pressure_forward >= RECLAIM_PREPARE && pressure_length >= 53) {
                    pressure_command[pressure_length] = '\0';
                    reclaim_request(pressure_command, pressure_length, 0,
                        pressure_forward, reclaim_deadline);
                    fail("memory-reclaim"); return 19;
                } else if (pressure_forward >= SHARING_INITIALIZE &&
                    pressure_forward <= SHARING_WRITE_LAST && pressure_length >= 32) {
                    errno = EINVAL; fail("memory-sharing-request"); return 18;
                } else if (pressure_length + 1 < sizeof(pressure_command)) pressure_command[pressure_length++] = input[i];
                else { fail("pressure-command-bound"); return 14; }
                continue;
            }
            int sharing_command = input[i] == 'A' ? SHARING_INITIALIZE :
                input[i] == 'E' ? SHARING_VERIFY :
                input[i] == 'I' ? SHARING_WRITE_FIRST :
                input[i] == 'J' ? SHARING_WRITE_FIRST + 1 :
                input[i] == 'K' ? SHARING_WRITE_FIRST + 2 :
                input[i] == 'L' ? SHARING_WRITE_LAST : 0;
            if (sharing_command) {
                struct timespec now;
                if (clock_gettime(CLOCK_MONOTONIC, &now)) { fail("memory-sharing-clock"); return 18; }
                sharing_deadline = (uint64_t)now.tv_sec * UINT64_C(1000000000) +
                    (uint64_t)now.tv_nsec + UINT64_C(15000000000);
                pressure_forward = sharing_command;
                continue;
            }
            if (input[i] == 'Q' || input[i] == 'T' || input[i] == 'R' || input[i] == 'V') {
                uint64_t now;
                if (reclaim_now(&now)) { fail("memory-reclaim-clock"); return 19; }
                reclaim_deadline = now + UINT64_C(10000000000);
                pressure_forward = input[i] == 'Q' ? RECLAIM_PREPARE :
                    input[i] == 'T' ? RECLAIM_DONATE : input[i] == 'R' ? RECLAIM_REUSE : RECLAIM_VERIFY;
                continue;
            }
            if (input[i] == 'P' && pressure > 0) { pressure_forward = 1; continue; }
            if (input[i] == 'C') { pressure_forward = 2; continue; }
            if (input[i] == 'H') { pressure_forward = 3; continue; }
            if (input[i] == 'D') { pressure_forward = 4; continue; }
            if (input[i] == 'Z') { pressure_forward = 5; continue; }
            if (input[i] == 'B') atomic_store(&console_burst, 1);
            if (input[i] == 'O') observations();
            if (input[i] == 'M' && network_mac(1)) fail("destination-mac");
        }
        emit_devices(++sequence, "");
        struct timespec wait = {0, 100000000}; nanosleep(&wait, NULL);
    }
}

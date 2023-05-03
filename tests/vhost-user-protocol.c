/*
 * Vhost User Protocol tester
 *
 * Copyright (c) 2023 Red Hat, Inc.
 *
 * Authors:
 *  Albert Esteve <aesteve@redhat.com>
 *
 * This work is licensed under the terms of the GNU GPL, version 2 or
 * later.  See the COPYING file in the top-level directory.
 * 
 * To execute the test, compile and execute the backend:
 *    $ ./tests/vhost-user-protocol
 * Then, run qemu with any vhost-user device you want to test with, e.g.:
 *    $ /qemu \
 *      -enable-kvm -m 512 -smp 2 \
 *      -object memory-backend-memfd,id=mem,size=512M,share=yes \
 *      -m 4096 -device vhost-user-rng-pci,chardev=char0 \
 *      -chardev socket,id=char0,path=/tmp/vupr.sock \
 *      fedora.img
 * The communication channel is then exercised and the tests will run, the
 * results will appear in the console.
 */


#define _FILE_OFFSET_BITS 64

#include "qemu/osdep.h"
#include "qemu/atomic.h"
#include "qemu/ctype.h"
#include "qemu/iov.h"
#include "qemu/uuid.h"
#include "standard-headers/linux/virtio_net.h"
#include "libvhost-user.h"

#define VHOST_USER_PROTOCOL_DEBUG 1

#define DPRINT(...) \
    do { \
        if (VHOST_USER_PROTOCOL_DEBUG) { \
            printf(__VA_ARGS__); \
        } \
    } while (0)

enum {
    VHOST_USER_PROTOCOL_MAX_QUEUES = 8,
};

typedef void (*CallbackFunc)(int sock, void *ctx);

typedef struct Event {
    void *ctx;
    CallbackFunc callback;
} Event;

typedef struct Dispatcher {
    int max_sock;
    fd_set fdset;
    Event events[FD_SETSIZE];
} Dispatcher;

typedef struct VuprDev {
    VuDev vudev;
    Dispatcher dispatcher;
    int hdrlen;
    int sock;
    int ready;
    int test_step;
    int quit;
    struct {
        int fd;
        void *addr;
        pthread_t thread;
    } notifier;
} VuprDev;

static void
vupr_die(const char *s)
{
    perror(s);
    exit(1);
}

static int
dispatcher_init(Dispatcher *dispr)
{
    FD_ZERO(&dispr->fdset);
    dispr->max_sock = -1;
    return 0;
}

static int
dispatcher_add(Dispatcher *dispr, int sock, void *ctx, CallbackFunc cb)
{
    if (sock >= FD_SETSIZE) {
        fprintf(stderr,
                "Error: Failed to add new event. sock %d should be less than %d\n",
                sock, FD_SETSIZE);
        return -1;
    }

    dispr->events[sock].ctx = ctx;
    dispr->events[sock].callback = cb;

    FD_SET(sock, &dispr->fdset);
    if (sock > dispr->max_sock) {
        dispr->max_sock = sock;
    }
    DPRINT("Added sock %d for watching. max_sock: %d\n",
           sock, dispr->max_sock);
    return 0;
}

static int
dispatcher_remove(Dispatcher *dispr, int sock)
{
    if (sock >= FD_SETSIZE) {
        fprintf(stderr,
                "Error: Failed to remove event. sock %d should be less than %d\n",
                sock, FD_SETSIZE);
        return -1;
    }

    FD_CLR(sock, &dispr->fdset);
    DPRINT("Sock %d removed from dispatcher watch.\n", sock);
    return 0;
}

/* timeout in us */
static int
dispatcher_wait(Dispatcher *dispr, uint32_t timeout)
{
    struct timeval tv;
    tv.tv_sec = timeout / 1000000;
    tv.tv_usec = timeout % 1000000;

    fd_set fdset = dispr->fdset;

    /* wait until some of sockets become readable. */
    int rc = select(dispr->max_sock + 1, &fdset, 0, 0, &tv);

    if (rc == -1) {
        vupr_die("select");
    }

    /* Timeout */
    if (rc == 0) {
        return 0;
    }

    /* Now call callback for every ready socket. */

    int sock;
    for (sock = 0; sock < dispr->max_sock + 1; sock++) {
        /* The callback on a socket can remove other sockets from the
         * dispatcher, thus we have to check that the socket is
         * still not removed from dispatcher's list
         */
        if (FD_ISSET(sock, &fdset) && FD_ISSET(sock, &dispr->fdset)) {
            Event *e = &dispr->events[sock];
            e->callback(sock, e->ctx);
        }
    }

    return 0;
}

static void
vupr_receive_cb(int sock, void *ctx)
{
    VuprDev *vupr = (VuprDev *)ctx;

    if (!vu_dispatch(&vupr->vudev)) {
        fprintf(stderr, "Error while dispatching\n");
    }
}

typedef struct WatchData {
    VuDev *dev;
    vu_watch_cb cb;
    void *data;
} WatchData;

static void
watch_cb(int sock, void *ctx)
{
    struct WatchData *wd = ctx;

    wd->cb(wd->dev, VU_WATCH_IN, wd->data);
}

static void
vupr_set_watch(VuDev *dev, int fd, int condition,
               vu_watch_cb cb, void *data)
{
    VuprDev *vupr = container_of(dev, VuprDev, vudev);
    static WatchData watches[FD_SETSIZE];
    struct WatchData *wd = &watches[fd];

    wd->cb = cb;
    wd->data = data;
    wd->dev = dev;
    dispatcher_add(&vupr->dispatcher, fd, wd, watch_cb);
}

static void
vupr_remove_watch(VuDev *dev, int fd)
{
    VuprDev *vupr = container_of(dev, VuprDev, vudev);

    dispatcher_remove(&vupr->dispatcher, fd);
}

static int
vupr_send_rarp_exec(VuDev *dev, VhostUserMsg *vmsg)
{
    DPRINT("Function %s() not implemented yet.\n", __func__);
    return 0;
}

#define VHOST_USER_VERSION 1

static void
vupr_panic(VuDev *dev, const char *msg)
{
    VuprDev *vupr = container_of(dev, VuprDev, vudev);

    fprintf(stderr, "PANIC: %s\n", msg);

    dispatcher_remove(&vupr->dispatcher, dev->sock);
    vupr->quit = 1;
}

static int
send_add_object_msg(VuDev *dev, int dmabuf_fd, QemuUUID *uuid)
{
    g_print("Sending UUID: %s\n", qemu_uuid_unparse_strdup(uuid));
    VhostUserMsg msg = {
        .request = VHOST_USER_BACKEND_SHARED_OBJECT,
        .size = sizeof(msg.payload.object),
        .flags = VHOST_USER_VERSION,
        .payload.object = {
            .dmabuf_fd = dmabuf_fd,
            .type = VHOST_SHARED_OBJECT_ADD,
        },
    };
    memcpy(msg.payload.object.uuid, uuid->data, sizeof(uuid->data));

    pthread_mutex_lock(&dev->slave_mutex);
    if (!dev->write_msg(dev, dev->slave_fd, &msg)) {
        pthread_mutex_unlock(&dev->slave_mutex);
        return 1;    
    }
    pthread_mutex_unlock(&dev->slave_mutex);
    return 0;
}

static int
send_rm_object_msg(VuDev *dev, QemuUUID *uuid)
{
    g_print("Sending UUID: %s\n", qemu_uuid_unparse_strdup(uuid));
    VhostUserMsg msg = {
        .request = VHOST_USER_BACKEND_SHARED_OBJECT,
        .size = sizeof(msg.payload.object),
        .flags = VHOST_USER_VERSION,
        .payload.object = {
            .type = VHOST_SHARED_OBJECT_REMOVE,
        },
    };
    memcpy(msg.payload.object.uuid, uuid->data, sizeof(uuid->data));

    pthread_mutex_lock(&dev->slave_mutex);
    if (!dev->write_msg(dev, dev->slave_fd, &msg)) {
        pthread_mutex_unlock(&dev->slave_mutex);
        return 1;    
    }
    pthread_mutex_unlock(&dev->slave_mutex);
    return 0;
}

static bool
send_lookup_object_msg(VuDev *dev, QemuUUID *uuid, int *dmabuf_fd)
{
    g_print("Looking for UUID: %s\n", qemu_uuid_unparse_strdup(uuid));
    unsigned char ch_uuid[16];

    memcpy(ch_uuid, uuid->data, sizeof(uuid->data));
    
    return vu_get_shared_object(dev, ch_uuid, dmabuf_fd);
}



static int
test_add_virtio_dmabuf(VuDev *dev, QemuUUID *uuid)
{
    DPRINT("Add dmabuf_fd to shared table\n");
    send_add_object_msg(dev, 15, uuid);

    DPRINT("test_add__virtio_dmabuf executed!\n");
    return 0;
}

static int
get_virtio_dmabuf(VuDev *dev, QemuUUID *uuid)
{
    DPRINT("Get dmabuf_fd from shared table\n");
    int dmabuf_rec = 0;
    if (!send_lookup_object_msg(dev, uuid, &dmabuf_rec)) {
        DPRINT("UUID not found!\n");
    }
    return dmabuf_rec;
}

static int
rm_virtio_dmabuf(VuDev *dev, QemuUUID *uuid)
{
    send_rm_object_msg(dev, uuid);
    return 0;
}

static int
vupr_process_msg(VuDev *dev, VhostUserMsg *vmsg, int *do_reply)
{
    DPRINT("%s: msg %d\n", __func__, vmsg->request);
    switch (vmsg->request) {
    case VHOST_USER_SEND_RARP:
        *do_reply = vupr_send_rarp_exec(dev, vmsg);
        return 1;
    case VHOST_USER_SET_VRING_ERR://VHOST_USER_SET_BACKEND_REQ_FD:
    {
        VuprDev *vupr = container_of(dev, VuprDev, vudev);
        vupr->ready = 1;
        return 0;
    }
    default:
        /* let the library handle the rest */
        return 0;
    }

    return 0;
}

static void
vupr_set_features(VuDev *dev, uint64_t features)
{
    VuprDev *vupr = container_of(dev, VuprDev, vudev);

    if ((features & (1ULL << VIRTIO_F_VERSION_1)) ||
        (features & (1ULL << VIRTIO_NET_F_MRG_RXBUF))) {
        vupr->hdrlen = 12;
    } else {
        vupr->hdrlen = 10;
    }
}

static uint64_t
vupr_get_features(VuDev *dev)
{
    return 1ULL << VIRTIO_NET_F_GUEST_ANNOUNCE |
        1ULL << VIRTIO_NET_F_MRG_RXBUF |
        1ULL << VIRTIO_F_VERSION_1;
}

static void
vupr_queue_set_started(VuDev *dev, int qidx, bool started)
{
    VuprDev *vupr = container_of(dev, VuprDev, vudev);
    VuVirtq *vq = vu_get_queue(dev, qidx);

    if (started && vupr->notifier.fd >= 0) {
        vu_set_queue_host_notifier(dev, vq, vupr->notifier.fd,
                                   qemu_real_host_page_size(),
                                   qidx * qemu_real_host_page_size());
    }
}

static int
video_get_config(VuDev *dev, uint8_t *config, uint32_t len)
{
    return 0;
}

static int
video_set_config(VuDev *dev, const uint8_t *data,
                 uint32_t offset, uint32_t size,
                 uint32_t flags)
{
    g_debug("%s: ", __func__);
    /*
     * set_config is required to set the F_CONFIG feature,
     * but we can just ignore the call
     */
    return 0;
}

static bool
vupr_queue_is_processed_in_order(VuDev *dev, int qidx)
{
    return true;
}

static const VuDevIface vuiface = {
    .get_features = vupr_get_features,
    .set_features = vupr_set_features,
    .process_msg = vupr_process_msg,
    .get_config = video_get_config,
    .set_config = video_set_config,
    .queue_set_started = vupr_queue_set_started,
    .queue_is_processed_in_order = vupr_queue_is_processed_in_order,
};

static void
vupr_accept_cb(int sock, void *ctx)
{
    VuprDev *dev = (VuprDev *)ctx;
    int conn_fd;
    struct sockaddr_un un;
    socklen_t len = sizeof(un);

    conn_fd = accept(sock, (struct sockaddr *) &un, &len);
    if (conn_fd == -1) {
        vupr_die("accept()");
    }
    DPRINT("Got connection from remote peer on sock %d\n", conn_fd);

    if (!vu_init(&dev->vudev,
                 VHOST_USER_PROTOCOL_MAX_QUEUES,
                 conn_fd,
                 vupr_panic,
                 NULL,
                 vupr_set_watch,
                 vupr_remove_watch,
                 &vuiface)) {
        fprintf(stderr, "Failed to initialize libvhost-user\n");
        exit(1);
    }

    dispatcher_add(&dev->dispatcher, conn_fd, ctx, vupr_receive_cb);
    dispatcher_remove(&dev->dispatcher, sock);
}

static VuprDev *
vupr_new(const char *path)
{
    VuprDev *dev = (VuprDev *) calloc(1, sizeof(VuprDev));
    struct sockaddr_un un;
    CallbackFunc cb;
    size_t len;

    if (strlen(path) >= sizeof(un.sun_path)) {
        fprintf(stderr, "unix domain socket path '%s' is too long\n", path);
        exit(1);
    }

    /* Get a UNIX socket. */
    dev->sock = socket(AF_UNIX, SOCK_STREAM, 0);
    if (dev->sock == -1) {
        vupr_die("socket");
    }

    dev->notifier.fd = -1;

    un.sun_family = AF_UNIX;
    strcpy(un.sun_path, path);
    len = sizeof(un.sun_family) + strlen(path);

    unlink(path);

    if (bind(dev->sock, (struct sockaddr *) &un, len) == -1) {
        vupr_die("bind");
    }

    if (listen(dev->sock, 1) == -1) {
        vupr_die("listen");
    }
    cb = vupr_accept_cb;

    DPRINT("Waiting for connections on UNIX socket %s ...\n", path);

    dispatcher_init(&dev->dispatcher);

    dispatcher_add(&dev->dispatcher, dev->sock, (void *)dev, cb);

    return dev;
}

static void
vupr_shared_dmabuf_test(VuprDev *dev, QemuUUID *uuid)
{
    if (dev->test_step == 0) {
        test_add_virtio_dmabuf(&dev->vudev, uuid);
        dev->test_step = 1;
    } else if (dev->test_step == 1) {
        int ret = get_virtio_dmabuf(&dev->vudev, uuid);
        assert(ret == 15);
        dev->test_step = 2;
    } else if (dev->test_step == 2) {
        rm_virtio_dmabuf(&dev->vudev, uuid);
        dev->test_step = 3;
    } else if (dev->test_step == 3) {
        int ret = get_virtio_dmabuf(&dev->vudev, uuid);
        assert(ret == -1);
        dev->test_step = 0;
        dev->ready = 0;
    }
}


static void
vupr_run(VuprDev *dev)
{
    QemuUUID uuid;
    qemu_uuid_generate(&uuid);
    while (!dev->quit) {
        if (dev->ready == 1) {
            vupr_shared_dmabuf_test(dev, &uuid);
        }
        /* timeout 200ms */
        dispatcher_wait(&dev->dispatcher, 200000);
        /* Here one can try polling strategy. */
    }
}

#define DEFAULT_UD_SOCKET "/tmp/vupr.sock"

static const char *ud_socket_path = DEFAULT_UD_SOCKET;

int
main(int argc, char *argv[])
{
    VuprDev *dev;
    int opt;
    
    while ((opt = getopt(argc, argv, "u")) != -1) {

        switch (opt) {
        case 'u':
            ud_socket_path = strdup(optarg);
            break;
        default:
            goto out;
        }
    }

    DPRINT("ud socket: %s\n", ud_socket_path);
    dev = vupr_new(ud_socket_path);
    if (!dev) {
        return 1;
    }
    
    vupr_run(dev);

    vu_deinit(&dev->vudev);

    return 0;

out:
    fprintf(stderr, "Usage: %s ", argv[0]);
    fprintf(stderr, "[-u ud_socket_path]\n");
    fprintf(stderr, "\t-u path to unix domain socket. default: %s\n",
            DEFAULT_UD_SOCKET);

    return 1;
}

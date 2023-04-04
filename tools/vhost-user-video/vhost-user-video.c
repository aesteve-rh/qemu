/*
 * VIRTIO Video Emulation via vhost-user
 *
 * Copyright (c) 2023 Red Hat, Inc.
 * Copyright (c) 2021 Linaro Ltd
 *
 * Authors:
 *      Peter Griffin <peter.griffin@linaro.org>
 *      Albert Esteve <aesteve@redhat.com>
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#define G_LOG_DOMAIN "vhost-user-video"
#define G_LOG_USE_STRUCTURED 1

#include <glib.h>
#include <gio/gio.h>
#include <gio/gunixsocketaddress.h>
#include <glib-unix.h>
#include <glib/gstdio.h>
#include <stdio.h>
#include <string.h>
#include <inttypes.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/mman.h>
#include <unistd.h>
#include <endian.h>
#include <assert.h>

#include "libvhost-user-glib.h"
#include "libvhost-user.h"
#include "standard-headers/linux/virtio_video.h"

#include "qemu/compiler.h"
#include "qemu/iov.h"

#include "vuvideo.h"
#include "v4l2_backend.h"
#include "virtio_video_helpers.h"

#ifndef container_of
#define container_of(ptr, type, member) ({                      \
        const typeof(((type *) 0)->member) * __mptr = (ptr);     \
        (type *) ((char *) __mptr - offsetof(type, member)); })
#endif

static gchar *socket_path;
static gchar *v4l2_path;
static gint socket_fd = -1;
static gboolean print_cap;
static gboolean verbose;
static gboolean debug;

static GOptionEntry options[] = {
    { "socket-path", 0, 0, G_OPTION_ARG_FILENAME, &socket_path,
      "Location of vhost-user Unix domain socket, "
      "incompatible with --fd", "PATH" },
    { "v4l2-device", 0, 0, G_OPTION_ARG_FILENAME, &v4l2_path,
      "Location of v4l2 device node", "PATH" },
    { "fd", 0, 0, G_OPTION_ARG_INT, &socket_fd,
      "Specify the fd of the backend, "
      "incompatible with --socket-path", "FD" },
    { "print-capabilities", 0, 0, G_OPTION_ARG_NONE, &print_cap,
      "Output to stdout the backend capabilities "
      "in JSON format and exit", NULL},
    { "verbose", 'v', 0, G_OPTION_ARG_NONE, &verbose,
      "Be more verbose in output", NULL},
    { "debug", 0, 0, G_OPTION_ARG_NONE, &debug,
      "Include debug output", NULL},
    { NULL }
};

enum {
    VHOST_USER_VIDEO_MAX_QUEUES = 2,
};

static const char *
vv_cmd_to_string(int cmd)
{
#define CMD(cmd) [cmd] = #cmd
    static const char *vg_cmd_str[] = {
        /* Command */
        CMD(VIRTIO_V4L2_CMD_OPEN),
        CMD(VIRTIO_V4L2_CMD_CLOSE),
        CMD(VIRTIO_V4L2_CMD_IOCTL),
        CMD(VIRTIO_V4L2_CMD_MMAP),
        CMD(VIRTIO_V4L2_CMD_MUNMAP),
    };
#undef CMD

    if (cmd >= 0 && cmd < G_N_ELEMENTS(vg_cmd_str)) {
        return vg_cmd_str[cmd];
    } else {
        return "unknown";
    }
}

static void video_panic(VuDev *dev, const char *msg)
{
    g_critical("%s\n", msg);
    exit(EXIT_FAILURE);
}

static uint64_t video_get_features(VuDev *dev)
{
    g_info("%s: replying", __func__);
    return 0;
}

static void video_set_features(VuDev *dev, uint64_t features)
{
    if (features) {
        g_autoptr(GString) s = g_string_new("Requested un-handled feature");
        g_string_append_printf(s, " 0x%" PRIx64 "", features);
        g_info("%s: %s", __func__, s->str);
    }
}

/*
 * The configuration of the device is static and set when we start the
 * daemon.
 */
static int
video_get_config(VuDev *dev, uint8_t *config, uint32_t len)
{
    VuVideo *v = container_of(dev, VuVideo, dev.parent);

    g_return_val_if_fail(len <= sizeof(struct virtio_v4l2_config), -1);
    v->virtio_config.device_caps = v->v4l2_dev->capabilities;
    v->virtio_config.vfl_type = 0;
    //v->virtio_config.bus_info = v->v4l2_dev->bus_info;
    memcpy(v->virtio_config.bus_info, v->v4l2_dev->bus_info, 32);

    memcpy(config, &v->virtio_config, len);

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

/*
 * Handlers for individual control messages
 */

#define EVENT_WQ_IDX 1

/*static void *stream_worker_thread(gpointer data)
{
    int ret;
    struct stream *s = data;
    VuVideo *v = s->video;
    VugDev *vugdev = &v->dev;
    VuDev *vudev = &vugdev->parent;
    VuVirtq *vq = vu_get_queue(vudev, EVENT_WQ_IDX);
    VuVirtqElement *elem;
    size_t len;

    struct v4l2_event ev;
    struct virtio_video_event vio_event;

    fd_set efds, rfds, wfds;
    bool have_event, have_read, have_write;
    enum v4l2_buf_type buf_type;

    fcntl(s->fd, F_SETFL, fcntl(s->fd, F_GETFL) | O_NONBLOCK);

    while (true) {
        int res;

        g_mutex_lock(&s->mutex);

        g_debug("Stream: id %d state %d", s->stream_id, s->stream_state);
        while (s->stream_state != STREAM_DESTROYING &&
               s->stream_state != STREAM_STREAMING &&
               s->stream_state != STREAM_DRAINING)
            g_cond_wait(&s->stream_cond, &s->mutex);

        if (s->stream_state == STREAM_DESTROYING) {
            g_debug("stream worker thread exiting!");
            s->stream_state = STREAM_DESTROYED;
            g_cond_signal(&s->stream_cond);
            g_mutex_unlock(&s->mutex);
            g_thread_exit(0);
        }

        g_mutex_unlock(&s->mutex);

        FD_ZERO(&efds);
        FD_SET(s->fd, &efds);
        FD_ZERO(&rfds);
        FD_SET(s->fd, &rfds);
        FD_ZERO(&wfds);
        FD_SET(s->fd, &wfds);

        struct timeval tv = { 0 , 500000 };
        res = select(s->fd + 1, &rfds, &wfds, &efds, &tv);
        if (res < 0) {
            g_printerr("%s:%d - select() failed: %s (%d)\n",
                       __func__, __LINE__, g_strerror(errno), errno);
            break;
        }

        if (res == 0) {
            g_debug("%s:%d - select() timeout", __func__, __LINE__);
            continue;
        }

        have_event = FD_ISSET(s->fd, &efds);
        have_read = FD_ISSET(s->fd, &rfds);
        have_write = FD_ISSET(s->fd, &wfds);

        g_debug("%s:%d have_event=%d, have_write=%d, have_read=%d\n",
                __func__, __LINE__, FD_ISSET(s->fd, &efds),
                FD_ISSET(s->fd, &wfds), FD_ISSET(s->fd, &rfds));

        g_mutex_lock(&s->mutex);

        if (have_event) {
            g_debug("%s: have_event!", __func__);
            res = ioctl(s->fd, VIDIOC_DQEVENT, &ev);
            if (res < 0) {
                g_printerr("%s:%d - VIDIOC_DQEVENT failed: %s (%d)\n",
                           __func__, __LINE__, g_strerror(errno), errno);
                break;
            }
            v4l2_to_virtio_event(&ev, &vio_event);

            elem = vu_queue_pop(vudev, vq, sizeof(struct VuVirtqElement));
            if (!elem) {
                g_debug("%s:%d\n", __func__, __LINE__);
                break;
            }

            len = iov_from_buf_full(elem->in_sg,
                                    elem->in_num, 0, (void *) &vio_event,
                                    sizeof(struct virtio_video_event));

            if (vio_event.event_type) {
                vu_queue_push(vudev, vq, elem, len);
                vu_queue_notify(vudev, vq);
            }
        }

        if (have_read && s->capture_streaming) {
            buf_type = s->has_mplane ? V4L2_BUF_TYPE_VIDEO_CAPTURE_MPLANE
                : V4L2_BUF_TYPE_VIDEO_CAPTURE;

            enum virtio_video_mem_type mem_type =
                get_queue_mem_type(s, VIRTIO_VIDEO_QUEUE_TYPE_INPUT);
            enum v4l2_memory memory = get_v4l2_memory(mem_type);

            ret = v4l2_dequeue_buffer(s->fd, buf_type, memory, s);
            if (ret < 0) {
                g_info("%s: v4l2_dequeue_buffer() failed CAPTURE ret(%d)",
                       __func__, ret);

                if (ret == -EPIPE) {
                    g_debug("Dequeued last buffer, stop streaming.");
                    v4l2_streamoff(s, buf_type);
                }
            }
        }

        if (have_write && s->output_streaming) {
            buf_type = s->has_mplane ? V4L2_BUF_TYPE_VIDEO_OUTPUT_MPLANE
                : V4L2_BUF_TYPE_VIDEO_OUTPUT;

            enum virtio_video_mem_type mem_type =
                get_queue_mem_type(s, VIRTIO_VIDEO_QUEUE_TYPE_OUTPUT);
            enum v4l2_memory memory = get_v4l2_memory(mem_type);

            ret = v4l2_dequeue_buffer(s->fd, buf_type, memory, s);
            if (ret < 0) {
                g_info("%s: v4l2_dequeue_buffer() failed OUTPUT ret(%d)",
                       __func__, ret);
            }
        }

        g_mutex_unlock(&s->mutex);
    }

    return NULL;
}*/

void send_ctrl_response(struct vu_video_ctrl_command *vio_cmd,
                       uint8_t *resp, size_t resp_len)
{
    size_t len;

    virtio_v4l2_ctrl_hdr_htole((struct virtio_v4l2_cmd_header *)resp);

    /* send virtio_video_resource_queue_resp */
    len = iov_from_buf_full(vio_cmd->elem.in_sg,
                            vio_cmd->elem.in_num, 0, resp, resp_len);

    if (len != resp_len) {
        g_critical("%s: response size incorrect %zu vs %zu",
                   __func__, len, resp_len);
    }

    vu_queue_push(vio_cmd->dev, vio_cmd->vq, &vio_cmd->elem, len);
    vu_queue_notify(vio_cmd->dev, vio_cmd->vq);

    if (vio_cmd->finished) {
        g_free(vio_cmd->cmd_buf);
        free(vio_cmd);
    }
}

void send_ctrl_response_nodata(struct vu_video_ctrl_command *vio_cmd)
{
    send_ctrl_response(vio_cmd, vio_cmd->cmd_buf,
                       sizeof(struct virtio_video_cmd_hdr));
}

static int
handle_open_cmd(struct VuVideo *v,
                struct vu_video_ctrl_command *cmd)
{
    uint32_t status = 0;
    struct virtio_v4l2_session *session;
    struct virtio_v4l2_resp_open resp;
    /* TODO use a proper ID generator to avoid leaking FDs to the guest... */
    int session_id = v4l2_open(v->v4l2_dev->devname);
    if (session_id < 0) {
        g_printerr("Error opening device %s: %s (%d).\n", v->v4l2_dev->devname,
                   g_strerror(errno), errno);
        status = errno;
        goto out;
    }
    session = g_new0(struct virtio_v4l2_session, 1);
    session->id = session_id;
    session->fd = session_id;
    session->v4l2_dev = v->v4l2_dev;
    g_hash_table_insert(v->sessions, GINT_TO_POINTER(session_id), session);
    g_debug("Add new session: id %d", session_id);

out:
    resp.hdr.status = status;
    resp.session_id = session_id;
    cmd->finished = true;
    send_ctrl_response(cmd, (uint8_t *)&resp,
                       sizeof(struct virtio_v4l2_resp_open));
    return 0;
}

static int
handle_close_cmd(struct VuVideo *v,
                struct vu_video_ctrl_command *cmd)
{
    uint32_t status = 0;
    struct virtio_v4l2_cmd_close *close_cmd =
        (struct virtio_v4l2_cmd_close *) cmd->cmd_buf;
    struct virtio_v4l2_session *session;
    struct virtio_v4l2_resp_close resp;

    session = (struct virtio_v4l2_session *) g_hash_table_lookup(
        v->sessions, GINT_TO_POINTER(close_cmd->session_id));
    if (session == NULL) {
        g_printerr("Error session %d not found.\n", close_cmd->session_id);
        status = EINVAL;
        goto out;
    }
    v4l2_close(session->fd);
    g_hash_table_remove(v->sessions, GINT_TO_POINTER(close_cmd->session_id));
    g_debug("Remove session: id %d", close_cmd->session_id);

out:
    resp.hdr.status = status;
    cmd->finished = true;
    send_ctrl_response(cmd, (uint8_t *)&resp,
                       sizeof(struct virtio_v4l2_resp_close));
    return 0;
}

static int
handle_ioctl_cmd(struct VuVideo *v,
                 struct vu_video_ctrl_command *cmd)
{
    struct virtio_v4l2_cmd_ioctl *ioctl_cmd = (void *) cmd->cmd_buf;
    struct virtio_v4l2_session *session;

    session = (struct virtio_v4l2_session *) g_hash_table_lookup(
        v->sessions, GINT_TO_POINTER(ioctl_cmd->session_id));
    if (session == NULL) {
        g_printerr("Session id (%d) not found.", ioctl_cmd->session_id);
        goto err;
    }

    g_debug("%s: session_id (%d) received ioctl %s", __func__,
            ioctl_cmd->session_id, vv_ioctl_to_string(ioctl_cmd->code));

    switch (ioctl_cmd->code) {
    case VIRTIO_V4L2_IOCTL_CODE(VIDIOC_ENUM_FMT):
        virtio_video_send_enum_fmt(session->fd, cmd, ioctl_cmd);
        break;
    case VIRTIO_V4L2_IOCTL_CODE(VIDIOC_G_FMT):
        virtio_video_send_get_fmt(session->fd, cmd, ioctl_cmd);
        break;
    case VIRTIO_V4L2_IOCTL_CODE(VIDIOC_S_FMT):
        virtio_video_send_set_fmt(session->fd, cmd, ioctl_cmd);
        break;
    case VIRTIO_V4L2_IOCTL_CODE(VIDIOC_REQBUFS):
        virtio_video_send_reqbufs(session->fd, cmd, ioctl_cmd);
        break;
    case VIRTIO_V4L2_IOCTL_CODE(VIDIOC_QUERYBUF):
        virtio_video_send_querybufs(session->fd, cmd, ioctl_cmd);
        break;
    case VIRTIO_V4L2_IOCTL_CODE(VIDIOC_ENUMINPUT):
        virtio_video_send_enum_input(session->fd, cmd, ioctl_cmd);
        break;
    case VIRTIO_V4L2_IOCTL_CODE(VIDIOC_QUERYCTRL):
        virtio_video_send_queryctrl(session->fd, cmd, ioctl_cmd);
        break;
    case VIRTIO_V4L2_IOCTL_CODE(VIDIOC_G_INPUT):
    case VIRTIO_V4L2_IOCTL_CODE(VIDIOC_S_INPUT):
    case VIRTIO_V4L2_IOCTL_CODE(VIDIOC_G_OUTPUT):
    case VIRTIO_V4L2_IOCTL_CODE(VIDIOC_S_OUTPUT):
        virtio_video_send_s_g_io(session->fd, cmd, ioctl_cmd, ioctl_cmd->code);
        break;
    case VIRTIO_V4L2_IOCTL_CODE(VIDIOC_ENUMOUTPUT):
        virtio_video_send_enum_output(session->fd, cmd, ioctl_cmd);
        break;
    case VIRTIO_V4L2_IOCTL_CODE(VIDIOC_TRY_FMT):
        virtio_video_send_try_fmt(session->fd, cmd, ioctl_cmd);
        break;
    case VIRTIO_V4L2_IOCTL_CODE(VIDIOC_SUBSCRIBE_EVENT):
    case VIRTIO_V4L2_IOCTL_CODE(VIDIOC_UNSUBSCRIBE_EVENT):
        virtio_video_send_un_subscribe_event(
            session->fd, cmd, ioctl_cmd, ioctl_cmd->code);
        break;
    case VIRTIO_V4L2_IOCTL_CODE(VIDIOC_G_SELECTION):
        virtio_video_send_g_selection(session->fd, cmd, ioctl_cmd);
        break;
    case VIRTIO_V4L2_IOCTL_CODE(VIDIOC_S_SELECTION):
        virtio_video_send_s_selection(session->fd, cmd, ioctl_cmd);
        break;
    case VIRTIO_V4L2_IOCTL_CODE(VIDIOC_QUERY_EXT_CTRL):
        virtio_video_send_query_ext_ctrl(session->fd, cmd, ioctl_cmd);
        break;
    default:
        g_printerr("Unknown IOCTL command code: %d", ioctl_cmd->code);
        goto err;
    }
    return 0;

err:
    struct virtio_v4l2_resp_ioctl resp;
    resp.hdr.status = ENOTTY;
    cmd->finished = true;
    send_ctrl_response(cmd, (uint8_t *)&resp,
                       sizeof(struct virtio_v4l2_resp_ioctl));
    return -1;
}

static void
vv_process_cmd(VuVideo *video, struct vu_video_ctrl_command *cmd)
{
    switch (cmd->cmd_hdr->cmd) {
    case VIRTIO_V4L2_CMD_OPEN:
        handle_open_cmd(video, cmd);
        break;
    case VIRTIO_V4L2_CMD_CLOSE:
        handle_close_cmd(video, cmd);
        break;
    case VIRTIO_V4L2_CMD_IOCTL:
        handle_ioctl_cmd(video, cmd);
        break;
    case VIRTIO_V4L2_CMD_MMAP:
        g_error("**** VIRTIO_V4L2_CMD_MMAP unimplemented!");
        break;
    case VIRTIO_V4L2_CMD_MUNMAP:
        g_error("**** VIRTIO_V4L2_CMD_MUNMAP unimplemented!");
        break;
    default:
        g_error("Unknown VIRTIO_VIDEO command: 0x%x", cmd->cmd_hdr->cmd);
        break;
    }
}

static void
video_handle_ctrl(VuDev *dev, int qidx)
{
    VuVirtq *vq = vu_get_queue(dev, qidx);
    VuVideo *video = container_of(dev, VuVideo, dev.parent);
    size_t cmd_len, len, offset = 0;

    struct vu_video_ctrl_command *cmd;

    for (;;) {
        cmd = vu_queue_pop(dev, vq, sizeof(struct vu_video_ctrl_command));
        if (!cmd) {
            break;
        }

        cmd->vq = vq;
        cmd->error = 0;
        cmd->finished = false;
        cmd->dev = dev;

        cmd_len = iov_size(cmd->elem.out_sg, cmd->elem.out_num);
        cmd->cmd_buf = g_malloc0(cmd_len);
        len = iov_to_buf_full(cmd->elem.out_sg, cmd->elem.out_num,
                              offset, cmd->cmd_buf, cmd_len);

        if (len != cmd_len) {
            g_warning("%s: command size incorrect %zu vs %zu\n",
                      __func__, len, cmd_len);
        }

        /* header is first on every cmd struct */
        cmd->cmd_hdr = (struct virtio_v4l2_cmd_header *) cmd->cmd_buf;
        /* bswap header */
        virtio_v4l2_ctrl_hdr_letoh(cmd->cmd_hdr);
        g_debug("Received %s cmd", vv_cmd_to_string(cmd->cmd_hdr->cmd));
        vv_process_cmd(video, cmd);
    }
}

static void
video_queue_set_started(VuDev *dev, int qidx, bool started)
{
    VuVirtq *vq = vu_get_queue(dev, qidx);

    g_debug("queue started %d:%d\n", qidx, started);

    switch (qidx) {
    case 0:
        vu_set_queue_handler(dev, vq, started ? video_handle_ctrl : NULL);
        break;
    default:
        break;
    }
}

/*
 * video_process_msg: process messages of vhost-user interface
 *
 * Any that are not handled here are processed by the libvhost library
 * itself.
 */
static int video_process_msg(VuDev *dev, VhostUserMsg *msg, int *do_reply)
{
    VuVideo *r = container_of(dev, VuVideo, dev.parent);

    g_debug("%s: msg %d", __func__, msg->request);

    switch (msg->request) {
    case VHOST_USER_NONE:
        g_main_loop_quit(r->loop);
        return 1;
    default:
        return 0;
    }
}

static const VuDevIface vuiface = {
    .set_features = video_set_features,
    .get_features = video_get_features,
    .queue_set_started = video_queue_set_started,
    .process_msg = video_process_msg,
    .get_config = video_get_config,
    .set_config = video_set_config,
};

static void video_destroy(VuVideo *v)
{
    vug_deinit(&v->dev);
    if (socket_path) {
        unlink(socket_path);
    }
    v4l2_backend_free(v->v4l2_dev);
}

/* Print vhost-user.json backend program capabilities */
static void print_capabilities(void)
{
    printf("{\n");
    printf("  \"type\": \"misc\"\n");
    printf("}\n");
}

static gboolean hangup(gpointer user_data)
{
    GMainLoop *loop = (GMainLoop *) user_data;
    g_info("%s: caught hangup/quit signal, quitting main loop", __func__);
    g_main_loop_quit(loop);
    return true;
}

int main(int argc, char *argv[])
{
    GError *error = NULL;
    GOptionContext *context;
    g_autoptr(GSocket) socket = NULL;
    VuVideo video = {  };

    context = g_option_context_new("vhost-user emulation of video device");
    g_option_context_add_main_entries(context, options, "vhost-user-video");
    if (!g_option_context_parse(context, &argc, &argv, &error)) {
        g_printerr("option parsing failed: %s\n", error->message);
        exit(1);
    }

    g_option_context_free(context);

    if (print_cap) {
        print_capabilities();
        exit(0);
    }

    if (!socket_path && socket_fd < 0) {
        g_printerr("Please specify either --fd or --socket-path\n");
        exit(EXIT_FAILURE);
    }

    if (verbose || debug) {
        g_log_set_handler(NULL, G_LOG_LEVEL_MASK, g_log_default_handler, NULL);
        if (debug) {
            g_setenv("G_MESSAGES_DEBUG", "all", true);
        }
    } else {
        g_log_set_handler(NULL,
                          G_LOG_LEVEL_WARNING | G_LOG_LEVEL_CRITICAL
                          | G_LOG_LEVEL_ERROR,
                          g_log_default_handler, NULL);
    }

    /*
     * Open the v4l2 device and enumerate supported formats.
     * Use this to determine whether it is a stateful encoder/decoder.
     */
    if (!v4l2_path || !g_file_test(v4l2_path, G_FILE_TEST_EXISTS)) {
        g_printerr("Please specify a valid --v4l2-device\n");
        exit(EXIT_FAILURE);
    } else {
        video.v4l2_dev = v4l2_backend_init(v4l2_path);
        if (!video.v4l2_dev) {
            g_printerr("v4l2 backend init failed!\n");
            exit(EXIT_FAILURE);
        }
    }

    video.sessions = g_hash_table_new_full(NULL, NULL, NULL, g_free);

    /*
     * Now create a vhost-user socket that we will receive messages
     * on. Once we have our handler set up we can enter the glib main
     * loop.
     */
    if (socket_path) {
        g_autoptr(GSocketAddress) addr = g_unix_socket_address_new(socket_path);
        g_autoptr(GSocket) bind_socket =
            g_socket_new(G_SOCKET_FAMILY_UNIX, G_SOCKET_TYPE_STREAM,
                         G_SOCKET_PROTOCOL_DEFAULT, &error);

        if (!g_socket_bind(bind_socket, addr, false, &error)) {
            g_printerr("Failed to bind to socket at %s (%s).\n",
                       socket_path, error->message);
            exit(EXIT_FAILURE);
        }
        if (!g_socket_listen(bind_socket, &error)) {
            g_printerr("Failed to listen on socket %s (%s).\n",
                       socket_path, error->message);
        }
        g_message("awaiting connection to %s", socket_path);
        socket = g_socket_accept(bind_socket, NULL, &error);
        if (!socket) {
            g_printerr("Failed to accept on socket %s (%s).\n",
                       socket_path, error->message);
        }
    } else {
        socket = g_socket_new_from_fd(socket_fd, &error);
        if (!socket) {
            g_printerr("Failed to connect to FD %d (%s).\n",
                       socket_fd, error->message);
            exit(EXIT_FAILURE);
        }
    }

    /*
     * Create the main loop first so all the various sources can be
     * added. As well as catching signals we need to ensure vug_init
     * can add it's GSource watches.
     */

    video.loop = g_main_loop_new(NULL, FALSE);
    /* catch exit signals */
    g_unix_signal_add(SIGHUP, hangup, video.loop);
    g_unix_signal_add(SIGINT, hangup, video.loop);

    if (!vug_init(&video.dev, VHOST_USER_VIDEO_MAX_QUEUES,
                  g_socket_get_fd(socket),
                  video_panic, &vuiface)) {
        g_printerr("Failed to initialize libvhost-user-glib.\n");
        exit(EXIT_FAILURE);
    }

    g_message("entering main loop, awaiting messages");
    g_main_loop_run(video.loop);
    g_message("finished main loop, cleaning up");

    g_main_loop_unref(video.loop);
    video_destroy(&video);
}

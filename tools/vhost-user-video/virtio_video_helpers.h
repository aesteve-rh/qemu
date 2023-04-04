// SPDX-License-Identifier: GPL-2.0+
/*
 * virtio-video helpers
 *
 * Copyright Red Hat, Inc. 2023
 * Copyright Linaro 2021
 *
 * Authors:
 *      Peter Griffin <peter.griffin@linaro.org>
 *      Albert Esteve <aesteve@redhat.com>
 *
 * This work is licensed under the terms of the GNU GPL, version 2 or later.
 * See the COPYING file in the top-level directory.
 */

#ifndef VIRTIO_VIDEO_HELPERS_H
#define VIRTIO_VIDEO_HELPERS_H

#include <stdint.h>
#include "standard-headers/linux/virtio_video.h"
#include <linux/videodev2.h>
#include "libvhost-user-glib.h"
#include "libvhost-user.h"

/*
 * Virtio-v4l2 protocol definition.
 */

#define VIRTIO_V4L2_IOCTL_CODE(IOCTL) ((IOCTL >> _IOC_NRSHIFT) & _IOC_NRMASK)

#define VIRTIO_V4L2_CMD_OPEN 1
#define VIRTIO_V4L2_CMD_CLOSE 2
#define VIRTIO_V4L2_CMD_IOCTL 3
#define VIRTIO_V4L2_CMD_MMAP 4
#define VIRTIO_V4L2_CMD_MUNMAP 5

#define VIRTIO_V4L2_MMAP_FLAG_RW (1 << 0)

struct virtio_v4l2_cmd_header {
	uint32_t cmd;
	uint32_t __padding;
};

struct virtio_v4l2_resp_header {
	uint32_t status;
	uint32_t __padding;
};

struct virtio_v4l2_cmd_open {
	struct virtio_v4l2_cmd_header hdr;
};

struct virtio_v4l2_resp_open {
	struct virtio_v4l2_resp_header hdr;
	uint32_t session_id;
	uint32_t __padding;
};

struct virtio_v4l2_cmd_close {
	struct virtio_v4l2_cmd_header hdr;
	uint32_t session_id;
	uint32_t __padding;
};

struct virtio_v4l2_resp_close {
	struct virtio_v4l2_resp_header hdr;
};

struct virtio_v4l2_cmd_ioctl {
	struct virtio_v4l2_cmd_header hdr;
	uint32_t session_id;
	uint32_t code;
};

struct virtio_v4l2_resp_ioctl {
	struct virtio_v4l2_resp_header hdr;
};

#define VIRTIO_V4L2_MMAP_FLAG_RW (1 << 0)

struct virtio_v4l2_cmd_mmap {
	struct virtio_v4l2_cmd_header hdr;
	uint32_t session_id;
	uint32_t flags;
	uint64_t offset;
};

struct virtio_v4l2_resp_mmap {
	struct virtio_v4l2_resp_header hdr;
	uint64_t addr;
	uint64_t len;
};

struct virtio_v4l2_cmd_munmap {
	struct virtio_v4l2_cmd_header hdr;
	uint64_t offset;
};

struct virtio_v4l2_resp_munmap {
	struct virtio_v4l2_resp_header hdr;
};

#define VIRTIO_V4L2_EVT_ERROR 0
#define VIRTIO_V4L2_EVT_DQBUF 1

struct virtio_v4l2_event_header {
	uint32_t event;
	uint32_t session_id;
};

/**
 * Host-side error.
 */
/*struct virtio_v4l2_event_error {
	struct virtio_v4l2_event_header hdr;
	uint32_t errno;
	uint32_t __padding;
};*/

/**
 * Signals that a buffer is not being used anymore on the host and can be
 * dequeued.
 */
struct virtio_v4l2_event_dqbuf {
	struct virtio_v4l2_event_header hdr;
	struct v4l2_buffer buffer;
	struct v4l2_plane planes[VIDEO_MAX_PLANES];
};

#define VIRTIO_V4L2_LAST_QUEUE (V4L2_BUF_TYPE_META_OUTPUT)

/*
 * End of virtio-v4l2 protocol definition.
 */

/*
 * Structure to track internal state of VIDEO Device
 */

typedef struct VuVideo {
    VugDev dev;
    struct virtio_v4l2_config virtio_config;
    GMainLoop *loop;
    struct v4l2_device *v4l2_dev;
    GHashTable *sessions;
} VuVideo;

struct v4l2_device {
    const gchar *devname;
    unsigned int dev_type;
    unsigned int capabilities;
    unsigned char *bus_info;
    int fd;
    int epollfd;
    int opened;
    bool has_mplane;
    bool sup_dyn_res_switching;
};

struct vu_video_ctrl_command {
    VuVirtqElement elem;
    VuVirtq *vq;
    VuDev *dev;
    struct virtio_v4l2_cmd_header *cmd_hdr;
    uint32_t error;
    bool finished;
    uint8_t *cmd_buf;
};


typedef struct VuVideoDMABuf {
    struct vuvbm_device *dev;
    int memfd;
    int dmafd;

    void *start;
    size_t length;
} VuVideoDMABuf;

/**
 * A session on a virtio_v4l2 device, created whenever the device is opened.
 */
struct virtio_v4l2_session {
	/* Session ID used to communicate with the host */
	uint32_t id;

    int fd;
    struct v4l2_device *v4l2_dev;

	bool capture_streaming;
    uint32_t capture_num_queued;

    bool output_streaming;
    uint32_t output_num_allocated;
    uint32_t output_num_queued;
};

/*
 * Structure to track internal state of a Stream
 */

struct stream {
    struct virtio_video_stream_create vio_stream;
    uint32_t stream_id;
    GList *inputq_resources;
    GList *outputq_resources;
    VuVideo *video;
    GThread *worker_thread;
    uint32_t stream_state;
    GMutex mutex;
    GCond stream_cond;
    bool output_streaming;
    bool capture_streaming;
    bool subscribed_events;
    bool has_mplane;
    int fd;
    uint32_t output_bufcount;
    uint32_t capture_bufcount;
};

#define STREAM_STOPPED      1
#define STREAM_STREAMING    2
#define STREAM_DRAINING     3
#define STREAM_DESTROYING   4
#define STREAM_DESTROYED    5

/* Structure to track resources */

struct resource {
    enum v4l2_buf_type type;
    uint8_t session_id;
    uint8_t plane;
    uint8_t lenght;
    uint8_t map_count;
};

/*struct resource {
    uint32_t stream_id;
    struct virtio_video_resource_create vio_resource;
    struct virtio_video_resource_queue vio_res_q;
    struct iovec *iov;
    uint32_t iov_count;
    uint32_t v4l2_index;
    enum v4l2_buf_type type;
    struct vu_video_ctrl_command *vio_q_cmd;
    bool queued;
};*/

struct video_format_frame_rates {
    struct virtio_video_format_range frame_rates;
    struct v4l2_frmivalenum v4l_ival;
};

struct video_format_frame {
    struct virtio_video_format_frame frame;
    struct v4l2_frmsizeenum v4l_framesize;
    GList *frm_rate_l;
};

struct video_format {
    struct v4l2_fmtdesc fmt;
    struct virtio_video_format_desc desc;
    GList *vid_fmt_frm_l;
};

/* function prototypes */
int v4l2_stream_create(struct v4l2_device *dev,
                       uint32_t vio_codedformat, struct stream *s);
void v4l2_to_virtio_video_params(struct v4l2_device *dev,
                                 struct v4l2_format *fmt,
                                 struct v4l2_selection *sel,
                                 struct virtio_video_get_params_resp *resp);

void v4l2_to_virtio_fmtdesc(struct v4l2_device *dev,
                            struct video_format *vid_fmt,
                            enum v4l2_buf_type type);

void v4l2_to_virtio_event(struct v4l2_event *ev,
                          struct virtio_video_event *vio_ev);

struct resource *find_resource_by_v4l2index(struct stream *s,
                                             enum v4l2_buf_type buf_type,
                                             uint32_t v4l2_index);

void virtio_video_send_enum_fmt(int fd, struct vu_video_ctrl_command *cmd,
                                struct virtio_v4l2_cmd_ioctl *ioctl_cmd);
void virtio_video_send_get_fmt(int fd, struct vu_video_ctrl_command *cmd,
                               struct virtio_v4l2_cmd_ioctl *ioctl_cmd);
void virtio_video_send_set_fmt(int fd, struct vu_video_ctrl_command *cmd,
                               struct virtio_v4l2_cmd_ioctl *ioctl_cmd);
void virtio_video_send_reqbufs(int fd, struct vu_video_ctrl_command *cmd,
                               struct virtio_v4l2_cmd_ioctl *ioctl_cmd);
void virtio_video_send_querybufs(int fd, struct vu_video_ctrl_command *cmd,
                                 struct virtio_v4l2_cmd_ioctl *ioctl_cmd);
void virtio_video_send_enum_input(int fd, struct vu_video_ctrl_command *cmd,
                                  struct virtio_v4l2_cmd_ioctl *ioctl_cmd);
void virtio_video_send_queryctrl(int fd, struct vu_video_ctrl_command *cmd,
                                 struct virtio_v4l2_cmd_ioctl *ioctl_cmd);
void virtio_video_send_s_g_io(int fd, struct vu_video_ctrl_command *cmd,
                              struct virtio_v4l2_cmd_ioctl *ioctl_cmd,
                              unsigned long request);
void virtio_video_send_enum_output(int fd, struct vu_video_ctrl_command *cmd,
                                   struct virtio_v4l2_cmd_ioctl *ioctl_cmd);
void virtio_video_send_try_fmt(int fd, struct vu_video_ctrl_command *cmd,
                               struct virtio_v4l2_cmd_ioctl *ioctl_cmd);
void
virtio_video_send_un_subscribe_event(int fd,
                                     struct vu_video_ctrl_command *cmd,
                                     struct virtio_v4l2_cmd_ioctl *ioctl_cmd,
                                     unsigned long request);
void virtio_video_send_g_selection(int fd, struct vu_video_ctrl_command *cmd,
                                   struct virtio_v4l2_cmd_ioctl *ioctl_cmd);
void virtio_video_send_s_selection(int fd, struct vu_video_ctrl_command *cmd,
                                   struct virtio_v4l2_cmd_ioctl *ioctl_cmd);
void virtio_video_send_query_ext_ctrl(int fd, struct vu_video_ctrl_command *cmd,
                                      struct virtio_v4l2_cmd_ioctl *ioctl_cmd);

/*
 * The following conversion helpers and tables taken from Linux
 * frontend driver from opensynergy
 */

uint32_t virtio_video_level_to_v4l2(uint32_t level);
uint32_t virtio_video_v4l2_level_to_virtio(uint32_t v4l2_level);
uint32_t virtio_video_profile_to_v4l2(uint32_t profile);
uint32_t virtio_video_v4l2_profile_to_virtio(uint32_t v4l2_profile);
uint32_t virtio_video_format_to_v4l2(uint32_t format);
uint32_t virtio_video_v4l2_format_to_virtio(uint32_t v4l2_format);
uint32_t virtio_video_control_to_v4l2(uint32_t control);
uint32_t virtio_video_v4l2_control_to_virtio(uint32_t v4l2_control);
__le64 virtio_fmtdesc_generate_mask(GList **p_list);

/* Helpers for logging */
const char *vio_queue_name(enum virtio_video_queue_type queue);

static inline void
virtio_video_ctrl_hdr_letoh(struct virtio_video_cmd_hdr *hdr)
{
    hdr->type = le32toh(hdr->type);
    hdr->stream_id = le32toh(hdr->stream_id);
}

static inline void
virtio_v4l2_ctrl_hdr_letoh(struct virtio_v4l2_cmd_header *hdr)
{
    hdr->cmd = le32toh(hdr->cmd);
}

static inline void
virtio_video_ctrl_hdr_htole(struct virtio_video_cmd_hdr *hdr)
{
    hdr->type = htole32(hdr->type);
    hdr->stream_id = htole32(hdr->stream_id);
}

static inline void
virtio_v4l2_ctrl_hdr_htole(struct virtio_v4l2_cmd_header *hdr)
{
    hdr->cmd = htole32(hdr->cmd);
}
#endif

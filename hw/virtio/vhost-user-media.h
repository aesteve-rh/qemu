/*
 * vhost-user-media virtio device
 *
 * Copyright Red Hat, Inc. 2024
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef _VHOST_USER_MEDIA_H_
#define _VHOST_USER_MEDIA_H_

#include "standard-headers/linux/virtio_ids.h"
#include "standard-headers/linux/virtio_media.h"
#include "hw/virtio/virtio.h"
#include "hw/virtio/vhost.h"
#include "hw/virtio/vhost-user.h"
#include "chardev/char-fe.h"

#define TYPE_VHOST_USER_MEDIA "vhost-user-media-device"
#define VHOST_USER_MEDIA(obj) \
        OBJECT_CHECK(VHostUserMEDIA, (obj), TYPE_VHOST_USER_MEDIA)

struct virtio_media_config {
    uint32_t device_caps;
    uint32_t device_type;
    uint8_t card[32];
};

typedef struct {
    CharBackend chardev;
    struct virtio_media_config config;
} VHostUserMEDIAConf;

typedef struct {
    /*< private >*/
    VirtIODevice parent;
    VHostUserMEDIAConf conf;
    struct vhost_virtqueue *vhost_vq;
    struct vhost_dev vhost_dev;
    VhostUserState vhost_user;
    VirtQueue *command_vq;
    VirtQueue *event_vq;
    bool connected;
    /*< public >*/
} VHostUserMEDIA;


#endif /* _VHOST_USER_MEDIA_H_ */

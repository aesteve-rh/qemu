// SPDX-License-Identifier: GPL-2.0+
/*
 * vhost-user-video header
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

#ifndef VUVIDEO_H
#define VUVIDEO_H

#include "virtio_video_helpers.h"
#include "v4l2_backend.h"
#include "vuvideo.h"

void send_ctrl_response(struct vu_video_ctrl_command *vio_cmd,
                       uint8_t *resp, size_t resp_len);

void send_ctrl_response_nodata(struct vu_video_ctrl_command *vio_cmd);


#endif

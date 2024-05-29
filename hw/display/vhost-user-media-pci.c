/*
 * Vhost-user MEDIA virtio device PCI glue
 *
 * Copyright (c) 2021 Linaro Ltd
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "qemu/osdep.h"
#include "qemu/error-report.h"
#include "hw/qdev-properties.h"
#include "hw/virtio/vhost-user-media.h"
#include "hw/virtio/virtio-pci.h"

#define VIRTIO_MEDIA_PCI_CACHE_BAR 2

#define VIRTIO_MEDIA_PCI_SHMCAP_ID_CACHE 0

#define CACHE_SIZE 1ull << 30

struct VHostUserMEDIAPCI {
    VirtIOPCIProxy parent_obj;
    VHostUserMEDIA vdev;
    MemoryRegion cachebar;
};

typedef struct VHostUserMEDIAPCI VHostUserMEDIAPCI;

#define TYPE_VHOST_USER_MEDIA_PCI "vhost-user-media-pci-base"

#define VHOST_USER_MEDIA_PCI(obj) \
        OBJECT_CHECK(VHostUserMEDIAPCI, (obj), TYPE_VHOST_USER_MEDIA_PCI)

static Property vumedia_pci_properties[] = {
    DEFINE_PROP_BIT("ioeventfd", VirtIOPCIProxy, flags,
                    VIRTIO_PCI_FLAG_USE_IOEVENTFD_BIT, true),
    DEFINE_PROP_UINT32("vectors", VirtIOPCIProxy, nvectors,
                       DEV_NVECTORS_UNSPECIFIED),
    DEFINE_PROP_END_OF_LIST(),
};

static void vumedia_pci_realize(VirtIOPCIProxy *vpci_dev, Error **errp)
{
    VHostUserMEDIAPCI *dev = VHOST_USER_MEDIA_PCI(vpci_dev);
    DeviceState *dev_state = DEVICE(&dev->vdev);
    VirtIODevice *vdev = VIRTIO_DEVICE(dev_state);

    if (vpci_dev->nvectors == DEV_NVECTORS_UNSPECIFIED) {
        vpci_dev->nvectors = 1;
    }

    qdev_set_parent_bus(dev_state, BUS(&vpci_dev->bus), errp);
    object_property_set_bool(OBJECT(dev_state), "realized", true, errp);

    /*
     * The bar starts with the data cache
     * followed by the metadata cache.
     */
    memory_region_init(&dev->cachebar, OBJECT(vpci_dev),
                       "vhost-media-pci-cachebar", CACHE_SIZE);
    memory_region_add_subregion(&dev->cachebar, 0, &vdev->shmem_list[vdev->n_shmem_regions - 1]);
    virtio_pci_add_shm_cap(vpci_dev, VIRTIO_MEDIA_PCI_CACHE_BAR, 0,
                            CACHE_SIZE, VIRTIO_MEDIA_PCI_SHMCAP_ID_CACHE);

    /* After 'realized' so the memory region exists */
    pci_register_bar(&vpci_dev->pci_dev, VIRTIO_MEDIA_PCI_CACHE_BAR,
                     PCI_BASE_ADDRESS_SPACE_MEMORY |
                     PCI_BASE_ADDRESS_MEM_PREFETCH |
                     PCI_BASE_ADDRESS_MEM_TYPE_64,
                     &dev->cachebar);
}

static void vumedia_pci_class_init(ObjectClass *klass, void *data)
{
    DeviceClass *dc = DEVICE_CLASS(klass);
    VirtioPCIClass *k = VIRTIO_PCI_CLASS(klass);
    PCIDeviceClass *pcidev_k = PCI_DEVICE_CLASS(klass);
    k->realize = vumedia_pci_realize;
    set_bit(DEVICE_CATEGORY_STORAGE, dc->categories);
    device_class_set_props(dc, vumedia_pci_properties);
    pcidev_k->vendor_id = PCI_VENDOR_ID_REDHAT_QUMRANET;
    pcidev_k->device_id = 0; /* Set by virtio-pci based on virtio id */
    pcidev_k->revision = 0x00;
    pcidev_k->class_id = PCI_CLASS_STORAGE_OTHER;
}

static void vumedia_pci_instance_init(Object *obj)
{
    VHostUserMEDIAPCI *dev = VHOST_USER_MEDIA_PCI(obj);

    virtio_instance_init_common(obj, &dev->vdev, sizeof(dev->vdev),
                                TYPE_VHOST_USER_MEDIA);
}

static const VirtioPCIDeviceTypeInfo vumedia_pci_info = {
    .base_name             = TYPE_VHOST_USER_MEDIA_PCI,
    .non_transitional_name = "vhost-user-media-pci",
    .instance_size = sizeof(VHostUserMEDIAPCI),
    .instance_init = vumedia_pci_instance_init,
    .class_init    = vumedia_pci_class_init,
};

static void vumedia_pci_register(void)
{
    virtio_pci_types_register(&vumedia_pci_info);
}

type_init(vumedia_pci_register);

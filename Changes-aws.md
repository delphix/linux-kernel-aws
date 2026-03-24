Driver-related patches (dropped at every major release if they are not yet upstream):

7.0:
 - UBUNTU: SAUCE: HIBERNATION: xenbus: add freeze/thaw/restore callbacks support
 - UBUNTU: SAUCE: HIBERNATION: xen-blkfront: add callbacks for PM suspend and hibernation
 - UBUNTU: SAUCE: HIBERNATION: xen-netfront: add callbacks for PM suspend and hibernation support
 - UBUNTU: SAUCE: HIBERNATION: xen-netfront: call netif_device_attach on resume
 - UBUNTU: SAUCE: HIBERNATION: xen-blkfront: Fixed blkfront_restore to remove a call to negotiate_mq
 - UBUNTU: SAUCE: HIBERNATION: block: xen-blkfront: consider new dom0 features on restore
 - UBUNTU: SAUCE: HIBERNATION: x86: tsc: avoid system instability in hibernation

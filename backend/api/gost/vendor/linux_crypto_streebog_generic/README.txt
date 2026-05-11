Source: https://github.com/torvalds/linux/blob/master/crypto/streebog_generic.c

SPDX in file: GPL-2.0+ OR BSD-2-Clause

This is the Linux kernel shash implementation. It is not buildable as a single
translation unit outside the kernel: it includes <crypto/internal/hash.h>,
<crypto/streebog.h>, and Linux headers.

Snapshot date: 2026-05-11 (mirror of master at fetch time).

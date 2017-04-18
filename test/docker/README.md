# README
This directory includes the Dockerfiles for egalito images. There is one for each supported architecture.
When cross-compiling, QEMU is required. Depending on your distro you will need the corresponding `qemu-$ARCH-static` for which you are trying to cross-compile.

### Arch Link
`yaourt -S qemu-user-static`

### Debian
`apt-get install qemu-user-static`

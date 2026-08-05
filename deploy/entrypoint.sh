#!/bin/sh
# Runs as root just long enough to hand the app what it cannot grant itself,
# then drops to the unprivileged `scanner` user.
#
# Two things need root here and nothing else does:
#   1. The docker socket is root:docker 0660. Its group id belongs to the host,
#      so it cannot be baked into the image - we read it at start and add
#      `scanner` to a group with that gid. Without this, "Docker is not
#      installed or not running" even with the socket mounted.
#   2. Ownership of the bind-mounted data/config directories, which the host
#      may have created as root.
#
# Raw ARP does NOT need root: file capabilities are set on the interpreter at
# build time and survive the user switch (see Dockerfile).
#
# ponytail: no s6, no supervisor, no init system. One exec, one process.
set -e

SOCKET="${DOCKER_SOCKET:-/var/run/docker.sock}"

if [ "$(id -u)" = "0" ]; then
    if [ -S "$SOCKET" ]; then
        SOCKET_GID="$(stat -c '%g' "$SOCKET")"
        # A group with that gid may already exist under another name; reuse it.
        GROUP_NAME="$(getent group "$SOCKET_GID" | cut -d: -f1)"
        if [ -z "$GROUP_NAME" ]; then
            GROUP_NAME=dockersock
            groupadd -g "$SOCKET_GID" "$GROUP_NAME" 2>/dev/null || true
        fi
        usermod -aG "$GROUP_NAME" scanner 2>/dev/null || true
    fi

    for dir in /app/data /app/config; do
        [ -d "$dir" ] && chown -R scanner:scanner "$dir" 2>/dev/null || true
    done

    # setpriv, not gosu: gosu is a Go binary whose stdlib carried 39 CVEs, and
    # setpriv ships with util-linux in the base image. --init-groups picks up
    # the docker-socket group joined just above, same as gosu did.
    exec setpriv --reuid=scanner --regid=scanner --init-groups "$@"
fi

# Already unprivileged (user: override in compose, or a rootless runtime).
exec "$@"

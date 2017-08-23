Stubby integration with systemd
===============================

For GNU/Linux operating systems which use systemd as a process
manager, you might want to run stubby as a system service.

This directory provides recommended systemd unit files.

This setup assumes that there is a system-level user named "stubby"
which is in group "stubby", and try to limit the privileges of the
running daemon to that user as closely as possible.

Normally, a downstream distributor will install them as:

    /usr/lib/tmpfiles.d/stubby.conf
    /lib/systemd/system/stubby.service

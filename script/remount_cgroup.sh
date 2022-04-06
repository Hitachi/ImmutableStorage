#!/bin/bash
# Cgroups is required for the image builder to execute runc program.
for subsys in "cpu,cpuacct" cpuset devices memory pids blkio hugetlb "net_cls,net_prio" perf_event freezer
do
    subsysdir="/sys/fs/cgroup/$subsys"
    if [ ! -w $subsysdir ]
    then
        echo "remount $subsysdir"
        umount $subsysdir
        mount -t cgroup -o rw,nosuid,nodev,noexec,relatime,$subsys none $subsysdir
    fi
done

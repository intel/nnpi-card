#!/bin/sh

# This script rotates the log file /var/log/messages if it exceeds 10 MB.
# Rotation clears the original file and copies its contents to 'messages.1'
# The script is invoked once per minute by a crontab /var/spool/cron/crontabs/root

# max size in Megabytes
max_size=10

log_path='/var/log'
log_name='messages'

log_file=$log_path/$log_name
if [ ! -d "$log_path" ] || [ ! -f "$log_file" ]; then
    echo "$0: Log file '${log_file}' not found."
    exit 1
fi

# get size in Megabytes
file_size=`du -m $log_file | tr -s '\t' ' ' | cut -d' ' -f1`

if [ $file_size -gt $max_size ]; then
    echo "$0: Rotating log file '${log_file}' > $max_size bytes"
    log_rotated=$log_file.1
    rm $log_rotated
    cp $log_file $log_rotated
    truncate -s 0 $log_file
    echo -n > $log_file
fi
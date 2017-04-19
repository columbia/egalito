#!/bin/bash

# Add local user
# Either use the LOCAL_USER_ID if passed in at runtime or
# fallback

USER_ID=${LOCAL_USER_ID:-9001}

echo "Starting with UID : $USER_ID"
useradd --shell /bin/bash -u $USER_ID -o -c "" -m user
usermod -a -G dialout user
export HOME=/home/user
mkdir -p $HOME/.ccache
chown -R $USER_ID $HOME/.ccache
export PATH=/gcc-linaro-6.3.1-2017.02-x86_64_aarch64-linux-gnu/bin:$PATH
echo "PATH=/gcc-linaro-6.3.1-2017.02-x86_64_aarch64-linux-gnu/bin:$PATH" >> $HOME/.bashrc

exec gosu user "$@"

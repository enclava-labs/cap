#!/bin/sh
set -eu

# This POSIX-shell launcher exists so Bash startup hooks are cleared before the
# Bash implementation starts. A Bash script cannot protect itself from
# BASH_ENV because Bash reads that file before executing the script body.
unset \
  BASH_ENV ENV CDPATH GLOBIGNORE LD_PRELOAD LD_LIBRARY_PATH \
  DYLD_INSERT_LIBRARIES DYLD_LIBRARY_PATH PYTHONHOME PYTHONPATH \
  RUBYOPT NODE_OPTIONS PERL5LIB

case "$0" in
  */*) script_dir=${0%/*} ;;
  *) script_dir=. ;;
esac
script_dir=$(CDPATH= cd -- "$script_dir" && pwd -P)

if [ -x /usr/bin/bash ] && [ ! -d /usr/bin/bash ]; then
  bash_bin=/usr/bin/bash
elif [ -x /bin/bash ] && [ ! -d /bin/bash ]; then
  bash_bin=/bin/bash
else
  echo "error: missing trusted Bash interpreter (/usr/bin/bash or /bin/bash)" >&2
  exit 2
fi

exec "$bash_bin" "$script_dir/verify-api-image-ref.bash" "$@"

#!/usr/bin/env bash

set -eu
set -o pipefail

# System specific settings
export NIX_FIRST_BUILD_UID="${NIX_FIRST_BUILD_UID:-30001}"
export NIX_BUILD_USER_NAME_TEMPLATE="nixbld%d"

readonly PREFIX=/usr/local
readonly SERVICE_SRC=/share/rc/nix-daemon.sh
readonly SERVICE_DEST=/etc/rc.d/nix-daemon

poly_cure_artifacts() {
    :
}

poly_service_installed_check() {
    [ -e /usr/local/etc/rc.d/nix_daemon ]
}

poly_service_uninstall_directions() {
        cat <<EOF
$1. Delete the rc script

  sudo service stop nix-daemon
  sudo sysrc -x nix_daemon_enable nix_daemon_log_file
  sudo rm -rf $PREFIX$SERVICE_DEST
EOF
}

poly_service_setup_note() {
    :
}

poly_extra_try_me_commands() {
    :
}

poly_configure_nix_daemon_service() {
    if [ -e $PREFIX/etc/rc.d ]; then
        task "Setting up the nix-daemon rc.d service"

        _sudo "to set up the nix-daemon service" \
              ln -s "/nix/var/nix/profiles/default$SERVICE_SRC" $PREFIX$SERVICE_DEST

        _sudo "to enable the nix-daemon at startup" \
              sysrc nix_daemon_enable=YES
    else
        reminder "I don't support your init system yet; you may want to add nix-daemon manually."
    fi
}

poly_group_exists() {
    getent group "$1" > /dev/null 2>&1
}

poly_group_id_get() {
    getent group "$1" | cut -d: -f3
}

poly_create_build_group() {
    _sudo "Create the Nix build group, $NIX_BUILD_GROUP_NAME" \
          pw groupadd "$NIX_BUILD_GROUP_NAME" -g "$NIX_BUILD_GROUP_ID" >&2
}

poly_user_exists() {
    getent passwd "$1" > /dev/null 2>&1
}

poly_user_id_get() {
    getent passwd "$1" | cut -d: -f3
}

poly_user_hidden_get() {
    echo "1"
}

poly_user_hidden_set() {
    true
}

poly_user_home_get() {
    getent passwd "$1" | cut -d: -f6
}

poly_user_home_set() {
    _sudo "in order to give $1 a safe home directory" \
          pw usermod -d "$2" -n "$1"
}

poly_user_note_get() {
    getent passwd "$1" | cut -d: -f5
}

poly_user_note_set() {
    _sudo "in order to give $1 a useful comment" \
          pw usermod -c "$2" -n "$1"
}

poly_user_shell_get() {
    getent passwd "$1" | cut -d: -f7
}

poly_user_shell_set() {
    _sudo "in order to prevent $1 from logging in" \
          pw usermod -s "$2" -n "$1"
}

poly_user_in_group_check() {
    id -Gn "$1" | grep -q "$2" > /dev/null 2>&1
}

poly_user_in_group_set() {
    _sudo "Add $1 to the $2 group"\
          pw groupmod "$2" -m "$1"
}

poly_user_primary_group_get() {
    id -gn "$1"
}

poly_user_primary_group_set() {
    _sudo "to let the nix daemon use this user for builds (this might seem redundant, but there are two concepts of group membership)" \
          pw usermod -g "$2" -n "$1"

}

poly_create_build_user() {
    username=$1
    uid=$2
    builder_num=$3

    _sudo "Creating the Nix build user, $username" \
          pw useradd \
          -d /var/empty \
          -c "Nix build user $builder_num" \
          -g "$NIX_BUILD_GROUP_ID" \
          -G "$NIX_BUILD_GROUP_NAME" \
          -s /sbin/nologin \
          -u "$uid" \
          -h - \
          -n "$username"
}

poly_prepare_to_install() {
    :
}

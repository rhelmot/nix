ifdef HOST_FREEBSD

  $(foreach n, nix-daemon.sh, $(eval $(call install-file-in, $(d)/$(n), $(prefix)/share/rc, 0755)))

  clean-files += $(d)/nix-daemon.sh

endif

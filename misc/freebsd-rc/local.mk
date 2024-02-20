ifdef HOST_FREEBSD

  $(foreach n, nix-daemon.sh, $(eval $(call install-file-in, $(d)/$(n), $(prefix)/share/rc, 0644)))
  $(foreach n, nix-daemon.conf, $(eval $(call install-file-in, $(d)/$(n), $(prefix)/lib/tmpfiles.d, 0644)))

  clean-files += $(d)/nix-daemon.sh

endif

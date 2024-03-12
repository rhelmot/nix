#pragma once

#if __FreeBSD__

#include "../local-derivation-goal.hh"
#include "util.hh"

#include <sys/param.h>
#include <sys/uio.h>
#include <sys/mount.h>
#include <sys/jail.h>
#include <sys/sockio.h>
#include <sys/socket.h>
#include <jail.h>
#include <stdlib.h>
#include <string.h>
#include <net/if.h>

namespace nix {
    void unmountAll(Path &path);
}

#endif

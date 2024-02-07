#pragma once

#if __APPLE__

#include "../local-derivation-goal.hh"
#include "util.hh"

#include <spawn.h>
#include <sys/sysctl.h>

#define REQUIRES_HASH_REWRITE true

namespace nix {
    void specialExecBuilder(std::string &builder, Strings &args, Strings &envStrs);
}

#endif

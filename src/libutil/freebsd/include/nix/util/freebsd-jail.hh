#pragma once
///@file

#include "nix/util/types.hh"

namespace nix {

class AutoRemoveJail
{
    bool del;
public:
    int jid;
    std::vector<Path> childrenMounts;
    AutoRemoveJail(int jid);
    AutoRemoveJail();
    ~AutoRemoveJail();
    void cancel();
    void reset(int j);
};

} // namespace nix

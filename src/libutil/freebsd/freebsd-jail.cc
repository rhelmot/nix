#ifdef __FreeBSD__
#  include "nix/util/freebsd-jail.hh"

#  include <sys/resource.h>
#  include <sys/param.h>
#  include <sys/jail.h>
#  include <sys/mount.h>

#  include "nix/util/error.hh"
#  include "nix/util/util.hh"

namespace nix {

AutoRemoveJail::AutoRemoveJail()
    : del{false}
{
}

AutoRemoveJail::AutoRemoveJail(int jid)
    : jid(jid)
    , del(true)
{
}

AutoRemoveJail::~AutoRemoveJail()
{
    try {
        if (del) {
            if (jail_remove(jid) < 0) {
                throw SysError("Failed to remove jail %1%", jid);
            }
        }
        for (auto & path : childrenMounts) {
            int r = unmount(path.c_str(), 0);
            if (r < 0 && errno == EBUSY) {
                sleep(1);
                r = unmount(path.c_str(), 0);
            }
            if (r < 0) {
                throw SysError("Failed to unmount path %1%", path);
            }
        }
    } catch (...) {
        ignoreExceptionInDestructor();
    }
}

void AutoRemoveJail::cancel()
{
    del = false;
}

void AutoRemoveJail::reset(int j)
{
    del = true;
    jid = j;
}

//////////////////////////////////////////////////////////////////////

} // namespace nix
#endif

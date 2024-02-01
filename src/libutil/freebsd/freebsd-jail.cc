#ifdef __FreeBSD__
#  include "nix/util/freebsd-jail.hh"

#  include <sys/resource.h>
#  include <sys/param.h>
#  include <sys/jail.h>
#  include <sys/mount.h>

#  include "nix/util/error.hh"
#  include "nix/util/util.hh"

namespace nix {

AutoRemoveJail::AutoRemoveJail(int jid)
    : jid(jid)
{
}

AutoRemoveJail::~AutoRemoveJail()
{
    try {
        if (jid != INVALID_JAIL) {
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
                throw SysError("Failed to unmount path %1%", PathFmt(path));
            }
        }
    } catch (...) {
        ignoreExceptionInDestructor();
    }
}

void AutoRemoveJail::cancel() noexcept
{
    jid = INVALID_JAIL;
}

//////////////////////////////////////////////////////////////////////

} // namespace nix
#endif

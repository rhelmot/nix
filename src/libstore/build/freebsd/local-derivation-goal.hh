#if __FreeBSD__
void chrootSetup(Path &chrootRootDir);
void createChild(const std::string &slaveName);
void enterJail();
#endif

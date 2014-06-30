//ian says: just one place to keep all the hacks i need for cross compiling
// we can "polish" these, after the frenzy.

#ifdef _WIN32
#define PriSize_t   "u"
#define PriSSize_t   "u"
#else
#define PriSize_t   "zu"
#define PriSSize_t  "zd"
#endif

#ifdef _WIN32
#ifndef SSIZE_MAX
#define SSIZE_MAX INT_MAX   //should actually be defined as INT_MAX for w32 and  LLONG_MAX for w64 it.
#endif
#endif

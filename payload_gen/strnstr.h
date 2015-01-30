#ifndef STRNTSTR_H
#define STRNTSTR_H

#include <stddef.h>

#define CASECMPCONST(X,Y) strncasecmp(X,Y,sizeof(Y)-1)
#define STRNCMPCONST(X,Y) strncmp(X,Y,sizeof(Y)-1)

/*
 * Find the first occurrence of needle in haystack, where the search is limited to the
 * first len characters of haystack.
 */
char *strnstr(const char *s, const char *find, size_t slen);

#endif /*  STRNTSTR_H */

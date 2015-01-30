#include <assert.h>
#include <string.h>
#include <stdio.h>
#include <ctype.h>


#include "strnstr.h"

/*
 * Find the first occurrence of needle in haystack, where the search is limited to the
 * first len characters of haystack.
 */
char *strnstr(const char *haystack, const char *needle, size_t len){
  size_t needle_length = strlen(needle);
  int prick = toupper(*needle);
  char c, *front = (char *)haystack;
  //Note: strnstr("0123456789FYY", "FYY", 11) should fail.
  while (((c = *front) != '\0') && (len-- >= needle_length)){
    if (toupper(c) == prick){
      if (strncmp(front, needle, needle_length) == 0){
        return front;
      }
    }
    front++;
  }
  return NULL;
}

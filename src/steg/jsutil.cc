/* Copyright 2011, 2012, 2013 SRI International
 * See LICENSE for other credits and copying information
 */

#include "util.h"
#include "payloads.h"
#include "jsutil.h"
#include "strncasestr.h"

#include <ctype.h>

static const char* js_keywords[] = {
      // java_script keywords (incl future reserved words):
      // http://ecma-international.org/ecma-262/5.1/#sec-7.6.1
      "break", "case", "catch", "class", "const", "continue", "debugger", "default",
      "delete", "do", "else", "enum", "export", "extends", "finally",
      "for", "function", "if", "import", "in", "instanceof", "new", "return",
      "super", "switch", "this", "throw", "try", "typeof", "var",
      "void", "while", "with",

      // java_script strict mode future_reserved_words
      "implements", "interface", "let", "package", "private", "protected", "public", "static", "yield",

      // common const values
      "false", "False", "true", "True", "null", "undefined",

      // common functions
      "random", "write", "writeln", "indexOf",

      // URI-specific keywords
      "http", "https"

};


#define arraysize(ar)  (sizeof(ar) / sizeof(ar[0]))

static int num_keywords = arraysize(js_keywords);
static short len_keywords[arraysize(js_keywords)];


/*
 * compute_keyword_len stores the length of keywords[i] 
 * in len_keywords[i]
 */
void 
compute_keyword_len (const char * list[], short len[], int size)
{
  int i;
  for (i=0; i<size; i++) {
     len[i] = strlen(list[i]);
  }
}


/*
 * skip_JS_pattern returns the number of characters to skip when
 * the input pointer matches the start of a common java_script
 * keyword 
 *
 * todo: 
 * use a more efficient pattern matching algo
 */

size_t 
skip_JS_pattern(char *cp, int len) 
{
  int i,j;

  if (len < 1) return 0;

  for (i=0; i < num_keywords; i++) {
    char* word = (char *)js_keywords[i];

    if (len <= len_keywords[i])
      continue;

    if (word[0] != cp[0])
      continue;

    for (j=1; j < len_keywords[i]; j++) {

      if (isxdigit(word[j])) {
        if (!isxdigit(cp[j])) {
          goto next_word;
        } else {
          continue;
        }
      }
      
      if (cp[j] != word[j]) {
        goto next_word;
      }
    }

    if (!isalnum(cp[j]) && cp[j] != JS_DELIMITER && cp[j] != JS_DELIMITER_REPLACEMENT) {
      return len_keywords[i]+1;
    }
      
  next_word:
    continue;
  }

  return 0;
}


int 
isalnum_ (char c) 
{
  if (isalnum(c) || c == '_') return 1;
  else return 0;
}


int 
offset2Alnum_ (char *p, int range) 
{
  char *cp = p;

  while ((cp < (p+range)) && !isalnum_(*cp)) {
    cp++;
  }

  if (cp < (p+range)) {
    return (cp-p);
  } else {
    return -1;
  }
}


int 
offset2Non_alnum_ (char *p, int range) 
{
  char *cp = p;

  while ((cp < (p+range)) && isalnum_(*cp)) {
    cp++;
  }

  if (cp < (p+range)) {
    return (cp-p);
  } else {
    return -1;
  }
}


int 
offset2Non_num (char *p, int range) 
{
  char *cp = p;

  while ((cp < (p+range)) && (isdigit(*cp) || (*cp == '.') || (*cp == 'x') || (*cp == 'e'))) {
    cp++;
  }

  if (cp < (p+range)) {
    return (cp-p);
  } else {
    return -1;
  }
}


/*
 * offset2Hex returns the offset to the next usable hex char.
 * usable here refer to char that our steg module can use to encode
 * data. in particular, words that correspond to common java_script keywords
 * are not used for data encoding (see skip_JS_pattern). also, because
 * JS var name must start with an underscore or a letter (but not a digit)
 * we don't use the first char of a word for encoding data
 *
 * e.g., the JS statement "var a;" won't be used for encoding data
 * because "var" is a common JS keyword and "a" is the first char of a word
 *
 * input:
 * p - ptr to the starting pos 
 * range - max number of char to look
 * is_last_char_hex - is the char pointed to by (p-1) a hex char 
 *
 * output:
 * offset2Hex returns the offset to the next usable hex char
 * between p and (p+range), if it exists;
 * otherwise, it returns -1
 *
 */
int 
offset2Hex (char *p, int range, int is_last_char_hex) 
{
  char *cp = p;
  int i,j;
  int is_first_word_char = 1;

  if (range < 1) return -1;

  // case 1: last char is hexadecimal
  if (is_last_char_hex) {
    if (isxdigit(*cp)) 
      return 0; // base case

    while (cp < (p+range) && isalnum_(*cp)) {
      cp++;
      if (isxdigit(*cp)) 
	return (cp-p);
    }

    if (cp >= (p+range)) {
      return -1;
    }
  // non-alnum_ found, fallthru and handle case 2
  }

 
  // case 2: find the next word that starts with alnum or underscore,
  // which could be a variable, keyword, or literal inside a string

  i = offset2Alnum_(cp, p+range-cp);

  if (i == -1) 
    return -1;

  while (cp < (p+range) && i != -1) {
    if (i == 0) { 
      if (is_first_word_char) {
        j = skip_JS_pattern(cp, p+range-cp); 
        if (j > 0) {
          cp = cp+j;
        } 
	else {
          cp++; 
	  is_first_word_char = 0; // skip the 1st char of a word
        }
      } 
      else { // we are in the middle of a word; no need to invoke skip_JS_pattern
        if (isxdigit(*cp)) 
	  return (cp-p);
        if (! isalnum_(*cp)) {
          is_first_word_char = 1;
        }
        cp++;
     }
    } 
    else {
      cp += i; 
      is_first_word_char = 1;
    }
    i = offset2Alnum_(cp, p+range-cp);    
  } // while

  // cannot find next usable hex char 
  return -1;
 
}


/*
 * capacity_JS computes the number of usable char in the JS payload that
 * can be used for encoding data
 */
unsigned int 
capacity_JS (char* buf, int len, int mode) 
{
  char *h_end, *bp, *js_start, *js_end;
  int cnt=0;
  int j;

  // jump to the beginning of the body of the HTTP message
  h_end = strnstr(buf, "\r\n\r\n", len);
  if (h_end == NULL) {
    // cannot find the separator between HTTP header and HTTP body
    return 0;
  }
  bp = h_end + 4;

  if (mode != CONTENT_JAVASCRIPT && mode != CONTENT_HTML_JAVASCRIPT) {
    log_warn("unknown mode (%d) for capacity_JS() ...", mode);
    goto err;
  }

  if (mode == CONTENT_JAVASCRIPT) {
    j = offset2Hex(bp, (buf+len)-bp, 0);

    while (j != -1) {
      cnt++;
      if (j == 0) {
        bp = bp+1;
      } else {
        bp = bp+j+1;
      }

      j = offset2Hex(bp, (buf+len)-bp, 1);
    } // while
    return cnt;
  }

  if (mode == CONTENT_HTML_JAVASCRIPT) {

    while (bp < (buf+len)) {
      js_start = strnstr(bp, JS_SCRIPT_START, len-(bp-buf));
      if (js_start == NULL) break;
      bp = js_start+31;
      js_end = strnstr(bp, JS_SCRIPT_END, len-(bp-buf));
      if (js_end == NULL) break;
      // count the number of usable hex char between js_start+31 and js_end

      j = offset2Hex(bp, js_end-bp, 0);
      while (j != -1) {
        cnt++;
        if (j == 0) {
          bp = bp+1;
        } else {
          bp = bp+j+1;
        }
        j = offset2Hex(bp, js_end-bp, 1);
      } // while (j != -1)

      bp += 9;
    } // while (bp < (buf+len))
    return cnt;
  }

 err:
  return 0;
}






/*
 * str_in_binary looks for char array pattern of length pattern_len in a char array
 * blob of length blob_len
 *
 * return a pointer for the first occurrence of pattern in blob, if found
 * otherwise, return NULL
 * 
 */
char* 
str_in_binary (const char *pattern, size_t pattern_len, const char *blob, size_t blob_len) 
{
  int found = 0;
  char *cp = (char *)blob;
  const char *blob_end = blob + blob_len;

  while ((size_t)(blob_end - cp) >= pattern_len) {
    if (memcmp(cp, pattern, pattern_len) == 0) {
      found = 1;
      break;
    }
    cp++; 
  }

  if (found)
    return cp;
  return NULL;
}



/*
 * find the number of char in {i, g, m} 
 * appearing in the input word of length wlen
 */
int 
count_GIM (char *word, int wlen) 
{
   int i_flag = 0, g_flag = 0, m_flag = 0;
   char *cp;

   cp = word;
   if (wlen < 1) return 0;
   while (cp < word+wlen) {
     if (*cp == 'i') {
       i_flag = 1;
     } else if (*cp == 'g') {
       g_flag = 1;
     } else if (*cp == 'm') {
       m_flag = 1;
     }
     cp++;
   }
   return (i_flag+g_flag+m_flag);
}



// computing the lengths of keywords in js_keywords[] and storing them 
// in len_keywords[], where num_keywords contains the number of keywords
// in js_keywords[]
// note: only need to call this once
void 
init_js_keywords () 
{
  compute_keyword_len(js_keywords, len_keywords, num_keywords);
}


/* Copyright 2011, 2012 SRI International
 * See LICENSE for other credits and copying information
 */

#include "util.h"
#include "unittest.h"
#include "../steg/pdfSteg.h"

static void
test_pdf_wrap_unwrap(void *)
{
  const char *pdf =
    "[PDFHDR][STUFFS1]1 0 obj <<\n/Length 12\n/Filter /FlateDecode\n>>\nstream\nABCDEFGHIJYY>>endstream\n[STUFF2][PDFTRAILER]";

  const char *const tests[] = {
    "12345",
    "123456789012",
    "12345678901",
    "1234567890?",
    0
  };

  char out[200];
  char orig[200];
  int i;
  size_t r1, r2;
  size_t rv;

  for (i = 0; tests[i]; i++) {
    memset(out, 0, sizeof out);
    memset(orig, 0, sizeof out);
    pdf_wrap(tests[i], strlen(tests[i]),
                  pdf, strlen(pdf),
                  out, sizeof out, rv);
    tt_int_op(rv, >, 0);
    r1 = rv;

    pdf_unwrap(out, r1, orig, sizeof orig, rv);
    tt_int_op(rv, >, 0);
    r2 = rv;
    tt_int_op(r2, ==, strlen(tests[i]));
    tt_stn_op(orig, ==, tests[i], r2);
  }

 end:;
}

#define T(name) \
  { #name, test_pdf_##name, 0, 0, 0 }

struct testcase_t pdf_tests[] = {
  T(wrap_unwrap),
  END_OF_TESTCASES
};

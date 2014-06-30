#!/usr/bin/perl

use strict;
use warnings;

$| = 1;
my $res;
$res = qx(js -C -f $ARGV[0] 2>&1);
if ($res ne "") {
  print "$res\n";
}

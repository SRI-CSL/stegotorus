#!/bin/sh

type perl >/dev/null 2>&1 || { echo "require perl, but it's not found"; exit 1; }
type js >/dev/null 2>&1 || { echo "require js (SpiderMonkey JavaScript Shell), but it's not found"; exit 1; }

cd pcaptester

if [ ! -d "js-testfiles" ]; then
  echo "JStestfiles directory not found"
  exit 1
fi

shopt -s nullglob
for file in js-testfiles/*.js
do
  echo "validating $file"
  python ./js-validate.py $file
  perl ./jscheck.pl $file
done
shopt -u nullglob

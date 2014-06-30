#!/bin/csh

set cnt = 1

if (! -e file-extract) then
  g++ file-extract.c -o file-extract
endif



foreach file (`grep "Content-Type: application/x-shockwave-flash"  pcapcontents/* |awk '{print $3}'`)
  echo $cnt

    ./file-extract $file "$1/"$cnt".swf"
    @ cnt = $cnt + 1
end


set cnt = 1

foreach file (`grep "Content-Type: application/x-javascript" pcapcontents/* |awk '{print $3}'`)
  echo $cnt

    ./file-extract $file "$1/"$cnt".js"
    @ cnt = $cnt + 1
end


set cnt = 1

foreach file (`grep "Content-Type: application/pdf" pcapcontents/* |awk '{print $3}'`)
  echo $cnt

    ./file-extract $file "$1/"$cnt".pdf"
    @ cnt = $cnt + 1
end

set cnt = 1

foreach file (`grep "Content-Type: text/html" pcapcontents/* |awk '{print $3}'`)
  echo $cnt

    ./file-extract $file "$1/"$cnt".html"
    @ cnt = $cnt + 1
end

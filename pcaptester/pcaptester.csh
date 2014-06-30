#!/bin/csh
killall stegotorus >& /dev/null
killall tcpdump >& /dev/null

if (! -d pcaptester/pcapcontents) then
  mkdir pcaptester/pcapcontents
else
  rm -f pcaptester/pcapcontents/*
endif


if (! -d pcaptester/files) then
  mkdir pcaptester/files
else
  rm -f pcaptester/files/*
endif

set iface = `ifconfig -a |grep lo |head -1 |awk '{print $1}' |sed -e 's/://g'`

# exit if tcpdump fails to listen to interface iface
set tcpdumpP = `/usr/sbin/tcpdump -D|grep $iface`
test -z $tcpdumpP && echo "Failed to invoke tcpdump on interface $iface. Try turning on the setuid bit of tcpdump" && exit


# slow down the link so tcpdump doesn't lose packets
sudo pcaptester/fix-pipes.csh $iface


# unset environment variables BROHOME and BROPATH
unsetenv BROHOME
unsetenv BROPATH

set cnt = `which bro |grep "Command not found" |wc -l`

if ($cnt > 0) then
  echo "Please install bro"
  exit
endif


set perlP = `which perl | grep "Command not found" | wc -l`
if ($perlP > 0) then
  echo "Please install perl"
endif

set jsP = `which js | grep "Command not found" | wc -l`
if ($jsP > 0) then
  echo "Please install js (SpiderMonkey JavaScript Shell)"
endif


echo "starting fake server"
pcaptester/fake-server.csh 200000 |nc -l 1234 &
sleep 2
echo "starting stegotorus client"
pcaptester/start-client-unit.csh >& /dev/null &
sleep 2
echo "starting stegotorus server"
pcaptester/start-server-unit.csh >& /dev/null &


sleep 2 
echo "starting pcap"
/usr/sbin/tcpdump -nn -i $iface -s 0 -w pcaptester/pcap.dump "port 8081" >& pcap.out&

sleep 5
echo "Transmitting data"
curl --socks4a 127.0.0.1:1080 http://ignored > /dev/null
sleep 2

sudo ipfw -f flush

killall stegotorus >& /dev/null
killall fake-server >&  /dev/null
killall nc >& /dev/null
killall base64 >& /dev/null
killall tcpdump >& /dev/null

sleep 2

cd pcaptester
rm -f file-extract
echo "file-extract gone"
bro -C -r pcap.dump dump-contents >& bro-errors.txt
./file-extract-wrap.csh files


#validate swf files

foreach file (`ls files/*.swf`)
  echo "validating $file"
  python ./swf-validate.py $file
end


foreach file (`ls files/*.pdf`)
  echo "validating $file"
  python ./pdf-validate.py $file
end

foreach file (`ls files/*.js`)
  echo "validating $file"
  python ./js-validate.py $file
  if ($perlP == 0 && $jsP == 0) then
    perl ./jscheck.pl $file
  endif
end


foreach file (`ls files/*.html`)
  echo "validating $file"
  python ./js-validate.py $file
end



#set mtu of loopback to default 16384
sudo ifconfig lo0 mtu 16384

#! /bin/sh

if[ -f /usr/bin/genkeys ] ; then
  # generate keys, using our MAC as part of the ID seed
  ifconfig wlan0 |head -1 |awk '{print $5}' | /usr/bin/genkeys > /psp/keys.txt
  # remove the key generator so nobody can use it again
  rm /usr/bin/genkeys
  # now export the keys
  /usr/bin/exportKeys /psp/keys.txt > /psp/exportkeys.txt
fi


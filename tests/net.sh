#!/bin/bash

NAME="net"
FUNS=$(grep -i ' t ' /proc/kallsyms | grep -E 'netbk| net_| netif| tx| rx|skb| sk_' | awk '{print $3}')

ENTRY="{exec [var 0 (timestamp)]}"
EXIT="{exec
  [var 1 (timestamp)]
  [var 2 (sub [var 1] [var 0])]
  [store 0 (add [store 0] [var 2])]}"
OPTS="kernel"

export SPLINTER_DIR=$(mktemp -d)

x=0; for fun in ${FUNS}
do
  DST="${SPLINTER_DIR}/${NAME}/${fun}"
  mkdir -v -p "${DST}"
  echo "${fun}" > "${DST}/address"
  echo "${ENTRY}" > "${DST}/entry"
  echo "${EXIT}" > "${DST}/exit"
  echo "${OPTS}" > "${DST}/options"
  ((x=1+x))
done

if [[ ${x} -gt 0 ]]
then
  splinter hook-load net
  splinter hook-enable
  read -p "Now, do your test, then type enter"
  splinter hook-disable
  FMT="%50s %16s %16s %16s\\n"
  printf "${FMT}" "function" "total hits" "total time" "ticks/call"
  SPLINTER_FORMAT='%text% %hits% %store0%' splinter hook-show | while read fun hits totime
  do
    avg="[undefined]"
    if [[ ${hits} -gt 0 && ${totime} -gt 0 ]]
    then
      ((avg=${totime}/${hits}))
      printf "${FMT}" "${fun}" "${hits}" "${totime}" "${avg}"
    fi
  done | sort -r -n -k 3
else
  echo "No places to hook, quitting..."
fi

rm -rf "${SPLINTER_DIR}"


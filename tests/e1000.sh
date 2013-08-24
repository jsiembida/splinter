#!/bin/bash

NAME="e1000"
FUNS=$(grep " t ${NAME}_" /proc/kallsyms | grep -Ev 'init|setup|config|power|eeprom|info|alloc|free|regs|probe|watchdog|workaround|_set|_get|_phy|_led|reset|test|check' | awk '{print $3}')

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
  splinter hook-load "${NAME}"
  splinter hook-enable "${NAME}"
  read -p "Now, do your test, then type enter"
  splinter hook-disable "${NAME}"
  FMT="%32s %16s %16s %16s\\n"
  printf "${FMT}" "function" "total hits" "total time" "ticks/call"
  # '%(num)3s %(address)17s %(enable)8s %(refcount)4s %(hits)8s %(dropped)8s   %(text)s'
  SPLINTER_FORMAT='%(text)s %(hits)s %(store0)s' splinter hook-show "${NAME}" | while read fun hits totime
  do
    avg="[undefined]"
    if [[ ${hits} -gt 0 && ${totime} -gt 0 ]]
    then
      ((avg=${totime}/${hits}))
      printf "${FMT}" "${fun}" "${hits}" "${totime}" "${avg}"
    fi
  done | sort -r -n -k 4
else
  echo "No places to hook, quitting..."
fi

rm -rf "${SPLINTER_DIR}"


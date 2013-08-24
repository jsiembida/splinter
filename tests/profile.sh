#!/bin/bash

FMT="%32s %16s %16s %16s\\n"
printf "${FMT}" "function" "total hits" "total time" "ns/call"
SPLINTER_FORMAT='%text% %hits% %store0%' splinter hook-show | while read fun hits totime
do
  if [[ ${hits} -gt 0 && ${totime} -gt 0 ]]
  then
    ((avg=${totime}/${hits}))
    printf "${FMT}" "${fun}" "${hits}" "${totime}" "${avg}"
  fi
done | sort -r -n -k 4


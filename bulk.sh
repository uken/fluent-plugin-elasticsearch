#!/bin/bash

if [ -z "${1:-}" ] ; then
    echo Usage: $0 eshost:esport
    exit 1
fi

ES=$1

echo "Delete any existing test indices"
TESTIDX=testing-bulk-indexing
for i in {0..2}; do curl -XDELETE $ES/$TESTIDX-$i?pretty; done

# Normal bulk index, should index one record in three separate indices
curl -XPOST $ES/_bulk --data-binary @./data-step-00.json
curl -XPOST $ES/_bulk --data-binary @./data-step-01.json

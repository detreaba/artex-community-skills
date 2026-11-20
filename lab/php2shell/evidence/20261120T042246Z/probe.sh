#!/usr/bin/env bash
# Benign control probe (NOT a CVE reproduction): fetch the base URL, dump raw response.
# $1=variant  $2=base_url
curl -sS --max-time 5 -i "$2"

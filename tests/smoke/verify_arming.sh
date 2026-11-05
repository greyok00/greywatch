#!/bin/bash
# Phase-1 verification (adapted): state, events, and the switch — run arm
# first: echo '{"enabled": true}' > ~/greywatch/data/appfw/enable.json
cat ~/greywatch/data/appfw/enable.json
sleep 8
python3 -c "import json,os;d=json.load(open(os.path.expanduser('~/greywatch/data/status.json')));print('engine:',d.get('appfw_engine'));print('components:',{k:v.get('state') for k,v in (d.get('components') or {}).items() if 'appfw' in k})"
tail -2 ~/greywatch/data/appfw/events.jsonl
echo "kernel truth (sudo): nft list table inet greywatch_appfw"

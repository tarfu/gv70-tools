# gv70-tools


Shifting bits in DBC:
```
cat eGV70.dbc | python -c 'import re,sys; print(re.sub(": (\d+)\|", lambda i: ": "+str(int(i.group(1))-8)+"|" if i.group(1) else "",sys.stdin.read()))' > eGV70-8bit.dbc
```

Requests (First Byte is isotp header for single frame (0 for single frame 3 for datalength) `\xAA` is padding and can be left)
the answer is normally send to `<address you send your request to>+8`
```
BMS (rxid=0x7EC, txid=0x7E4): b'\x03\x22\x01\x01\xAA\xAA\xAA\xAA'
SOH (rxid=0x7EC, txid=0x7E4): b'\x03\x22\x01\x05\xAA\xAA\xAA\xAA'
CellVoltage1 (rxid=0x7EC, txid=0x7E4): b'\x03\x22\x01\x02\xAA\xAA\xAA\xAA'
CellVoltage2 (rxid=0x7EC, txid=0x7E4): b'\x03\x22\x01\x03\xAA\xAA\xAA\xAA'
CellVoltage3 (rxid=0x7EC, txid=0x7E4): b'\x03\x22\x01\x04\xAA\xAA\xAA\xAA'
CellVoltage4 (rxid=0x7EC, txid=0x7E4): b'\x03\x22\x01\x0A\xAA\xAA\xAA\xAA'
CellVoltage5 (rxid=0x7EC, txid=0x7E4): b'\x03\x22\x01\x0B\xAA\xAA\xAA\xAA'
CellVoltage6 (rxid=0x7EC, txid=0x7E4): b'\x03\x22\x01\x0C\xAA\xAA\xAA\xAA'
Temperatures (rxid=0x7BB, txid=0x7B3): b'\x03\x22\x01\x00\xAA\xAA\xAA\xAA'
Tires (rxid=0x7A8, txid=0x7A0): b'\x03\x22\xC0\x0B\xAA\xAA\xAA\xAA'
Car (rxid=0x7CE, txid=7C6): b'\x03\x22\xB0\x02'
```

Basis for ev6.dbc:
https://github.com/JejuSoul/OBD-PIDs-for-HKMC-EVs/issues/58
https://www.csselectronics.com/pages/kia-ev6-can-bus-data-uds-dbc


Getting GPS location in docker (yes the trailing / is needed) host networking assumed:
```
curl -vvv -X POST -H "Content-Type: application/json" -d '["ec2x.gnss_location"]' http://localhost:9000/dongle/94820371-fbcc-2338-ca38-2ca83b77c293/execute/
```

Battery signals needing more research: (response and service just here to remember those)
```
BO_ 2028 Battery: 62 Vector__XXX
 SG_ response m98M : 23|16@0+ (1,0) [0|0] "unit" Vector__XXX
 SG_ service M : 15|8@0+ (1,0) [0|0] "" Vector__XXX
 SG_ IsolationResistance m257 : 495|16@0+ (0,0) [0|1000] "kOhm" Vector__XXX needs more research
```

docker build and push:
```
docker buildx build -t tarfu/egv70:latest -t tarfu/egv70:$(git rev-parse --short HEAD) --platform=linux/arm/v7 --build-arg BUILDARCH=arm32v7 --push .
```

Extra Setup for autopi:
/etc/modules-load.d/can-extra.conf
```
can_isotp
vcan
```

current mosquito custom conf:
```
connection eGV70
address 8a6216a01c07466b8273354ed625784f.s2.eu.hivemq.cloud:8883
topic eGV70 out 1 "" ""
bridge_attempt_unsubscribe false
keepalive_interval 15
notifications false
restart_timeout 10
cleansession false
max_queued_messages 10000
autosave_interval 300
queue_qos0_messages true
try_private false
bridge_protocol_version mqttv311
max_inflight_messages 10
remote_username xxxx
remote_password xxxx
remote_clientid autopi-sync
bridge_capath /etc/ssl/certs/
bridge_insecure true
```
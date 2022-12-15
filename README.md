# gv70-tools


Shifting bits in DBC:
```
cat ev6.dbc | python -c 'import re,sys; print(re.sub(": (\d+)\|", lambda i: ": "+str(int(i.group(1))-8)+"|" if i.group(1) else "",sys.stdin.read()))' > ev6-8bit.dbc
```

Requests:
```
BMS: b'\x03\x22\x01\x01\xAA\xAA\xAA\xAA'
SOH: b'\x03\x22\x01\x05\xAA\xAA\xAA\xAA'
CellVoltage1: b'\x03\x22\x01\x02\xAA\xAA\xAA\xAA'
CellVoltage2: b'\x03\x22\x01\x03\xAA\xAA\xAA\xAA'
CellVoltage3: b'\x03\x22\x01\x04\xAA\xAA\xAA\xAA'
CellVoltage4: b'\x03\x22\x01\x0A\xAA\xAA\xAA\xAA'
CellVoltage5: b'\x03\x22\x01\x0B\xAA\xAA\xAA\xAA'
CellVoltage6: b'\x03\x22\x01\x0C\xAA\xAA\xAA\xAA'
Temperatures: b'\x03\x22\x01\x00\xAA\xAA\xAA\xAA'
Tires: b'\x03\x22\xC0\x0B\xAA\xAA\xAA\xAA'
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
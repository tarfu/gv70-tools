# gv70-tools

## What is the goal?

The goal of project is to have two functions:
- put all telemetry data I can get into an mqtt boker which ships it to an influxDB.
- Push Data to ABRP (https://abetterrouteplanner.com)

The telemtry data is put into a influxDB as Grafana only has 2 weeks retention in there prometheus free tier.
There will be other dataformats added for more flexibility.

## Setup on AutoPI
First follow the setup of: https://github.com/ugoogalizer/autopi-ioniq5/blob/8383ccfedd08e45d2940d75e5ad1481615110fc4/README.md
The two pids described there are in the community library of autopi and you won't need to add them manualy.

You also need the Docker Addon activated!

### (optional) Setup datashipment from local to remote MQTT
I use the local MQTT as a broker which then pushes the data on. So it wouldn't be hindered in shippment of data when we don't have an internet connection. Right now this goal is hindered by the fact that the ABRP shipment blocks right now.


- In settings enable the MQTT broker (Mosquitto v1.x)
- add the following lines to the custom config line by line to enable remote shippment from the local MQTT to a remote one: (`<placeholder>` is used to replace it with a value fitting for you (credentials and such))
```
connection <topic_name>
address <remote_mqtt_host>:<remote_mqtt_port>
topic <topic_name> out 1 "" ""
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
remote_username <remote_mqtt_user>
remote_password <remote_mqtt_password>
remote_clientid autopi-sync
bridge_capath /etc/ssl/certs/
bridge_insecure true
```

### add docker container to run on AutoPI

TBD

## Notes

Shifting bits in DBC:
```
cat eGV70.dbc | python -c 'import re,sys; print(re.sub(": (\d+)\|", lambda i: ": "+str(int(i.group(1))-8)+"|" if i.group(1) else "",sys.stdin.read()))' > eGV70-8bit.dbc
```

sending receiving with isotp-utils (padding important):
```
echo "22 01 01" | isotpsend -s 7e4 -d 7EC -p AA can0
isotprecv -d 7ec -s 7e4 -b 0 can0 -l -p 00
```

Requests (First Byte is isotp header for single frame (0 for single frame 3 for datalength) `\xAA` is padding and can be left)
the answer is normally send to `<address you send your request to>+8`
```
BMS (rxid=0x7EC, txid=0x7E4): b'\x03\x22\x01\x01'
SOH (rxid=0x7EC, txid=0x7E4): b'\x03\x22\x01\x05'
CellVoltage1 (rxid=0x7EC, txid=0x7E4): b'\x03\x22\x01\x02'
CellVoltage2 (rxid=0x7EC, txid=0x7E4): b'\x03\x22\x01\x03'
CellVoltage3 (rxid=0x7EC, txid=0x7E4): b'\x03\x22\x01\x04'
CellVoltage4 (rxid=0x7EC, txid=0x7E4): b'\x03\x22\x01\x0A'
CellVoltage5 (rxid=0x7EC, txid=0x7E4): b'\x03\x22\x01\x0B'
CellVoltage6 (rxid=0x7EC, txid=0x7E4): b'\x03\x22\x01\x0C'
Temperatures (rxid=0x7BB, txid=0x7B3): b'\x03\x22\x01\x00'
Tires (rxid=0x7A8, txid=0x7A0): b'\x03\x22\xC0\x0B'
Car (rxid=0x7CE, txid=7C6): b'\x03\x22\xB0\x02'
```

Basis for ev6.dbc:
https://github.com/JejuSoul/OBD-PIDs-for-HKMC-EVs/issues/58
https://www.csselectronics.com/pages/kia-ev6-can-bus-data-uds-dbc


Getting GPS location in docker (yes the trailing / is needed) host networking assumed:
```
curl -vvv -X POST -H "Content-Type: application/json" -d '["ec2x.gnss_location"]' http://localhost:9000/dongle/94820371-fbcc-2338-ca38-2ca83b77c293/execute/
```

GPS for CM4 (maybe works for others as well?)
```
curl -vvv -X POST -H "Content-Type: application/json" -d '["modem.connection", "gnss_location"]' http://localhost:9000/dongle/c47afd22-5ecc-5ccf-cd52-9f7e8d17517b/execute/
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


kw in influx:
```
from(bucket: "eGV70")
  |> range(start: v.timeRangeStart, stop: v.timeRangeStop)
  |> filter(fn: (r) => r["_measurement"] == "temps" or r["_measurement"] == "battery")
  |> filter(fn: (r) => r["_field"] == "BatteryDCVoltage" or r["_field"] == "BatteryCurrent")
  |> pivot(rowKey: ["_time"], columnKey: ["_field"], valueColumn: "_value")
  |> map(fn: (r) => ({r with _value: (r.BatteryDCVoltage * r.BatteryCurrent) / 1000.0}))
  |> aggregateWindow(every: v.windowPeriod, fn: mean)
  |> yield(name: "kwh")
  ```

import os
import isotp
import logging
import time
import threading
import can
import cantools
import sys
import json

from influx_line_protocol import Metric

from can.interfaces.socketcan import SocketcanBus
import paho.mqtt.client as mqtt

import paho.mqtt.publish as publish



def eprint(*args, **kwargs):
    print(*args, file=sys.stderr, **kwargs)





def metric_from_dict(name ,messurements, time_ns):
    print(messurements)
    metric = Metric(name)
    metric.with_timestamp(time_ns)
    if messurements is None:
        return {}
    for key, value in messurements.items():
        metric.add_value(key, value)
    return str(metric)  
    
    

def main():
    
    dbc_file_path = os.getenv("DBC_FILE", "eGV70-8bit.dbc")
    can_interface = os.getenv("CAN_INTERFACE", "vcan0")
    query_intervall = os.getenv("QUERY_INTERVAL", 30)
    mqtt_host = os.getenv("MQTT_HOST", "localhost")
    mqtt_port = os.getenv("MQTT_PORT", 8883)
    mqtt_username = os.getenv("MQTT_USER")
    mqtt_password = os.getenv("MQTT_PASSWORD")
    mqtt_topic = os.getenv("MQTT_TOPIC", "eGV70")
    
    while True:
        results = []
        now = time.time_ns()
        
        
        message_battery = {"topic": mqtt_topic, "payload": metric_from_dict("battery", {"test": 14}, now)}
        
        mqtt_auth = None if mqtt_username == None or mqtt_password == None else {"username": mqtt_username, "password": mqtt_password}
        print([message_battery])
        print({"username": mqtt_username, "password": mqtt_password})
        print({"messages": [message_battery], "hostname": mqtt_host, "port":mqtt_port, "auth":mqtt_auth, "client_id": "egv70-metrics", "protocol": mqtt.MQTTv311})
        publish.multiple([message_battery], hostname=mqtt_host, port=mqtt_port, auth=mqtt_auth, client_id="egv70-metrics", protocol=mqtt.MQTTv311, tls={"insecure": True})
        
        time.sleep(query_intervall)

    print("Exiting")

    return 0

if __name__ == '__main__':
    exit(main())

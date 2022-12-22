import os
import isotp
import time
import can
import cantools
import sys
import json
import requests

from influx_line_protocol import Metric

import paho.mqtt.client as mqtt

import paho.mqtt.publish as publish


def pad_payload(data, length=62) -> bytearray:
    data2 = data.ljust(length, b'\0')
    # padded = bytearray(b'\x00') # Not needed with new dbc
    # padded.extend(data2) # Not needed with new dbc
    return data2


def eprint(*args, **kwargs):
    print(*args, file=sys.stderr, **kwargs)


def process_command(sender: isotp.socket, reveiver: isotp.socket, command, response_length, parsed_database, read_timeout=5, read_pause=0.1):
    try:
        reveiver.send(command)
    except Exception as e:
        eprint(command.hex()+": "+repr(e))
        return {}

    t1 = time.time()
    while time.time() - t1 < read_timeout:
        try:
            data = reveiver.recv()
            if data:
                payload = pad_payload(data, response_length)
                try:
                    decoded = parsed_database.decode_message(
                        reveiver.address.rxid, payload)
                    return decoded if decoded is not None else {}
                except Exception as e:
                    # pass
                    eprint(payload.hex()+": "+repr(e))
                    return {}
                    # logging.error(traceback.format_exc())
            time.sleep(read_pause)
        except Exception as e:
            eprint(repr(e))
            return {}
    return {}

def process_BMS(app_7E4, db) -> dict:
    return process_command(app_7E4["sender"], app_7E4["receiver"], b'\x22\x01\x01', 62, db)


def process_SOH(app_7E4, db) -> dict:
    return process_command(app_7E4["sender"], app_7E4["receiver"], b'\x22\x01\x05', 62, db)


def process_Cell_Voltage(app_7E4, db) -> dict:
    commands = [b'\x22\x01\x02', b'\x22\x01\x03', b'\x22\x01\x04',
                b'\x22\x01\x0A', b'\x22\x01\x0B', b'\x22\x01\x0C']
    result = {}
    for command in commands:
        result |= process_command(app_7E4["sender"], app_7E4["receiver"], command, 62, db)
    return result


def process_Temperatures(app_7B3, db) -> dict:
    return process_command(app_7B3["sender"], app_7B3["receiver"], b'\x22\x01\x00', 54, db)


def process_Tires(app_7A0, db) -> dict:
    return process_command(app_7A0["sender"], app_7A0["receiver"], b'\x22\xC0\x0B', 64, db)


def get_gnss(deviceID):
    headers = {
        # Already added when you pass json=
        # 'Content-Type': 'application/json',
    }

    json_data = [
        'ec2x.gnss_location',
    ]

    response = requests.post(
        'http://localhost:9000/dongle/'+deviceID+'/execute/',
        headers=headers,
        json=json_data,
    )
    try:
        return response.json()
    except Exception as e:
        return {"error": repr(e)}


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
    mqtt_port = os.getenv("MQTT_PORT", 1883)
    mqtt_username = os.getenv("MQTT_USER")
    mqtt_password = os.getenv("MQTT_PASSWORD")
    mqtt_topic = os.getenv("MQTT_TOPIC", "eGV70")
    mqtt_tls = os.getenv("MQTT_TLS", "False").lower() in ['true', '1', 'yes', 'y', 't']
    mqtt_tls_insecure = os.getenv("MQTT_TLS_INSECURE", "False").lower() in ['true', '1', 'yes', 'y', 't']
    autopi_deviceID = os.getenv("AUTOPI_DEVICEID")
    
    mqtt_auth = None if mqtt_username == None or mqtt_password == None else {"username": mqtt_username, "password": mqtt_password}
    tls = None if not mqtt_tls else {"insecure": mqtt_tls_insecure}
    
    db = cantools.database.load_file(dbc_file_path)
    def can_bus(dev): return can.interface.Bus(dev, bustype='socketcan')

    app_7E4 = {"sender": isotp.socket(), "receiver": isotp.socket()} 
    app_7E4["receiver"].set_fc_opts(stmin=5, bs=0)
    app_7E4["sender"].bind(can_interface, address=isotp.Address(isotp.AddressingMode.Normal_11bits, rxid=0x7E4, txid=0x7EC))
    app_7E4["receiver"].bind(can_interface, isotp.Address(isotp.AddressingMode.Normal_11bits, rxid=0x7EC, txid=0x7E4))
    app_7B3 = {"sender": isotp.socket(), "receiver": isotp.socket()} 
    app_7B3["receiver"].set_fc_opts(stmin=5, bs=0)
    app_7B3["sender"].bind(can_interface, isotp.Address(isotp.AddressingMode.Normal_11bits, rxid=0x7B3, txid=0x7BB))
    app_7B3["receiver"].bind(can_interface, isotp.Address(isotp.AddressingMode.Normal_11bits, rxid=0x7BB, txid=0x7B3))
    app_7A0 = {"sender": isotp.socket(), "receiver": isotp.socket()} 
    app_7A0["receiver"].set_fc_opts(stmin=5, bs=0)
    app_7A0["sender"].bind(can_interface, isotp.Address(isotp.AddressingMode.Normal_11bits, rxid=0x7A0, txid=0x7A8))
    app_7A0["receiver"].bind(can_interface, isotp.Address(isotp.AddressingMode.Normal_11bits, rxid=0x7A8, txid=0x7A0))


    while True:
        results = []
        now = time.time_ns()
        battery = process_BMS(app_7E4, db)
        cell_voltages = process_Cell_Voltage(app_7E4, db)
        health = process_SOH(app_7E4, db)
        temps = process_Temperatures(app_7B3, db)
        tires = process_Tires(app_7A0, db)
        gnss = {}
        if autopi_deviceID:
            gnss = get_gnss(autopi_deviceID)
        
        
        message_battery = {"topic": mqtt_topic, "payload": metric_from_dict("battery", battery, now)}
        message_cell_voltages = {"topic": mqtt_topic, "payload": metric_from_dict("cell_voltages", cell_voltages, now)}
        message_health = {"topic": mqtt_topic, "payload": metric_from_dict("health", health, now)}
        message_temps = {"topic": mqtt_topic, "payload": metric_from_dict("temps", temps, now)}
        message_tires = {"topic": mqtt_topic, "payload": metric_from_dict("tires", tires, now)}
        message_gnss = {"topic": mqtt_topic, "payload": metric_from_dict("gnss", gnss, now)}
        
        if gnss["error"]:
            eprint("GNNS Error:" + gnss["error"])
            gnss = {}
            
        messages = []
        if len(battery) != 0:
            messages.append(message_battery)
        if len(cell_voltages) != 0:
            messages.append(message_cell_voltages)
        if len(health) != 0:
            messages.append(message_health)
        if len(temps) != 0:
            messages.append(message_temps)
        if len(tires) != 0:
            messages.append(message_tires)
        if len(gnss) != 0:
            messages.append(message_gnss)
        
        print("messages("+len(messages)+": "+messages)
        if len(messages) > 0:
            publish.multiple(messages, hostname=mqtt_host, port=int(mqtt_port), auth=mqtt_auth, client_id="egv70-metrics", protocol=mqtt.MQTTv311, tls=tls)
        
        time.sleep(query_intervall)

    print("Exiting")

    return 0

if __name__ == '__main__':
    exit(main())

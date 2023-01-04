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
        sender.send(command)
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

def process_Odometer(app_7C6, db) -> dict:
    return process_command(app_7C6["sender"], app_7C6["receiver"], b'\x22\xB0\x02', 64, db)

def check_autopi_socketcan_and_set_up(deviceID, ifname: str) -> bool:
    ifstatus = send_autopi_command(deviceID, [f"socketcan.show", ifname])
    eprint(ifstatus)
    if "error" in ifstatus:
        eprint(ifstatus)
        return False
    if ifstatus.get("operstate", "DOWN").lower() == "down":
        upstate = send_autopi_command(deviceID, ['socketcan.up', ifname])
        eprint(upstate)
        if "error" in upstate:
            eprint(upstate)
            return False
        return True
    return True

def send_autopi_command(deviceID: str, command: list):
    headers = {
        # Already added when you pass json=
        'Content-Type': 'application/json',
    }

    json_data = command

    try:
        response = requests.post(
            'http://localhost:9000/dongle/'+deviceID+'/execute/',
            headers=headers,
            json=json_data,
        )

        return response.json()
    except Exception as e:
        return {"error": repr(e)}

def get_gnss(deviceID):
    return send_autopi_command(deviceID, ['ec2x.gnss_location'])


def metric_from_dict(name ,messurements, time_ns):
    print(messurements)
    metric = Metric(name)
    metric.with_timestamp(time_ns)
    if messurements is None:
        return {}
    for key, value in messurements.items():
        metric.add_value(key, value)
    return str(metric)  
    
def send_abrp(epoch, message_dict, api_token, car_token, timeout=5):
    api_url = "https://api.iternio.com/1/tlm/send"
    
    headers = {
        'Authorization': 'APIKEY '+api_token,
        # Already added when you pass json=
        'Content-Type': 'application/json', 
    }

    dc_volate = message_dict['battery'].get('BatteryDCVoltage') if message_dict['battery'].get('BatteryDCVoltage') else 0
    bat_current = message_dict['battery'].get('BatteryCurrent') if message_dict['battery'].get('BatteryCurrent') else 0

    json_data = {
        'token': car_token,
        'tlm': {
            # time
            'utc': epoch,
            # gps
            'lat': message_dict['gnss'].get('lat'),
            'lon': message_dict['gnss'].get('lon'),
            'heading': message_dict['gnss'].get('cog'),
            'elevation': message_dict['gnss'].get('alt'),
            # battery
            'soc': message_dict['battery'].get('StateOfChargeDisplay'),
            'power': (dc_volate * bat_current)/1000 if dc_volate * bat_current != 0 else None,
            'is_charging': message_dict['battery'].get('Charging'),
            'is_dcfc': message_dict['battery'].get('RapidChargePort'),
            'kwh_charged': message_dict['battery'].get('CEC_CumulativeEnergyCharged'),
            'voltage': message_dict['battery'].get('BatteryDCVoltage'),
            'current': message_dict['battery'].get('BatteryCurrent'),
            'batt_temp': message_dict['battery'].get('BatteryMinTemperature'),
            # health
            'soh': message_dict['health'].get('StateOfHealth'),
            # car
            'ext_temp': message_dict['temps'].get('OutdoorTemperature'),
            'odometer': message_dict['car'].get('Odometer'),
            'speed': message_dict['temps'].get('VehicleSpeed'),
        }
    }
    
    
    try:
        response = requests.post(
            api_url,
            headers=headers,
            json=json_data,
        )
    
        return response.json()
    except Exception as e:
        return {
            "status": "exception",
            "errors": repr(e)
            }
    
        

def main():
    
    dbc_file_path = os.getenv("DBC_FILE", "eGV70-8bit.dbc")
    can_interface = os.getenv("CAN_INTERFACE", "vcan0")
    query_intervall = os.getenv("QUERY_INTERVAL", 10)
    mqtt_host = os.getenv("MQTT_HOST", "localhost")
    mqtt_port = os.getenv("MQTT_PORT", 1883)
    mqtt_username = os.getenv("MQTT_USER")
    mqtt_password = os.getenv("MQTT_PASSWORD")
    mqtt_topic = os.getenv("MQTT_TOPIC", "eGV70")
    mqtt_tls = os.getenv("MQTT_TLS", "False").lower() in ['true', '1', 'yes', 'y', 't']
    mqtt_tls_insecure = os.getenv("MQTT_TLS_INSECURE", "False").lower() in ['true', '1', 'yes', 'y', 't']
    autopi_deviceID = os.getenv("AUTOPI_DEVICEID")
    autopi_set_socketcan_up = os.getenv("AUTOPI_SET_SOCKETCAN_UP", "True").lower() in ['true', '1', 'yes', 'y', 't']
    autopi_die_if_can_not_set_up = os.getenv("AUTOPI_DIE_IF_CAN_NOT_SET_UP", "True").lower() in ['true', '1', 'yes', 'y', 't']
    abrp_apikey = os.getenv("ABRP_APIKEY")
    abrp_cartoken = os.getenv("ABRP_CARTOKEN")
    
    if autopi_set_socketcan_up:
        could_set_up = check_autopi_socketcan_and_set_up(autopi_deviceID, can_interface)
        if  not could_set_up and autopi_die_if_can_not_set_up:
            sys.exit(5)
    
    mqtt_auth = None if mqtt_username == None or mqtt_password == None else {"username": mqtt_username, "password": mqtt_password}
    tls = None if not mqtt_tls else {"insecure": mqtt_tls_insecure}
    
    db = cantools.database.load_file(dbc_file_path)

    app_7E4 = {"sender": isotp.socket(), "receiver": isotp.socket()} 
    app_7E4["receiver"].set_fc_opts(stmin=0, bs=0)
    app_7E4["receiver"].set_opts(txpad=0x00)
    app_7E4["sender"].set_opts(txpad=0xAA)
    app_7E4["sender"].bind(can_interface, isotp.Address(isotp.AddressingMode.Normal_11bits, rxid=0x00, txid=0x7E4))
    app_7E4["receiver"].bind(can_interface, isotp.Address(isotp.AddressingMode.Normal_11bits, rxid=0x7EC, txid=0x7E4))
    app_7B3 = {"sender": isotp.socket(), "receiver": isotp.socket()} 
    app_7B3["receiver"].set_fc_opts(stmin=0, bs=0)
    app_7B3["receiver"].set_opts(txpad=0x00)
    app_7B3["sender"].set_opts(txpad=0xAA)
    app_7B3["sender"].bind(can_interface, isotp.Address(isotp.AddressingMode.Normal_11bits, rxid=0x00, txid=0x7B3))
    app_7B3["receiver"].bind(can_interface, isotp.Address(isotp.AddressingMode.Normal_11bits, rxid=0x7BB, txid=0x7B3))
    app_7A0 = {"sender": isotp.socket(), "receiver": isotp.socket()} 
    app_7A0["receiver"].set_fc_opts(stmin=0, bs=0)
    app_7A0["receiver"].set_opts(txpad=0x00)
    app_7A0["sender"].set_opts(txpad=0xAA)
    app_7A0["sender"].bind(can_interface, isotp.Address(isotp.AddressingMode.Normal_11bits, rxid=0x00, txid=0x7A0))
    app_7A0["receiver"].bind(can_interface, isotp.Address(isotp.AddressingMode.Normal_11bits, rxid=0x7A8, txid=0x7A0))
    app_7C6 = {"sender": isotp.socket(), "receiver": isotp.socket()} 
    app_7C6["receiver"].set_fc_opts(stmin=0, bs=0)
    app_7C6["receiver"].set_opts(txpad=0x00)
    app_7C6["sender"].set_opts(txpad=0xAA)
    app_7C6["sender"].bind(can_interface, isotp.Address(isotp.AddressingMode.Normal_11bits, rxid=0x00, txid=0x7C6))
    app_7C6["receiver"].bind(can_interface, isotp.Address(isotp.AddressingMode.Normal_11bits, rxid=0x7CE, txid=0x7C6))


    while True:
        now_ns = time.time_ns()
        now_s = time.time()
        epoch = int(time.time())
        next_run = (now_s+query_intervall)
        skip_abrp_epoch = 0
        message = {}
        message["battery"] = process_BMS(app_7E4, db)
        message["cell_voltages"] = process_Cell_Voltage(app_7E4, db)
        message["health"] = process_SOH(app_7E4, db)
        message["temps"] = process_Temperatures(app_7B3, db)
        message["tires"] = process_Tires(app_7A0, db)
        message["car"] = process_Odometer(app_7C6, db)
        message["gnss"] = {}
        if autopi_deviceID:
            message["gnss"] = get_gnss(autopi_deviceID)
            
        if "error" in message["gnss"]:
            eprint("GNNS Error:" + message["gnss"]["error"])
            message["gnss"] = {}
        
        messages = []

        for key, value in message.items():
            msg = {"topic": mqtt_topic, "payload": metric_from_dict(key, value, now_ns)}
            if len(message[key]) != 0:
                messages.append(msg)
                
        
        eprint("messages("+str(len(messages))+": "+str(messages))
        if len(messages) > 0 and not (len(message['gnss']) != 0 and len(messages) == 1): # ignore gnss for sending decission
            publish.multiple(messages, hostname=mqtt_host, port=int(mqtt_port), auth=mqtt_auth, client_id="egv70-metrics", protocol=mqtt.MQTTv311, tls=tls)
        
            if abrp_apikey and abrp_cartoken and time.time()>skip_abrp_epoch:
                status = send_abrp(epoch, message, abrp_apikey, abrp_cartoken)
                if status.get("status") != "ok" and "errors" in status:
                    eprint(status)
                    skip_abrp_epoch=time.time()+60
                    eprint('error sending abrp pausing it for 1 minute')
            
        if len(messages) == 0:
            next_run = next_run+60
            eprint('non messages found sleeping 1 minute extra')
        sleeptime = next_run - time.time()
        time.sleep( sleeptime if sleeptime > 0 else 0 )

    print("Exiting")

    return 0

if __name__ == '__main__':
    sys.exit(main())

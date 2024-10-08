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


def process_command(sender: isotp.socket, receiver: isotp.socket, command, response_length, parsed_database, read_timeout=0.5, read_pause=0.1, resend_on_wrong_response_code=True):
    try:
        sender.send(command)
    except Exception as e:
        eprint(command.hex()+": "+repr(e))
        return {}

    t1 = time.time()
    while time.time() - t1 < read_timeout:
        try:
            data = receiver.recv()
            if data:
                payload = pad_payload(data, response_length)
                try:
                    decoded = parsed_database.decode_message(
                        receiver.address.rxid, payload)
                    if resend_on_wrong_response_code and decoded is not None and not decoded.get("response") == int.from_bytes(command[-2:], 'big', signed=False):
                        decoded = process_command(
                            sender=sender,
                            receiver=receiver,
                            command=command,
                            response_length=response_length,
                            parsed_database=parsed_database,
                            read_timeout=read_timeout,
                            read_pause=read_pause,
                            resend_on_wrong_response_code=False)
                    return decoded if decoded is not None and decoded.get("response") == int.from_bytes(command[-2:], 'big', signed=False) else {}
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
    command = b'\x22\x01\x01'
    response = process_command(app_7E4["sender"], app_7E4["receiver"], command, 62, db)
    if len(response) == 0:
        eprint(f"No Data for Command: {command.hex()}")
    return response


def process_SOH(app_7E4, db) -> dict:
    command = b'\x22\x01\x05'
    response = process_command(app_7E4["sender"], app_7E4["receiver"], command, 62, db)
    if len(response) == 0:
        eprint(f"No Data for Command: {command.hex()}")
    return response


def process_Cell_Voltage(app_7E4, db) -> dict:
    commands = [b'\x22\x01\x02', b'\x22\x01\x03', b'\x22\x01\x04',
                b'\x22\x01\x0A', b'\x22\x01\x0B', b'\x22\x01\x0C']
    result = {}
    for command in commands:
        response = process_command(app_7E4["sender"], app_7E4["receiver"], command, 62, db)
        if len(response) == 0:
            eprint(f"No Data for Command: {command.hex()}")
        result |= response
    return result


def process_Temperatures(app_7B3, db) -> dict:
    command = b'\x22\x01\x00'
    response = process_command(app_7B3["sender"], app_7B3["receiver"], command, 54, db)
    if len(response) == 0:
        eprint(f"No Data for Command: {command.hex()}")
    return response


def process_Tires(app_7A0, db) -> dict:
    command = b'\x22\xC0\x0B'
    response = process_command(app_7A0["sender"], app_7A0["receiver"], command, 64, db)
    if len(response) == 0:
        eprint(f"No Data for Command: {command.hex()}")
    return response

def process_Odometer(app_7C6, db) -> dict:
    command = b'\x22\xB0\x02'
    response = process_command(app_7C6["sender"], app_7C6["receiver"], command, 64, db)
    if len(response) == 0:
        eprint(f"No Data for Command: {command.hex()}")
    return response

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

def send_autopi_command(deviceID: str, command: list, timeout=5):
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
            timeout=timeout
        )

        return response.json()
    except Exception as e:
        return {"error": repr(e)}

def get_autopi_unit_id(timeout=5) -> str:
    headers = {
        # Already added when you pass json=
        'Content-Type': 'application/json',
    }

    try:
        response = requests.get(
            'http://localhost:9000/',
            headers=headers,
            timeout=timeout
        )

        unit_id = response.json().get("unit_id")
        if not unit_id:
            eprint(f"error getting autopi unit_id: {response.json()}")
        return unit_id
    except Exception as e:
        eprint(f"error getting autopi unit_id: {repr(e)}")
        return None

def get_gnss(deviceID):
    #for ec2x module:
    # return send_autopi_command(deviceID, ['ec2x.gnss_location'])
    #for le910cx module:
    return send_autopi_command(deviceID, ['modem.connection', 'gnss_location', 'decimal_degrees=True'])


def metric_from_dict(name ,messurements, time_ns):
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

    dc_volate = message_dict['battery'].get('BatteryDCVoltage', 0)
    bat_current = message_dict['battery'].get('BatteryCurrent', 0)
    is_charging = message_dict['temps'].get('VehicleSpeed', 0) <= 0 and  bat_current < 0

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
            'power': (dc_volate * bat_current)/1000 if dc_volate * bat_current != 0 else None,
            'is_charging': is_charging,
            'is_dcfc': message_dict['battery'].get('RapidChargePort'),
            'kwh_charged': message_dict['battery'].get('CEC_CumulativeEnergyCharged'),
            'voltage': message_dict['battery'].get('BatteryDCVoltage'),
            'current': message_dict['battery'].get('BatteryCurrent'),
            'batt_temp': message_dict['battery'].get('BatteryMinTemperature'),
            # health
            'soc': message_dict['health'].get('StateOfChargeDisplay'),
            'soh': message_dict['health'].get('StateOfHealth'),
            'soe': message_dict['battery'].get('StateOfChargeBMS', 0)/100*77.4 if message_dict['battery'].get('StateOfChargeBMS') else None,
            # car
            'ext_temp': message_dict['temps'].get('OutdoorTemperature'),
            'cabin_temp': message_dict['temps'].get('IndoorTemperature'),
            'odometer': message_dict['car'].get('Odometer'),
            'speed': message_dict['temps'].get('VehicleSpeed'),
            'tire_pressure_fl': message_dict['tires'].get('TirePressureFrontLeft', 0) * 6.8947572932 if message_dict['tires'].get('TirePressureFrontLeft') else None,
            'tire_pressure_fr': message_dict['tires'].get('TirePressureFrontRight', 0) * 6.8947572932 if message_dict['tires'].get('TirePressureFrontRight') else None,
            'tire_pressure_rl': message_dict['tires'].get('TirePressureBackLeft', 0) * 6.8947572932 if message_dict['tires'].get('TirePressureBackLeft') else None,
            'tire_pressure_rr': message_dict['tires'].get('TirePressureBackRight', 0) * 6.8947572932 if message_dict['tires'].get('TirePressureBackRight') else None,
        }
    }
    
    
    try:
        response = requests.post(
            api_url,
            headers=headers,
            json=json_data,
            timeout=timeout
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
    query_intervall = int(os.getenv("QUERY_INTERVAL", "5"))
    mqtt_host = os.getenv("MQTT_HOST", "localhost")
    mqtt_port = os.getenv("MQTT_PORT", 1883)
    mqtt_username = os.getenv("MQTT_USER")
    mqtt_password = os.getenv("MQTT_PASSWORD")
    mqtt_topic = os.getenv("MQTT_TOPIC", "eGV70")
    mqtt_tls = os.getenv("MQTT_TLS", "False").lower() in ['true', '1', 'yes', 'y', 't']
    mqtt_publish = os.getenv("MQTT_PUBLISH", "True").lower() in ['true', '1', 'yes', 'y', 't']
    mqtt_tls_insecure = os.getenv("MQTT_TLS_INSECURE", "False").lower() in ['true', '1', 'yes', 'y', 't']
    autopi_set_socketcan_up = os.getenv("AUTOPI_SET_SOCKETCAN_UP", "True").lower() in ['true', '1', 'yes', 'y', 't']
    autopi_die_if_can_not_set_up = os.getenv("AUTOPI_DIE_IF_CAN_NOT_SET_UP", "True").lower() in ['true', '1', 'yes', 'y', 't']
    abrp_apikey = os.getenv("ABRP_APIKEY")
    abrp_cartoken = os.getenv("ABRP_CARTOKEN")
    reset_modem_on_gps_stuck = os.getenv("RESET_MODEM_ON_GPS_STUCK", "True").lower() in ['true', '1', 'yes', 'y', 't']



    autopi_deviceID = get_autopi_unit_id()
    if not autopi_deviceID:
        sys.exit(5)
    
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


    last_gnss_time = ""
    gnss__stuck_time = 0
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
        
        if last_gnss_time == message["gnss"].get("time_utc") and reset_modem_on_gps_stuck:
            message["gnss"] = {}
            if gnss__stuck_time == 0:
                gnss__stuck_time = epoch
            eprint(f"GNSS: No updated Position available leaving gnss out")
            if epoch - gnss__stuck_time > 180: # stuck for 3 minutes we want to reboot
                eprint("GNSS: Stuck for 3 minutes resetting")
                gnss__stuck_time = 0
                send_autopi_command(autopi_deviceID, ['modem.reset', 'mode=one_shot'])
        else:
            last_gnss_time = message["gnss"].get("time_utc")
            gnss__stuck_time = 0

        messages = []

        for key, value in message.items():
            msg = {"topic": mqtt_topic, "payload": metric_from_dict(key, value, now_ns)}
            if len(message[key]) != 0:
                messages.append(msg)
                
        
        eprint(f"messages({len(messages)}) received")
        if len(messages) > 0 and not (len(message['gnss']) != 0 and len(messages) == 1): # ignore gnss for sending decission
            if mqtt_publish:
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

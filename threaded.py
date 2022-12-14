import isotp
import logging
import time
import threading
import can
import cantools
import sys
import json

from can.interfaces.socketcan import SocketcanBus


def pad_payload(data, length=62) -> bytearray:
    data2 = data.ljust(length, b'\0')
    # padded = bytearray(b'\x00') # Not needed with new dbc
    # padded.extend(data2) # Not needed with new dbc
    return data2


def eprint(*args, **kwargs):
    print(*args, file=sys.stderr, **kwargs)


def process_command(stack, command, response_length, parsed_database, read_timeout=5, read_pause=0.1):
    stack.send(command)
    while stack.transmitting():
        time.sleep(stack.sleep_time())

    t1 = time.time()
    while time.time() - t1 < read_timeout:
        if stack.available():
            payload = pad_payload(stack.recv(), response_length)
            try:
                decoded = parsed_database.decode_message(
                    stack.address.rxid, payload)
                return decoded
            except Exception as e:
                # pass
                eprint(payload.hex()+": "+repr(e))
                return None
                # logging.error(traceback.format_exc())
        time.sleep(read_pause)


def process_BMS(app_7E4, db) -> dict:
    return process_command(app_7E4.stack, b'\x03\x22\x01\x01\xAA\xAA\xAA\xAA', 62, db)


def process_SOH(app_7E4, db) -> dict:
    return process_command(app_7E4.stack, b'\x03\x22\x01\x05\xAA\xAA\xAA\xAA', 62, db)


def process_Cell_Voltage(app_7E4, db) -> dict:
    commands = [b'\x03\x22\x01\x02\xAA\xAA\xAA\xAA', b'\x03\x22\x01\x03\xAA\xAA\xAA\xAA', b'\x03\x22\x01\x04\xAA\xAA\xAA\xAA',
                b'\x03\x22\x01\x0A\xAA\xAA\xAA\xAA', b'\x03\x22\x01\x0B\xAA\xAA\xAA\xAA', b'\x03\x22\x01\x0C\xAA\xAA\xAA\xAA']
    result = {}
    for command in commands:
        result |= process_command(app_7E4.stack, command, 62, db)
    return result


def process_Temperatures(app_7B3, db) -> dict:
    return process_command(app_7B3.stack, b'\x03\x22\x01\x00\xAA\xAA\xAA\xAA', 54, db)


def process_Tires(app_7A0, db) -> dict:
    return process_command(app_7A0.stack, b'\x03\x22\xC0\x0B\xAA\xAA\xAA\xAA', 64, db)


class ThreadedApp:
    def __init__(self,
                 bus=SocketcanBus(channel='vcan0'),
                 addr=isotp.Address(isotp.AddressingMode.Normal_11bits, rxid=0x123, txid=0x456)):
        self.exit_requested = False
        self.bus = bus
        addr = addr
        self.stack = isotp.CanStack(
            self.bus, address=addr, error_handler=self.my_error_handler, params={"blocksize": 0})

    def start(self):
        self.exit_requested = False
        self.thread = threading.Thread(target=self.thread_task)
        self.thread.start()

    def stop(self):
        self.exit_requested = True
        if self.thread.isAlive():
            self.thread.join()

    def my_error_handler(self, error):
        logging.warning('IsoTp error happened : %s - %s' %
                        (error.__class__.__name__, str(error)))

    def thread_task(self):
        while self.exit_requested == False:
            self.stack.process()                # Non-blocking
            # Variable sleep time based on state machine state
            time.sleep(self.stack.sleep_time())

    def shutdown(self):
        self.stop()
        self.bus.shutdown()


if __name__ == '__main__':

    db = cantools.database.load_file('ev6.dbc')
    def can_bus(dev): return can.interface.Bus(dev, bustype='socketcan')

    app_7E4 = ThreadedApp(
        bus=can_bus("vcan0"),
        addr=isotp.Address(isotp.AddressingMode.Normal_11bits,
                           rxid=0x7EC, txid=0x7E4)
    )
    app_7E4.start()

    app_7B3 = ThreadedApp(
        bus=can_bus("vcan0"),
        addr=isotp.Address(isotp.AddressingMode.Normal_11bits,
                           rxid=0x7BB, txid=0x7B3)
    )
    app_7B3.start()

    app_7A0 = ThreadedApp(
        bus=can_bus("vcan0"),
        addr=isotp.Address(isotp.AddressingMode.Normal_11bits,
                           rxid=0x7A8, txid=0x7A0)
    )
    app_7A0.start()

    while True:
        results = []
        results.append(process_BMS(app_7E4, db))
        results.append(process_Cell_Voltage(app_7E4, db))
        results.append(process_SOH(app_7E4, db))
        results.append(process_Temperatures(app_7B3, db))
        results.append(process_Tires(app_7A0, db))
        print(json.dumps(results))

    print("Exiting")
    app_7E4.shutdown()

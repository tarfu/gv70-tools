import can
import isotp
import cantools
import logging
import time
import traceback
import json
import sys

def my_error_handler(error):
   logging.warning('IsoTp error happened : %s - %s' % (error.__class__.__name__, str(error)))

def eprint(*args, **kwargs):
    print(*args, file=sys.stderr, **kwargs)

if __name__ == '__main__':
    db = cantools.database.load_file('ev6.dbc')
    can_bus = can.interface.Bus('vcan0', bustype='socketcan')

    addr = isotp.Address(isotp.AddressingMode.Normal_11bits, rxid=0x7EC, txid=0x0)

    stack = isotp.CanStack(can_bus, address=addr, error_handler=my_error_handler, params={"blocksize": 0})

    stack.send(b'\x03\x22\x01\x01\xAA\xAA\xAA\xAA')

    while stack.transmitting():
        stack.process()
        time.sleep(stack.sleep_time())


    while  True:
        stack.process()
        if stack.available():
            message = stack.recv()
            message = message.ljust(62, b'\0')
            padded = bytearray(b'\x00')
            padded.extend(message)
            try:
                decoded = db.decode_message(stack.address.rxid, padded)
                print(json.dumps(decoded))
            except Exception as e:
                #pass
                eprint(message.hex()+": "+repr(e))
                #logging.error(traceback.format_exc())
        time.sleep(stack.sleep_time())

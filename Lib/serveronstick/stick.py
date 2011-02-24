"""
module for actually talking to the Server on Stick
"""

# Copyright (c) 2011, Yubico AB
# All rights reserved.

__all__ = [
    # constants
    # functions
    # classes
    'Stick'
]

import serial
import sys
import util

class SoS_Stick():
    """
    The current SoS is a USB device using serial communication.

    This class exposes the basic functions read, write and flush (input).
    """
    def __init__(self, device, timeout=1, debug=False):
        """
        Open SoS device.
        """
        self.debug = debug
        self.device = device
        self.num_read_bytes = 0
        self.num_write_bytes = 0
        self.ser = serial.Serial(device, 115200, timeout = timeout)
        if self.debug:
            sys.stderr.write("%s: OPEN %s\n" %(
                    self.__class__.__name__,
                    self.ser
                    ))
        return None

    def write(self, data):
        """
        Write data to SoS device.
        """
        self.num_write_bytes += len(data)
        if self.debug:
            sys.stderr.write("%s: WRITE %i:\n%s\n" %(
                    self.__class__.__name__,
                    len(data),
                    util.hexdump(data)
                    ))
        return self.ser.write(data)

    def read(self, num_bytes):
        """
        Read a number of bytes from SoS device.
        """
        if num_bytes < 1:
            return 0
        if self.debug:
            sys.stderr.write("%s: READING %i\n" %(
                    self.__class__.__name__,
                    num_bytes
                    ))
        res = self.ser.read(num_bytes)
        if self.debug:
            sys.stderr.write("%s: READ %i:\n%s\n" %(
                    self.__class__.__name__,
                    len(res),
                    util.hexdump(res)
                    ))
        self.num_read_bytes += len(res)
        return res

    def flush(self):
        """
        Flush input buffers.
        """
        if self.debug:
            sys.stderr.write("%s: FLUSH INPUT\n" %(
                    self.__class__.__name__
                    ))
        self.ser.flushInput()

    def __repr__(self):
        return '<%s instance at %s: %s - r:%i w:%i>' % (
            self.__class__.__name__,
            hex(id(self)),
            self.device,
            self.num_read_bytes,
            self.num_write_bytes
            )

    def __del__(self):
        """
        Close device when SoS instance is destroyed.
        """
        if self.debug:
            sys.stderr.write("%s: CLOSE %s\n" %(
                    self.__class__.__name__,
                    self.ser
                    ))
        self.ser.close()

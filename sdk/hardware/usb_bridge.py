from __future__ import annotations

import glob
import os
import time
from typing import Dict, Optional

from sdk.hardware.protocol import decode_message, encode_message


class DeviceNotConnected(RuntimeError):
    pass


class USBTimeoutError(TimeoutError):
    pass


def autodetect_serial_port() -> Optional[str]:
    patterns = ["/dev/ttyUSB*", "/dev/tty.usbserial-*", "/dev/ttyACM*", "COM*"]
    for pattern in patterns:
        matches = glob.glob(pattern)
        if matches:
            return sorted(matches)[0]
    return None


class USBSerialBridge:
    def __init__(self, port: Optional[str] = None, baud: int = 115200, timeout_seconds: float = 1.0):
        self.port = port or autodetect_serial_port()
        self.baud = baud
        self.timeout_seconds = timeout_seconds
        self._serial = None

    def connect(self) -> None:
        if not self.port:
            raise DeviceNotConnected("No serial port configured or auto-detected")
        try:
            import serial
        except ModuleNotFoundError as exc:
            raise DeviceNotConnected("pyserial is required for USB transport") from exc

        self._serial = serial.Serial(self.port, self.baud, timeout=self.timeout_seconds)

    def ensure_connected(self) -> None:
        if self._serial is None:
            self.connect()

    def send_json(self, message: Dict[str, object]) -> None:
        self.ensure_connected()
        self._serial.write(encode_message(message))
        self._serial.flush()

    def read_json(self, timeout_seconds: Optional[float] = None) -> Dict[str, object]:
        self.ensure_connected()
        deadline = time.time() + (timeout_seconds or self.timeout_seconds)
        while time.time() < deadline:
            line = self._serial.readline()
            if line:
                return decode_message(line)
        raise USBTimeoutError("Timed out waiting for device response")

    def close(self) -> None:
        if self._serial is not None:
            self._serial.close()
            self._serial = None

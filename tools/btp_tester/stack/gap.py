import logging
from asyncio import Event
from collections import namedtuple
from threading import Timer

from stack.property import Property, timeout_cb

LeAdv = namedtuple('LeAdv', 'addr_type addr rssi flags eir')


class Connection:
    def __init__(self, addr, addr_type):
        self.addr_type = addr
        self.addr = addr_type


class Gap:
    def __init__(self):
        self.name = None
        self.name_short = None

        self.connections = Property({})
        self.current_settings = Property({
            "Powered": False,
            "Connectable": False,
            "Fast Connectable": False,
            "Discoverable": False,
            "Bondable": False,
            "Link Level Security": False,  # Link Level Security (Sec. mode 3)
            "SSP": False,  # Secure Simple Pairing
            "BREDR": False,  # Basic Rate/Enhanced Data Rate
            "HS": False,  # High Speed
            "LE": False,  # Low Energy
            "Advertising": False,
            "SC": False,  # Secure Connections
            "Debug Keys": False,
            "Privacy": False,
            "Controller Configuration": False,
            "Static Address": False,
        })
        self.iut_bd_addr = Property({
            "address": None,
            "type": None,
        })
        self.discoverying = Property(False)
        self.found_devices = Property([])  # List of found devices

        self.passkey = Property(None)

    def connected(self, addr, addr_type):
        try:
            addr = addr.decode()
        except AttributeError:
            pass
        self.connections.data[addr] = Connection(addr, addr_type)

    def disconnected(self, addr, addr_type):
        try:
            addr = addr.decode()
        except AttributeError:
            pass
        self.connections.data.pop(addr)

    def is_connected(self, addr=None, addr_type=None):
        if not addr:
            return len(self.connections.data) > 0

        try:
            addr = addr.decode()
        except AttributeError:
            pass
        conn = self.connections.data.get(addr, None)
        return conn is not None

    def wait_for_connection(self, timeout, addr=None, addr_type=None):
        if self.is_connected(addr, addr_type):
            return True

        flag = Event()
        flag.set()

        t = Timer(timeout, timeout_cb, [flag])
        t.start()

        while flag.is_set():
            if self.is_connected(addr, addr_type):
                t.cancel()
                return True

        return False

    def wait_for_disconnection(self, timeout, addr=None, addr_type=None):
        if not self.is_connected(addr, addr_type):
            return True

        flag = Event()
        flag.set()

        t = Timer(timeout, timeout_cb, [flag])
        t.start()

        while flag.is_set():
            if not self.is_connected(addr, addr_type):
                t.cancel()
                return True

        return False

    def current_settings_set(self, key):
        if key in self.current_settings.data:
            self.current_settings.data[key] = True
        else:
            logging.error("%s %s not in current_settings",
                          self.current_settings_set.__name__, key)

    def current_settings_clear(self, key):
        if key in self.current_settings.data:
            self.current_settings.data[key] = False
        else:
            logging.error("%s %s not in current_settings",
                          self.current_settings_clear.__name__, key)

    def current_settings_get(self, key):
        if key in self.current_settings.data:
            return self.current_settings.data[key]
        else:
            logging.error("%s %s not in current_settings",
                          self.current_settings_get.__name__, key)
            return False

    def iut_addr_get_str(self):
        return self.iut_bd_addr.data["address"].decode()

    def iut_addr_get_bytes(self):
        return self.iut_bd_addr.data["address"]

    def iut_addr_get_type(self):
        return int(self.iut_bd_addr.data["type"])

    def iut_addr_set(self, addr, addr_type):
        self.iut_bd_addr.data["address"] = addr
        self.iut_bd_addr.data["type"] = addr_type

    def iut_addr_is_random(self):
        # FIXME: Do not use hard-coded 0x01 <-> le_random
        return True if self.iut_bd_addr.data["type"] == 0x01 else False

    def iut_has_privacy(self):
        return self.current_settings_get("Privacy")

    def reset_discovery(self):
        self.discoverying.data = True
        self.found_devices.data = []

    def get_passkey(self, timeout=5):
        if self.passkey.data is None:
            flag = Event()
            flag.set()

            t = Timer(timeout, timeout_cb, [flag])
            t.start()

            while flag.is_set():
                if self.passkey.data:
                    t.cancel()
                    break

        return self.passkey.data

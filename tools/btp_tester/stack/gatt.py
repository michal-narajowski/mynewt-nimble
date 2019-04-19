from asyncio import Event


class Gatt:
    def __init__(self):
        self.verify_values = []
        self.svcs = []
        self.chrs = []
        self.gatt_db = {}

    # These definitions are for PTS compatibility

    def add_verify_values(self, val):
        self.verify_values.append(val)

    def clear_verify_values(self):
        self.verify_values.clear()

    def add_svcs(self, val):
        self.svcs.append(val)

    def clear_svcs(self):
        self.svcs.clear()

    def add_chrs(self, val):
        self.chrs.append(val)

    def clear_chrs(self):
        self.chrs.clear()

    # End

    def add_attribute(self, attr_type, values):
        handle = values[0]
        self.gatt_db[handle] = (attr_type, values)

    def clear_db(self):
        self.gatt_db.clear()

    def print_db(self):
        for hdl, attr in sorted(self.gatt_db.items()):
            (attr_type, value) = attr
            print("{} {} {!r}".format(hdl, attr_type, value))

    def find_characteristic_end(self, hdl):
        attr = self.gatt_db.get(hdl)
        (attr_type, value) = attr
        if attr_type != "characteristic":
            raise Exception("Not a characteristic handle")

        handles = list(sorted(self.gatt_db.keys()))
        for next_hdl in handles:
            # Find next attribute handle
            if next_hdl <= hdl:
                continue

            # if the next handle is equal to the previous characteristic
            # definition + 2, then it means there are no descriptors there
            if next_hdl == (hdl + 2):
                return None

            attr = self.gatt_db.get(next_hdl)
            (attr_type, value) = attr

            # find the next attribute that is not a descriptor,
            # this will be the end of the characteristic
            if attr_type == "descriptor":
                continue

            # Return handle of the next attribue - 1, which is the end
            # of the previous characteristic
            return next_hdl - 1

        # If there are no more characteristics then return 0xffff
        return 0xffff

class GattAttribute:
    def __init__(self, handle, perm, uuid, att_rsp):
        self.handle = handle
        self.perm = perm
        self.uuid = uuid
        self.att_read_rsp = att_rsp

    def __repr__(self):
        return "{}({} {} {} {})".format(self.__class__.__name__,
                                        self.handle, self.perm,
                                        self.uuid, self.att_read_rsp)


class GattService(GattAttribute):
    pass


class GattPrimary(GattService):
    pass


class GattSecondary(GattService):
    pass


class GattServiceIncluded(GattAttribute):
    def __init__(self, handle, perm, uuid, att_rsp, incl_svc_hdl, end_grp_hdl):
        GattAttribute.__init__(self, handle, perm, uuid, att_rsp)
        self.incl_svc_hdl = incl_svc_hdl
        self.end_grp_hdl = end_grp_hdl

    def __repr__(self):
        return "{}({} {})".format(super(GattServiceIncluded, self).__repr__(),
                                  self.incl_svc_hdl,
                                  self.end_grp_hdl)


class GattCharacteristic(GattAttribute):
    def __init__(self, handle, perm, uuid, att_rsp, prop, value_handle):
        GattAttribute.__init__(self, handle, perm, uuid, att_rsp)
        self.prop = prop
        self.value_handle = value_handle

    def __repr__(self):
        return "{}({} {})".format(super(GattCharacteristic, self).__repr__(),
                                  self.prop, self.value_handle)

class GattCharacteristicDescriptor(GattAttribute):
    def __init__(self, handle, perm, uuid, att_rsp, value):
        GattAttribute.__init__(self, handle, perm, uuid, att_rsp)
        self.value = value
        self.has_changed = Event()

    def __repr__(self):
        return "{}({})".format(super(GattCharacteristicDescriptor,
                                     self).__repr__(),
                               self.value)


class GattDB:
    def __init__(self):
        self.db = dict()

    def attr_add(self, handle, attr):
        self.db[handle] = attr

    def attr_lookup_handle(self, handle):
        if handle in self.db:
            return self.db[handle]
        else:
            return None

    def print_db(self):
        for hdl, attr in sorted(self.db.items()):
            print("{} {!r}".format(hdl, attr))

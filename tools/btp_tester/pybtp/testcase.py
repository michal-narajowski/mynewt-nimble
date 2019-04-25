import binascii
import time
import unittest

from pybtp import btp
from pybtp.types import IOCap, AdType, UUID, PTS_DB, Prop, Perm
from stack.gatt import GattDB, GattCharacteristic


def preconditions(iutctl):
    btp.core_reg_svc_gap(iutctl)
    btp.core_reg_svc_gatt(iutctl)
    iutctl.stack.gap_init()
    iutctl.stack.gatt_init()
    btp.gap_read_ctrl_info(iutctl)


class AdData:
    ad_uuid16 = (AdType.uuid16_some, 'abcd')


def connection_procedure(central, peripheral):
    btp.gap_set_conn(peripheral)
    btp.gap_set_gendiscov(peripheral)
    btp.gap_adv_ind_on(peripheral, ad=[AdData.ad_uuid16])

    btp.gap_conn(central,
                 peripheral.stack.gap.iut_addr_get())

    btp.gap_wait_for_connection(peripheral)
    btp.gap_wait_for_connection(central,
                                addr=peripheral.stack.gap.iut_addr_get())


def disconnection_procedure(central, peripheral):
    btp.gap_disconn(central,
                    peripheral.stack.gap.iut_addr_get())

    btp.gap_wait_for_disconnection(peripheral)
    btp.gap_wait_for_disconnection(central,
                                   addr=peripheral.stack.gap.iut_addr_get())


class BTPTestCase(unittest.TestCase):
    def __init__(self, testname, iut, lt):
        super(__class__, self).__init__(testname)

        if iut is None:
            raise Exception("IUT is None")

        if lt is None:
            raise Exception("LT is None")

        self.iut = iut
        self.lt = lt

    @classmethod
    def init_testcases(cls, iut, lt):
        testcases = []
        ldr = unittest.TestLoader()
        for testname in ldr.getTestCaseNames(cls):
            testcases.append(cls(testname, iut, lt))
        return testcases

    def setUp(self):
        self.iut.start()
        self.iut.wait_iut_ready_event()
        self.lt.start()
        self.lt.wait_iut_ready_event()

    def tearDown(self):
        self.iut.stop()
        self.lt.stop()


class BTPTestCaseLT2(unittest.TestCase):
    def __init__(self, testname, iut, lt1, lt2):
        super(__class__, self).__init__(testname)

        if iut is None:
            raise Exception("IUT is None")

        if lt1 is None:
            raise Exception("LT1 is None")

        if lt2 is None:
            raise Exception("LT2 is None")

        self.iut = iut
        self.lt1 = lt1
        self.lt2 = lt2

    @classmethod
    def init_testcases(cls, iut, lt1, lt2):
        testcases = []
        ldr = unittest.TestLoader()
        for testname in ldr.getTestCaseNames(cls):
            testcases.append(cls(testname, iut, lt1, lt2))
        return testcases

    def setUp(self):
        self.iut.start()
        self.iut.wait_iut_ready_event()
        self.lt1.start()
        self.lt1.wait_iut_ready_event()
        self.lt2.start()
        self.lt2.wait_iut_ready_event()

    def tearDown(self):
        self.iut.stop()
        self.lt1.stop()
        self.lt2.stop()


class GAPTestCase(BTPTestCase):
    def __init__(self, testname, iut, lt):
        super(__class__, self).__init__(testname, iut, lt)

    def setUp(self):
        super(__class__, self).setUp()
        preconditions(self.iut)
        preconditions(self.lt)

    def tearDown(self):
        super(__class__, self).tearDown()

    def test_scan(self):
        btp.gap_set_conn(self.lt)
        btp.gap_set_gendiscov(self.lt)
        btp.gap_adv_ind_on(self.lt, None, None)

        btp.gap_start_discov(self.iut)
        time.sleep(5)
        btp.gap_stop_discov(self.iut)
        found = btp.check_discov_results(self.iut,
                                         self.lt.stack.gap.iut_addr_get())
        self.assertTrue(found)

    def test_scan_rpa(self):
        btp.gap_set_conn(self.lt)
        btp.gap_set_gendiscov(self.lt)
        btp.gap_adv_ind_on(self.lt,
                           ad=[(AdType.name_full,
                                self.lt.stack.gap.name.encode())])

        btp.gap_start_discov(self.iut)
        time.sleep(5)
        btp.gap_stop_discov(self.iut)
        found = btp.check_discov_results_by_name(self.iut,
                                                 self.lt.stack.gap.name,
                                                 self.lt.stack.gap.name_short)
        self.assertIsNotNone(found)

    def test_advertising(self):
        connection_procedure(central=self.lt, peripheral=self.iut)
        self.assertTrue(self.iut.stack.gap.is_connected())
        self.assertTrue(self.lt.stack.gap.is_connected())

        disconnection_procedure(central=self.lt, peripheral=self.iut)
        self.assertFalse(self.iut.stack.gap.is_connected())
        self.assertFalse(self.lt.stack.gap.is_connected())

    def test_connection(self):
        connection_procedure(central=self.iut, peripheral=self.lt)
        self.assertTrue(self.lt.stack.gap.is_connected())
        self.assertTrue(self.iut.stack.gap.is_connected())

        disconnection_procedure(central=self.iut, peripheral=self.lt)
        self.assertFalse(self.lt.stack.gap.is_connected())
        self.assertFalse(self.iut.stack.gap.is_connected())

    def test_connection_rpa(self):
        btp.gap_set_conn(self.lt)
        btp.gap_set_gendiscov(self.lt)
        btp.gap_adv_ind_on(self.lt,
                           ad=[(AdType.name_full,
                                self.lt.stack.gap.name.encode()),
                               AdData.ad_uuid16])

        btp.gap_start_discov(self.iut)
        time.sleep(5)
        btp.gap_stop_discov(self.iut)
        found = btp.check_discov_results_by_name(self.iut,
                                                 self.lt.stack.gap.name,
                                                 self.lt.stack.gap.name_short)
        self.assertIsNotNone(found)

        btp.gap_conn(self.iut,
                     found.addr)

        btp.gap_wait_for_connection(self.iut)
        btp.gap_wait_for_connection(self.lt)

        self.assertTrue(self.iut.stack.gap.is_connected())
        self.assertTrue(self.lt.stack.gap.is_connected())

        btp.gap_disconn(self.iut,
                        found.addr)

        btp.gap_wait_for_disconnection(self.lt)
        btp.gap_wait_for_disconnection(self.iut)

        self.assertFalse(self.lt.stack.gap.is_connected())
        self.assertFalse(self.iut.stack.gap.is_connected())

    def test_pairing_jw(self):
        btp.gap_set_io_cap(self.iut, IOCap.display_only)
        btp.gap_set_conn(self.lt)
        btp.gap_set_gendiscov(self.lt)
        btp.gap_adv_ind_on(self.lt,
                           ad=[(AdType.name_full,
                                self.lt.stack.gap.name.encode()),
                               AdData.ad_uuid16])

        btp.gap_start_discov(self.iut)
        time.sleep(5)
        btp.gap_stop_discov(self.iut)
        found = btp.check_discov_results_by_name(self.iut,
                                                 self.lt.stack.gap.name,
                                                 self.lt.stack.gap.name_short)
        self.assertIsNotNone(found)

        btp.gap_conn(self.iut,
                     found.addr)

        btp.gap_wait_for_connection(self.iut)
        btp.gap_wait_for_connection(self.lt)

        self.assertTrue(self.iut.stack.gap.is_connected())
        self.assertTrue(self.lt.stack.gap.is_connected())

        btp.gap_pair(self.iut,
                     found.addr)

        time.sleep(10)

        btp.gap_disconn(self.iut,
                        found.addr)

        btp.gap_wait_for_disconnection(self.lt)
        btp.gap_wait_for_disconnection(self.iut)

        self.assertFalse(self.lt.stack.gap.is_connected())
        self.assertFalse(self.iut.stack.gap.is_connected())

    def test_pairing_numcmp(self):
        btp.gap_set_io_cap(self.iut, IOCap.display_yesno)
        btp.gap_set_io_cap(self.lt, IOCap.display_yesno)

        connection_procedure(central=self.iut, peripheral=self.lt)
        self.assertTrue(self.lt.stack.gap.is_connected())
        self.assertTrue(self.iut.stack.gap.is_connected())

        btp.gap_pair(self.iut,
                     self.lt.stack.gap.iut_addr_get())

        pk_iut = self.iut.stack.gap.get_passkey()
        self.assertIsNotNone(pk_iut)
        pk_lt = self.lt.stack.gap.get_passkey()
        self.assertIsNotNone(pk_lt)
        self.assertEqual(pk_iut, pk_lt)

        btp.gap_passkey_confirm(self.iut,
                                self.lt.stack.gap.iut_addr_get(), 1)

        btp.gap_passkey_confirm(self.lt,
                                self.iut.stack.gap.iut_addr_get(), 1)

        disconnection_procedure(central=self.iut, peripheral=self.lt)
        self.assertFalse(self.lt.stack.gap.is_connected())
        self.assertFalse(self.iut.stack.gap.is_connected())

    def test_pairing_input(self):
        btp.gap_set_io_cap(self.iut, IOCap.keyboard_only)
        btp.gap_set_io_cap(self.lt, IOCap.display_only)

        connection_procedure(central=self.iut, peripheral=self.lt)
        self.assertTrue(self.lt.stack.gap.is_connected())
        self.assertTrue(self.iut.stack.gap.is_connected())

        btp.gap_pair(self.iut,
                     self.lt.stack.gap.iut_addr_get())

        pk_lt = self.lt.stack.gap.get_passkey()
        self.assertIsNotNone(pk_lt)

        btp.gap_passkey_entry_req_ev(self.iut,
                                     self.lt.stack.gap.iut_addr_get())

        btp.gap_passkey_entry_rsp(self.iut,
                                  self.lt.stack.gap.iut_addr_get(),
                                  pk_lt)

        disconnection_procedure(central=self.iut, peripheral=self.lt)
        self.assertFalse(self.lt.stack.gap.is_connected())
        self.assertFalse(self.iut.stack.gap.is_connected())

    def test_gattc_discover_primary_svcs(self):
        connection_procedure(central=self.iut, peripheral=self.lt)
        self.assertTrue(self.lt.stack.gap.is_connected())
        self.assertTrue(self.iut.stack.gap.is_connected())

        btp.gattc_disc_prim_svcs(self.iut,
                                 self.lt.stack.gap.iut_addr_get())

        db = GattDB()
        server_db = GattDB()
        btp.gattc_disc_prim_svcs_rsp(self.iut, db)

        btp.gatt_server_fetch_db(self.lt,
                                 server_db,
                                 type_uuid=UUID.primary_svc)

        self.assertEqual(db, server_db)

        disconnection_procedure(central=self.iut, peripheral=self.lt)
        self.assertFalse(self.lt.stack.gap.is_connected())
        self.assertFalse(self.iut.stack.gap.is_connected())

    def test_gattc_discover_primary_uuid(self):
        connection_procedure(central=self.iut, peripheral=self.lt)
        self.assertTrue(self.lt.stack.gap.is_connected())
        self.assertTrue(self.iut.stack.gap.is_connected())

        btp.gattc_disc_prim_uuid(self.iut,
                                 self.lt.stack.gap.iut_addr_get(),
                                 UUID.gap_svc)

        db = GattDB()
        server_db = GattDB()
        btp.gattc_disc_prim_uuid_rsp(self.iut, db)

        btp.gatt_server_fetch_db(self.lt, server_db,
                                 type_uuid=UUID.primary_svc)

        self.assertTrue(server_db.contains(db))

        disconnection_procedure(central=self.iut, peripheral=self.lt)
        self.assertFalse(self.lt.stack.gap.is_connected())
        self.assertFalse(self.iut.stack.gap.is_connected())

    def test_gattc_find_incl_svcs(self):
        connection_procedure(central=self.iut, peripheral=self.lt)
        self.assertTrue(self.lt.stack.gap.is_connected())
        self.assertTrue(self.iut.stack.gap.is_connected())

        btp.gattc_disc_prim_svcs(self.iut,
                                 self.lt.stack.gap.iut_addr_get())

        db = GattDB()
        btp.gattc_disc_prim_svcs_rsp(self.iut, db)

        svcs = db.get_services()
        db.clear()

        for svc in svcs:
            start_hdl, end_hdl = svc.handle, svc.end_hdl

            btp.gattc_find_included(self.iut,
                                    self.lt.stack.gap.iut_addr_get(),
                                    start_hdl, end_hdl)

            btp.gattc_find_included_rsp(self.iut, db)

        server_db = GattDB()
        btp.gatt_server_fetch_db(self.lt, server_db,
                                 type_uuid=UUID.include_svc)

        db.print_db()
        server_db.print_db()
        self.assertEqual(server_db, db)

        disconnection_procedure(central=self.iut, peripheral=self.lt)
        self.assertFalse(self.lt.stack.gap.is_connected())
        self.assertFalse(self.iut.stack.gap.is_connected())

    def test_gattc_discover_all_chrcs(self):
        connection_procedure(central=self.iut, peripheral=self.lt)
        self.assertTrue(self.lt.stack.gap.is_connected())
        self.assertTrue(self.iut.stack.gap.is_connected())

        btp.gattc_disc_prim_svcs(self.iut,
                                 self.lt.stack.gap.iut_addr_get())

        db = GattDB()
        btp.gattc_disc_prim_svcs_rsp(self.iut, db)

        svcs = db.get_services()
        db.clear()

        for svc in svcs:
            start_hdl, end_hdl = svc.handle, svc.end_hdl

            btp.gattc_disc_all_chrc(self.iut,
                                    self.lt.stack.gap.iut_addr_get(),
                                    start_hdl, end_hdl)

            btp.gattc_disc_all_chrc_rsp(self.iut, db)

        server_db = GattDB()
        btp.gatt_server_fetch_db(self.lt, server_db,
                                 type_uuid=UUID.chrc)

        db.print_db()
        server_db.print_db()
        self.assertEqual(server_db, db)

        disconnection_procedure(central=self.iut, peripheral=self.lt)
        self.assertFalse(self.lt.stack.gap.is_connected())
        self.assertFalse(self.iut.stack.gap.is_connected())

    def test_gattc_discover_chrc_uuid(self):
        connection_procedure(central=self.iut, peripheral=self.lt)
        self.assertTrue(self.lt.stack.gap.is_connected())
        self.assertTrue(self.iut.stack.gap.is_connected())

        btp.gattc_disc_chrc_uuid(self.iut,
                                 self.lt.stack.gap.iut_addr_get(),
                                 0x0001, 0xffff, UUID.device_name)

        db = GattDB()
        server_db = GattDB()
        btp.gattc_disc_chrc_uuid_rsp(self.iut, db)

        btp.gatt_server_fetch_db(self.lt, server_db,
                                 type_uuid=UUID.chrc)

        self.assertGreater(len(db), 0)
        self.assertTrue(server_db.contains(db))

        disconnection_procedure(central=self.iut, peripheral=self.lt)
        self.assertFalse(self.lt.stack.gap.is_connected())
        self.assertFalse(self.iut.stack.gap.is_connected())

    def test_gattc_discover_all_descs(self):
        connection_procedure(central=self.iut, peripheral=self.lt)
        self.assertTrue(self.lt.stack.gap.is_connected())
        self.assertTrue(self.iut.stack.gap.is_connected())

        btp.gattc_disc_prim_svcs(self.iut,
                                 self.lt.stack.gap.iut_addr_get())

        db = GattDB()
        btp.gattc_disc_prim_svcs_rsp(self.iut, db)

        svcs = db.get_services()

        for svc in svcs:
            start_hdl, end_hdl = svc.handle, svc.end_hdl

            btp.gattc_disc_all_chrc(self.iut,
                                    self.lt.stack.gap.iut_addr_get(),
                                    start_hdl, end_hdl)

            btp.gattc_disc_all_chrc_rsp(self.iut, db)

        attributes = db.get_attributes()
        for attr in attributes:
            if not isinstance(attr, GattCharacteristic):
                continue

            end_hdl = db.find_characteristic_end(attr.handle)
            if not end_hdl:
                continue

            btp.gattc_disc_all_desc(self.iut,
                                    self.lt.stack.gap.iut_addr_get(),
                                    attr.value_handle + 1, end_hdl)

            btp.gattc_disc_all_desc_rsp(self.iut, db)

        server_db = GattDB()
        btp.gatt_server_fetch_db(self.lt, server_db)

        db.print_db()
        server_db.print_db()

        db_desc = db.get_descriptors()
        server_db_desc = server_db.get_descriptors()
        self.assertEqual(server_db_desc, db_desc)

        disconnection_procedure(central=self.iut, peripheral=self.lt)
        self.assertFalse(self.lt.stack.gap.is_connected())
        self.assertFalse(self.iut.stack.gap.is_connected())

    def test_gattc_read(self):
        btp.gatts_add_svc(self.lt, 0, PTS_DB.SVC)
        char_hdl = btp.gatts_add_char(self.lt, 0, Prop.read | Prop.write,
                                      Perm.read | Perm.write,
                                      PTS_DB.CHR_READ_WRITE)

        value = "123456"
        btp.gatts_set_val(self.lt, char_hdl, value)

        btp.gatts_start_server(self.lt)

        connection_procedure(central=self.iut, peripheral=self.lt)
        self.assertTrue(self.lt.stack.gap.is_connected())
        self.assertTrue(self.iut.stack.gap.is_connected())

        verify_values = self.iut.stack.gatt.verify_values

        btp.gattc_read(self.iut,
                       self.lt.stack.gap.iut_addr_get(),
                       char_hdl + 1)

        btp.gattc_read_rsp(self.iut, store_rsp=True, store_val=True)

        self.assertEqual(verify_values[0], "No error")
        self.assertEqual(verify_values[1], value)

        disconnection_procedure(central=self.iut, peripheral=self.lt)
        self.assertFalse(self.lt.stack.gap.is_connected())
        self.assertFalse(self.iut.stack.gap.is_connected())

    def test_gattc_read_long(self):
        btp.gatts_add_svc(self.lt, 0, PTS_DB.SVC)
        char_hdl = btp.gatts_add_char(self.lt, 0, Prop.read | Prop.write,
                                      Perm.read | Perm.write,
                                      PTS_DB.CHR_READ_WRITE)

        value = "FF" * 280
        btp.gatts_set_val(self.lt, char_hdl, value)

        btp.gatts_start_server(self.lt)

        connection_procedure(central=self.iut, peripheral=self.lt)
        self.assertTrue(self.lt.stack.gap.is_connected())
        self.assertTrue(self.iut.stack.gap.is_connected())

        verify_values = self.iut.stack.gatt.verify_values

        btp.gattc_read_long(self.iut,
                            self.lt.stack.gap.iut_addr_get(),
                            char_hdl + 1, 0)

        btp.gattc_read_long_rsp(self.iut, store_rsp=True, store_val=True)

        self.assertEqual(verify_values[0], "No error")
        self.assertEqual(verify_values[1], value)

        disconnection_procedure(central=self.iut, peripheral=self.lt)
        self.assertFalse(self.lt.stack.gap.is_connected())
        self.assertFalse(self.iut.stack.gap.is_connected())

    def test_gattc_write(self):
        btp.gatts_add_svc(self.lt, 0, PTS_DB.SVC)
        char_hdl = btp.gatts_add_char(self.lt, 0, Prop.read | Prop.write,
                                      Perm.read | Perm.write,
                                      PTS_DB.CHR_READ_WRITE)

        btp.gatts_set_val(self.lt, char_hdl, "123456")

        btp.gatts_start_server(self.lt)

        connection_procedure(central=self.iut, peripheral=self.lt)
        self.assertTrue(self.lt.stack.gap.is_connected())
        self.assertTrue(self.iut.stack.gap.is_connected())

        verify_values = self.iut.stack.gatt.verify_values

        btp.gattc_write(self.iut,
                        self.lt.stack.gap.iut_addr_get(),
                        char_hdl + 1,
                        "FFFFFF")

        btp.gattc_write_rsp(self.iut, store_rsp=True)

        self.assertEqual(verify_values[0], "No error")

        hdl, data = btp.gatts_attr_value_changed_ev(self.lt)
        val = binascii.hexlify(data[0]).decode().upper()

        self.assertEqual(val, "FFFFFF")

        disconnection_procedure(central=self.iut, peripheral=self.lt)
        self.assertFalse(self.lt.stack.gap.is_connected())
        self.assertFalse(self.iut.stack.gap.is_connected())

    def test_gattc_write_long(self):
        btp.gatts_add_svc(self.lt, 0, PTS_DB.SVC)
        char_hdl = btp.gatts_add_char(self.lt, 0, Prop.read | Prop.write,
                                      Perm.read | Perm.write,
                                      PTS_DB.CHR_READ_WRITE)

        init_value = "00" * 280
        btp.gatts_set_val(self.lt, char_hdl, init_value)

        btp.gatts_start_server(self.lt)

        connection_procedure(central=self.iut, peripheral=self.lt)
        self.assertTrue(self.lt.stack.gap.is_connected())
        self.assertTrue(self.iut.stack.gap.is_connected())

        value = "FF" * 280
        btp.gattc_write_long(self.iut,
                             self.lt.stack.gap.iut_addr_get(),
                             char_hdl + 1,
                             0, value)

        btp.gattc_write_long_rsp(self.iut, store_rsp=True)

        verify_values = self.iut.stack.gatt.verify_values
        self.assertEqual(verify_values[0], "No error")

        hdl, data = btp.gatts_attr_value_changed_ev(self.lt)
        recv_val = binascii.hexlify(data[0]).decode().upper()

        self.assertEqual(recv_val, value)

        disconnection_procedure(central=self.iut, peripheral=self.lt)
        self.assertFalse(self.lt.stack.gap.is_connected())
        self.assertFalse(self.iut.stack.gap.is_connected())

    def test_gattc_notification(self):
        btp.gatts_add_svc(self.lt, 0, PTS_DB.SVC)
        char_hdl = btp.gatts_add_char(self.lt, 0,
                                      Prop.read | Prop.write |
                                      Prop.nofity | Prop.indicate,
                                      Perm.read | Perm.write,
                                      PTS_DB.CHR_READ_WRITE)

        btp.gatts_start_server(self.lt)

        connection_procedure(central=self.iut, peripheral=self.lt)
        self.assertTrue(self.lt.stack.gap.is_connected())
        self.assertTrue(self.iut.stack.gap.is_connected())

        btp.gattc_cfg_notify(self.iut,
                             self.lt.stack.gap.iut_addr_get(),
                             1, char_hdl + 2)

        time.sleep(1)

        btp.gatts_set_val(self.lt,
                          char_hdl,
                          "0001")

        btp.gattc_notification_ev(self.iut,
                                  self.lt.stack.gap.iut_addr_get(),
                                  0x01,
                                  char_hdl + 1,
                                  "0001")

        disconnection_procedure(central=self.iut, peripheral=self.lt)
        self.assertFalse(self.lt.stack.gap.is_connected())
        self.assertFalse(self.iut.stack.gap.is_connected())

    def test_gattc_indication(self):
        btp.gatts_add_svc(self.lt, 0, PTS_DB.SVC)
        char_hdl = btp.gatts_add_char(self.lt, 0,
                                      Prop.read | Prop.write |
                                      Prop.nofity | Prop.indicate,
                                      Perm.read | Perm.write,
                                      PTS_DB.CHR_READ_WRITE)

        btp.gatts_start_server(self.lt)

        connection_procedure(central=self.iut, peripheral=self.lt)
        self.assertTrue(self.lt.stack.gap.is_connected())
        self.assertTrue(self.iut.stack.gap.is_connected())

        btp.gattc_cfg_indicate(self.iut,
                               self.lt.stack.gap.iut_addr_get(),
                               1, char_hdl + 2)

        time.sleep(1)

        btp.gatts_set_val(self.lt,
                          char_hdl,
                          "0001")

        btp.gattc_notification_ev(self.iut,
                                  self.lt.stack.gap.iut_addr_get(),
                                  0x02,
                                  char_hdl + 1,
                                  "0001")

        disconnection_procedure(central=self.iut, peripheral=self.lt)
        self.assertFalse(self.lt.stack.gap.is_connected())
        self.assertFalse(self.iut.stack.gap.is_connected())


class GAPTestCaseLT2(BTPTestCaseLT2):
    def __init__(self, testname, iut, lt1, lt2):
        super(__class__, self).__init__(testname, iut, lt1, lt2)

    def setUp(self):
        super(__class__, self).setUp()
        preconditions(self.iut)
        preconditions(self.lt1)
        preconditions(self.lt2)

    def tearDown(self):
        super(__class__, self).tearDown()

    def test_advertising(self):
        connection_procedure(central=self.lt1, peripheral=self.iut)
        self.assertTrue(self.iut.stack.gap.is_connected())
        self.assertTrue(self.lt1.stack.gap.is_connected())
        connection_procedure(central=self.lt2, peripheral=self.iut)
        self.assertTrue(self.iut.stack.gap.is_connected())
        self.assertTrue(self.lt2.stack.gap.is_connected())

        disconnection_procedure(central=self.lt1, peripheral=self.iut)
        self.assertFalse(self.iut.stack.gap.is_connected())
        self.assertFalse(self.lt1.stack.gap.is_connected())
        disconnection_procedure(central=self.lt2, peripheral=self.iut)
        self.assertFalse(self.iut.stack.gap.is_connected())
        self.assertFalse(self.lt2.stack.gap.is_connected())

    def test_connection(self):
        connection_procedure(central=self.iut, peripheral=self.lt1)
        self.assertTrue(self.lt1.stack.gap.is_connected())
        self.assertTrue(self.iut.stack.gap.is_connected())
        connection_procedure(central=self.iut, peripheral=self.lt2)
        self.assertTrue(self.lt2.stack.gap.is_connected())
        self.assertTrue(self.iut.stack.gap.is_connected())

        disconnection_procedure(central=self.iut, peripheral=self.lt1)
        self.assertFalse(self.lt1.stack.gap.is_connected())
        disconnection_procedure(central=self.iut, peripheral=self.lt2)
        self.assertFalse(self.lt2.stack.gap.is_connected())
        self.assertFalse(self.iut.stack.gap.is_connected())

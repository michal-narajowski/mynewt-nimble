import time
import unittest

from pybtp import btp
from pybtp.types import IOCap, AdType, UUID


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

    def test_gattc_discovery(self):
        btp.gatts_start_server(self.lt)
        connection_procedure(central=self.iut, peripheral=self.lt)
        self.assertTrue(self.lt.stack.gap.is_connected())
        self.assertTrue(self.iut.stack.gap.is_connected())

        btp.gattc_disc_full(self.iut,
                            self.lt.stack.gap.iut_addr_get())

        self.iut.stack.gatt.print_db()

        self.assertTrue(len(self.iut.stack.gatt.gatt_db) > 0)

        disconnection_procedure(central=self.iut, peripheral=self.lt)
        self.assertFalse(self.lt.stack.gap.is_connected())
        self.assertFalse(self.iut.stack.gap.is_connected())

    def test_gattc_discover_primary_svcs(self):
        connection_procedure(central=self.iut, peripheral=self.lt)
        self.assertTrue(self.lt.stack.gap.is_connected())
        self.assertTrue(self.iut.stack.gap.is_connected())

        btp.gattc_disc_prim_svcs(self.iut,
                                 self.lt.stack.gap.iut_addr_get())

        btp.gattc_disc_prim_svcs_rsp(self.iut)

        self.iut.stack.gatt.print_db()

        self.assertTrue(len(self.iut.stack.gatt.gatt_db) > 0)

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

        btp.gattc_disc_prim_uuid_rsp(self.iut)

        self.iut.stack.gatt.print_db()

        self.assertTrue(len(self.iut.stack.gatt.gatt_db) > 0)

        disconnection_procedure(central=self.iut, peripheral=self.lt)
        self.assertFalse(self.lt.stack.gap.is_connected())
        self.assertFalse(self.iut.stack.gap.is_connected())

    def test_gattc_discover_all_chrcs(self):
        connection_procedure(central=self.iut, peripheral=self.lt)
        self.assertTrue(self.lt.stack.gap.is_connected())
        self.assertTrue(self.iut.stack.gap.is_connected())

        btp.gattc_disc_all_chrc(self.iut,
                                self.lt.stack.gap.iut_addr_get(),
                                0x0001, 0xffff)

        btp.gattc_disc_all_chrc_rsp(self.iut)

        self.iut.stack.gatt.print_db()

        self.assertTrue(len(self.iut.stack.gatt.gatt_db) > 0)

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

        btp.gattc_disc_chrc_uuid_rsp(self.iut)

        self.iut.stack.gatt.print_db()

        self.assertTrue(len(self.iut.stack.gatt.gatt_db) > 0)

        disconnection_procedure(central=self.iut, peripheral=self.lt)
        self.assertFalse(self.lt.stack.gap.is_connected())
        self.assertFalse(self.iut.stack.gap.is_connected())

    def test_gattc_discover_all_descs(self):
        connection_procedure(central=self.iut, peripheral=self.lt)
        self.assertTrue(self.lt.stack.gap.is_connected())
        self.assertTrue(self.iut.stack.gap.is_connected())

        btp.gattc_disc_all_desc(self.iut,
                                self.lt.stack.gap.iut_addr_get(),
                                0x0001, 0xffff)

        btp.gattc_disc_all_desc_rsp(self.iut)

        self.iut.stack.gatt.print_db()

        self.assertTrue(len(self.iut.stack.gatt.gatt_db) > 0)

        disconnection_procedure(central=self.iut, peripheral=self.lt)
        self.assertFalse(self.lt.stack.gap.is_connected())
        self.assertFalse(self.iut.stack.gap.is_connected())

    def test_gattc_read_write(self):
        value_handle = 37
        connection_procedure(central=self.iut, peripheral=self.lt)
        self.assertTrue(self.lt.stack.gap.is_connected())
        self.assertTrue(self.iut.stack.gap.is_connected())

        verify_values = self.iut.stack.gatt.verify_values

        btp.gattc_read(self.iut,
                       self.lt.stack.gap.iut_addr_get(),
                       value_handle)

        btp.gattc_read_rsp(self.iut, store_rsp=True, store_val=True)

        self.assertEqual(verify_values[0], "No error")
        self.assertEqual(verify_values[1], "00".encode())

        btp.gattc_write(self.iut,
                        self.lt.stack.gap.iut_addr_get(),
                        value_handle,
                        "01")

        btp.gattc_write_rsp(self.iut, store_rsp=True)

        self.assertEqual(verify_values[0], "No error")

        btp.gattc_read(self.iut,
                       self.lt.stack.gap.iut_addr_get(),
                       value_handle)

        btp.gattc_read_rsp(self.iut, store_rsp=True, store_val=True)

        self.assertEqual(verify_values[0], "No error")
        self.assertEqual(verify_values[1], "01".encode())

        disconnection_procedure(central=self.iut, peripheral=self.lt)
        self.assertFalse(self.lt.stack.gap.is_connected())
        self.assertFalse(self.iut.stack.gap.is_connected())

    def test_gattc_notification(self):
        value_id = 4
        cccd_handle = 38
        connection_procedure(central=self.iut, peripheral=self.lt)
        self.assertTrue(self.lt.stack.gap.is_connected())
        self.assertTrue(self.iut.stack.gap.is_connected())

        btp.gattc_cfg_notify(self.iut,
                             self.lt.stack.gap.iut_addr_get(),
                             1, cccd_handle)

        time.sleep(1)

        btp.gatts_set_val(self.lt,
                          value_id,
                          "0001")

        btp.gattc_notification_ev(self.iut,
                                  self.lt.stack.gap.iut_addr_get(),
                                  0x01)

        disconnection_procedure(central=self.iut, peripheral=self.lt)
        self.assertFalse(self.lt.stack.gap.is_connected())
        self.assertFalse(self.iut.stack.gap.is_connected())

    def test_gattc_indication(self):
        value_id = 4
        cccd_handle = 38
        connection_procedure(central=self.iut, peripheral=self.lt)
        self.assertTrue(self.lt.stack.gap.is_connected())
        self.assertTrue(self.iut.stack.gap.is_connected())

        btp.gattc_cfg_indicate(self.iut,
                               self.lt.stack.gap.iut_addr_get(),
                               1, cccd_handle)

        time.sleep(1)

        btp.gatts_set_val(self.lt,
                          value_id,
                          "0001")

        btp.gattc_notification_ev(self.iut,
                                  self.lt.stack.gap.iut_addr_get(),
                                  0x02)

        disconnection_procedure(central=self.iut, peripheral=self.lt)
        self.assertFalse(self.lt.stack.gap.is_connected())
        self.assertFalse(self.iut.stack.gap.is_connected())

    def test_gatts_get_attrs(self):
        btp.gatts_start_server(self.iut)

        db = btp.gatt_server_fetch_db(self.iut)
        db.print_db()


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

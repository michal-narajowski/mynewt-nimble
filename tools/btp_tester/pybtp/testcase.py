import time
import unittest

from pybtp import btp
from pybtp.types import IOCap, AdType


def preconditions(iutctl):
    btp.core_reg_svc_gap(iutctl)
    btp.core_reg_svc_gatt(iutctl)
    iutctl.stack.gap_init()
    iutctl.stack.gatt_init()
    btp.gap_read_ctrl_info(iutctl)


class AdData:
    ad_uuid16 = (AdType.uuid16_some, 'abcd')


def connection_procedure(peripheral, central):
    btp.gap_set_conn(peripheral)
    btp.gap_set_gendiscov(peripheral)
    btp.gap_adv_ind_on(peripheral, ad=[AdData.ad_uuid16])

    btp.gap_conn(central,
                 peripheral.stack.gap.iut_addr_get_str(),
                 peripheral.stack.gap.iut_addr_get_type())

    btp.gap_wait_for_connection(peripheral)
    btp.gap_wait_for_connection(central)


def disconnection_procedure(peripheral, central):
    btp.gap_disconn(central,
                    peripheral.stack.gap.iut_addr_get_str(),
                    peripheral.stack.gap.iut_addr_get_type())

    btp.gap_wait_for_disconnection(peripheral)
    btp.gap_wait_for_disconnection(central)


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
                                         self.lt.stack.gap.iut_addr_get_str(),
                                         self.lt.stack.gap.iut_addr_get_type())
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
        connection_procedure(peripheral=self.iut, central=self.lt)
        self.assertTrue(self.iut.stack.gap.is_connected())
        self.assertTrue(self.lt.stack.gap.is_connected())

        disconnection_procedure(peripheral=self.iut, central=self.lt)
        self.assertFalse(self.iut.stack.gap.is_connected())
        self.assertFalse(self.lt.stack.gap.is_connected())

    def test_connection(self):
        connection_procedure(peripheral=self.lt, central=self.iut)
        self.assertTrue(self.lt.stack.gap.is_connected())
        self.assertTrue(self.iut.stack.gap.is_connected())

        disconnection_procedure(peripheral=self.lt, central=self.iut)
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
                     found.addr.decode(),
                     found.addr_type)

        btp.gap_wait_for_connection(self.iut)
        btp.gap_wait_for_connection(self.lt)

        self.assertTrue(self.iut.stack.gap.is_connected())
        self.assertTrue(self.lt.stack.gap.is_connected())

        btp.gap_disconn(self.iut,
                        found.addr.decode(),
                        found.addr_type)

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
                     found.addr.decode(),
                     found.addr_type)

        btp.gap_wait_for_connection(self.iut)
        btp.gap_wait_for_connection(self.lt)

        self.assertTrue(self.iut.stack.gap.is_connected())
        self.assertTrue(self.lt.stack.gap.is_connected())

        btp.gap_pair(self.iut,
                     found.addr.decode(),
                     found.addr_type)

        time.sleep(10)

        btp.gap_disconn(self.iut,
                        found.addr.decode(),
                        found.addr_type)

        btp.gap_wait_for_disconnection(self.lt)
        btp.gap_wait_for_disconnection(self.iut)

        self.assertFalse(self.lt.stack.gap.is_connected())
        self.assertFalse(self.iut.stack.gap.is_connected())

    def test_pairing_numcmp(self):
        btp.gap_set_io_cap(self.iut, IOCap.display_yesno)
        btp.gap_set_io_cap(self.lt, IOCap.display_yesno)

        connection_procedure(peripheral=self.lt, central=self.iut)
        self.assertTrue(self.lt.stack.gap.is_connected())
        self.assertTrue(self.iut.stack.gap.is_connected())

        btp.gap_pair(self.iut,
                     self.lt.stack.gap.iut_addr_get_str(),
                     self.lt.stack.gap.iut_addr_get_type())

        pk_iut = self.iut.stack.gap.get_passkey()
        self.assertIsNotNone(pk_iut)
        pk_lt = self.lt.stack.gap.get_passkey()
        self.assertIsNotNone(pk_lt)
        self.assertEqual(pk_iut, pk_lt)

        btp.gap_passkey_confirm(self.iut,
                                self.lt.stack.gap.iut_addr_get_str(),
                                self.lt.stack.gap.iut_addr_get_type(), 1)

        btp.gap_passkey_confirm(self.lt,
                                self.iut.stack.gap.iut_addr_get_str(),
                                self.iut.stack.gap.iut_addr_get_type(), 1)

        disconnection_procedure(peripheral=self.lt, central=self.iut)
        self.assertFalse(self.lt.stack.gap.is_connected())
        self.assertFalse(self.iut.stack.gap.is_connected())

    def test_pairing_input(self):
        btp.gap_set_io_cap(self.iut, IOCap.keyboard_only)
        btp.gap_set_io_cap(self.lt, IOCap.display_only)

        connection_procedure(peripheral=self.lt, central=self.iut)
        self.assertTrue(self.lt.stack.gap.is_connected())
        self.assertTrue(self.iut.stack.gap.is_connected())

        btp.gap_pair(self.iut,
                     self.lt.stack.gap.iut_addr_get_str(),
                     self.lt.stack.gap.iut_addr_get_type())

        pk_lt = self.lt.stack.gap.get_passkey()
        self.assertIsNotNone(pk_lt)

        btp.gap_passkey_entry_req_ev(self.iut,
                                     self.lt.stack.gap.iut_addr_get_str(),
                                     self.lt.stack.gap.iut_addr_get_type())

        btp.gap_passkey_entry_rsp(self.iut,
                                  self.lt.stack.gap.iut_addr_get_str(),
                                  self.lt.stack.gap.iut_addr_get_type(),
                                  pk_lt)

        disconnection_procedure(peripheral=self.lt, central=self.iut)
        self.assertFalse(self.lt.stack.gap.is_connected())
        self.assertFalse(self.iut.stack.gap.is_connected())

    def test_gattc_discovery(self):
        btp.gatts_start_server(self.iut)
        connection_procedure(peripheral=self.lt, central=self.iut)
        self.assertTrue(self.lt.stack.gap.is_connected())
        self.assertTrue(self.iut.stack.gap.is_connected())

        btp.gattc_disc_full(self.iut,
                            self.lt.stack.gap.iut_addr_get_type(),
                            self.lt.stack.gap.iut_addr_get_str())

        self.iut.stack.gatt.print_db()

        self.assertTrue(len(self.iut.stack.gatt.gatt_db) > 0)

        disconnection_procedure(peripheral=self.lt, central=self.iut)
        self.assertFalse(self.lt.stack.gap.is_connected())
        self.assertFalse(self.iut.stack.gap.is_connected())

    def test_gattc_read_write(self):
        value_handle = 33
        btp.gatts_start_server(self.iut)
        connection_procedure(peripheral=self.lt, central=self.iut)
        self.assertTrue(self.lt.stack.gap.is_connected())
        self.assertTrue(self.iut.stack.gap.is_connected())

        verify_values = self.iut.stack.gatt.verify_values

        btp.gattc_read(self.iut,
                       self.lt.stack.gap.iut_addr_get_type(),
                       self.lt.stack.gap.iut_addr_get_str(),
                       value_handle)

        btp.gattc_read_rsp(self.iut, store_rsp=True, store_val=True)

        self.assertEqual(verify_values[0], "No error")
        self.assertEqual(verify_values[1], "00".encode())

        btp.gattc_write(self.iut,
                        self.lt.stack.gap.iut_addr_get_type(),
                        self.lt.stack.gap.iut_addr_get_str(),
                        value_handle,
                        "01")

        btp.gattc_write_rsp(self.iut, store_rsp=True)

        self.assertEqual(verify_values[0], "No error")

        btp.gattc_read(self.iut,
                       self.lt.stack.gap.iut_addr_get_type(),
                       self.lt.stack.gap.iut_addr_get_str(),
                       value_handle)

        btp.gattc_read_rsp(self.iut, store_rsp=True, store_val=True)

        self.assertEqual(verify_values[0], "No error")
        self.assertEqual(verify_values[1], "01".encode())

        disconnection_procedure(peripheral=self.lt, central=self.iut)
        self.assertFalse(self.lt.stack.gap.is_connected())
        self.assertFalse(self.iut.stack.gap.is_connected())

    def test_gattc_notification(self):
        value_id = 4
        cccd_handle = 34
        btp.gatts_start_server(self.iut)
        connection_procedure(peripheral=self.lt, central=self.iut)
        self.assertTrue(self.lt.stack.gap.is_connected())
        self.assertTrue(self.iut.stack.gap.is_connected())

        btp.gattc_cfg_notify(self.iut,
                             self.lt.stack.gap.iut_addr_get_type(),
                             self.lt.stack.gap.iut_addr_get_str(),
                             1, cccd_handle)

        time.sleep(1)

        btp.gatts_set_val(self.lt,
                          value_id,
                          "0001")

        btp.gattc_notification_ev(self.iut,
                                  self.lt.stack.gap.iut_addr_get_str(),
                                  self.lt.stack.gap.iut_addr_get_type(),
                                  0x01)

        disconnection_procedure(peripheral=self.lt, central=self.iut)
        self.assertFalse(self.lt.stack.gap.is_connected())
        self.assertFalse(self.iut.stack.gap.is_connected())

    def test_gattc_indication(self):
        value_id = 4
        cccd_handle = 34
        btp.gatts_start_server(self.iut)
        connection_procedure(peripheral=self.lt, central=self.iut)
        self.assertTrue(self.lt.stack.gap.is_connected())
        self.assertTrue(self.iut.stack.gap.is_connected())

        btp.gattc_cfg_indicate(self.iut,
                               self.lt.stack.gap.iut_addr_get_type(),
                               self.lt.stack.gap.iut_addr_get_str(),
                               1, cccd_handle)

        time.sleep(1)

        btp.gatts_set_val(self.lt,
                          value_id,
                          "0001")

        btp.gattc_notification_ev(self.iut,
                                  self.lt.stack.gap.iut_addr_get_str(),
                                  self.lt.stack.gap.iut_addr_get_type(),
                                  0x02)

        disconnection_procedure(peripheral=self.lt, central=self.iut)
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
        connection_procedure(peripheral=self.iut, central=self.lt1)
        self.assertTrue(self.iut.stack.gap.is_connected())
        self.assertTrue(self.lt1.stack.gap.is_connected())
        connection_procedure(peripheral=self.iut, central=self.lt2)
        self.assertTrue(self.iut.stack.gap.is_connected())
        self.assertTrue(self.lt2.stack.gap.is_connected())

        disconnection_procedure(peripheral=self.iut, central=self.lt1)
        self.assertFalse(self.iut.stack.gap.is_connected())
        self.assertFalse(self.lt1.stack.gap.is_connected())
        disconnection_procedure(peripheral=self.iut, central=self.lt2)
        self.assertFalse(self.iut.stack.gap.is_connected())
        self.assertFalse(self.lt2.stack.gap.is_connected())

    def test_connection(self):
        connection_procedure(peripheral=self.lt1, central=self.iut)
        self.assertTrue(self.lt1.stack.gap.is_connected())
        self.assertTrue(self.iut.stack.gap.is_connected())
        connection_procedure(peripheral=self.lt2, central=self.iut)
        self.assertTrue(self.lt2.stack.gap.is_connected())
        self.assertTrue(self.iut.stack.gap.is_connected())

        disconnection_procedure(peripheral=self.lt1, central=self.iut)
        self.assertFalse(self.lt1.stack.gap.is_connected())
        self.assertFalse(self.iut.stack.gap.is_connected())
        disconnection_procedure(peripheral=self.lt2, central=self.iut)
        self.assertFalse(self.lt2.stack.gap.is_connected())
        self.assertFalse(self.iut.stack.gap.is_connected())

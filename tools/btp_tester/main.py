import logging
import unittest

from projects.android.iutctl import AndroidCtl
from projects.mynewt.iutctl import MynewtCtl
from pybtp import btp
from pybtp.testcase import GAPTestCase, AdData, preconditions, GAPTestCaseLT2


def main():
    print("Starting tester")
    format = ("%(asctime)s %(name)-20s %(levelname)s %(threadName)-20s "
              "%(filename)-25s %(lineno)-5s %(funcName)-25s : %(message)s")
    logging.basicConfig(level=logging.DEBUG,
                        format=format)
    logger = logging.getLogger('websockets.server')
    logger.setLevel(logging.ERROR)
    logger.addHandler(logging.StreamHandler())

    mynewt1 = MynewtCtl('/dev/ttyACM0', '683357425')
    mynewt2 = MynewtCtl('/dev/ttyACM1', '683056478')
    # android = AndroidCtl('192.168.9.123', 8765)

    def suite():
        suite = unittest.TestSuite()
        suite.addTest(GAPTestCase('test_gattc_discover_primary_uuid',
                                  mynewt1, mynewt2))
        # suite.addTests(GAPTestCase.init_testcases(mynewt1, mynewt2))
        return suite

    runner = unittest.TextTestRunner(verbosity=2)
    runner.run(suite())

    # mynewt1.start()
    # mynewt1.wait_iut_ready_event()
    # preconditions(mynewt1)
    # btp.gap_set_conn(mynewt1)
    # btp.gap_set_gendiscov(mynewt1)
    # btp.gap_adv_ind_on(mynewt1, ad=[AdData.ad_uuid16])


if __name__ == "__main__":
    main()

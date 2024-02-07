import unittest
import shutil
import os

from log_analyzer import get_last_log

TEST_FOLDER = "tests_487hyh2r893"


class EqualityTest(unittest.TestCase):

    def testLogFinder(self):
        if not os.path.exists(TEST_FOLDER):
            os.mkdir(TEST_FOLDER)
        files = [
            ("nginx-access-ui.log-20150101", False),
            ("nginx-access-ui.log-20160101.gz", True),
            ("nginx-access-ui.log-20170101.bz2", False),
            ("nginx-access-ui.log-20180101.xyz", False),
        ]
        for file, _ in files:
            open(os.path.join(TEST_FOLDER, file), 'w').close()
        filename, log_date = get_last_log(TEST_FOLDER)
        shutil.rmtree(TEST_FOLDER, ignore_errors=True)
        for file, target in files:
            if target:
                self.assertEqual(filename, os.path.join(TEST_FOLDER, file))
            else:
                self.assertNotEqual(filename, os.path.join(TEST_FOLDER, file))


if __name__ == '__main__':
    unittest.main()

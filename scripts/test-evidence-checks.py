#!/usr/bin/env python3
"""Regression checks for accidental zero-test or wrong-binary release receipts."""
import unittest
from evidence_checks import native, oauth, suite
class ReceiptTests(unittest.TestCase):
    def setUp(self):
        self.digest = 'a'*64
        self.log = '\n'.join(['TESTED_BINARY_SHA256 '+self.digest, 'running 1 test',
            'test runner::tests::os_isolation_with_real_uids_and_inherited_pipe ...',
            'PASS: separate AI UID cannot read broker state, modify measured code, or invoke broker',
            'PASS: native worker received only the authorized plaintext; keys/memory/FDs denied',
            'PASS: monotonic UID allocation and workload timeout',
            'PASS: extended ACL bypass is refused even with root-owned 0600 mode',
            'test result: ok. 1 passed; 0 failed; 0 ignored;'])
    def test_positive_control(self):
        native(self.log, 'os-isolation', self.digest, macos=True)
    def test_zero_tests_wrong_name_and_missing_probes_refused(self):
        for old,new in [('1 passed','0 passed'), ('running 1 test','running 0 tests'),
                        ('test runner::tests::','test renamed::'), ('PASS: native worker','OMITTED'),
                        ('PASS: extended ACL','OMITTED'), ('TESTED_BINARY_SHA256','OMITTED')]:
            with self.subTest(old=old), self.assertRaises(AssertionError):
                native(self.log.replace(old,new), 'os-isolation', self.digest, macos=True)
    def test_wrong_binary_and_repeated_receipt_refused(self):
        for text in [self.log.replace('a'*64,'b'*64), self.log+'\nTESTED_BINARY_SHA256 '+self.digest]:
            with self.assertRaises(AssertionError): native(text,'os-isolation',self.digest)
    def test_generic_success_is_insufficient(self):
        with self.assertRaises(AssertionError): suite('test result: ok. 0 passed; 0 failed;')
        with self.assertRaises(AssertionError): oauth(self.log)
if __name__ == '__main__': unittest.main()

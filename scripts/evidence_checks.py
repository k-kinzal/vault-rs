"""Non-vacuous native execution receipts, shared by producers and aggregation."""
import re

def suite(text):
    assert 'test result: FAILED' not in text, 'failed test suite'
    assert any(int(n) > 0 for n in re.findall(r'test result: ok\. (\d+) passed; 0 failed;', text)), 'no tests executed'

def single(text, name, markers):
    suite(text)
    assert 'running 1 test\n' in text, 'expected one focused native test'
    assert 'test result: ok. 1 passed; 0 failed; 0 ignored;' in text, 'focused test did not pass'
    assert 'test '+name+' ...' in text, 'wrong focused test'
    for marker in markers:
        assert marker in text, 'missing native receipt: '+marker

def oauth(text):
    single(text, 'real_authorization_server_code_pkce_dpop_flow',
           ['PASS: real oidc-provider HTTPS authorization code, S256 PKCE, consent, DPoP nonce'])

def native(text, kind, digest, macos=False):
    assert re.fullmatch('[0-9a-f]{64}', digest), 'invalid binary digest'
    receipts = re.findall(r'^TESTED_BINARY_SHA256 ([0-9a-f]{64})$', text, re.M)
    assert receipts == [digest], 'native test did not use the packaged release binary'
    if kind == 'os-isolation':
        markers = ['PASS: separate AI UID cannot read broker state, modify measured code, or invoke broker',
                   'PASS: native worker received only the authorized plaintext; keys/memory/FDs denied',
                   'PASS: monotonic UID allocation and workload timeout']
        if macos:
            markers.append('PASS: extended ACL bypass is refused even with root-owned 0600 mode')
        single(text, 'runner::tests::os_isolation_with_real_uids_and_inherited_pipe', markers)
    else:
        assert kind == 'deployment', 'unknown native check'
        single(text, 'real_cli_services_broker_two_users_restart_and_revocation',
               ['PASS: real CLI HTTPS witness/Vault/broker; two subjects; isolated private-pipe workload; resident service keys; independent process restart; no restored uses; owner revocation. SOFTWARE KEY FIXTURE ONLY.'])

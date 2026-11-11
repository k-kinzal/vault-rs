# Public test fixtures

`*.TEST-ONLY.pem` are generated, public RSA test keys. They must never protect real secrets. Production executables do not include these fixtures or the software RSA unwrapper.

`rfc9180-p256.json` is the mode=0, kem_id=16, kdf_id=1, aead_id=3 known-answer case selected from the [CFRG HPKE test vectors](https://github.com/cfrg/draft-irtf-cfrg-hpke/blob/master/test-vectors.json), accompanying [RFC 9180](https://www.rfc-editor.org/rfc/rfc9180). The test checks the first encryption against the published private/public key, encapsulation, info, AAD, ciphertext and plaintext. The evidence source manifest pins the exact bytes used here; changing the upstream branch does not change a test run.

These RSA keys are public test fixtures, generated for this repository with:

```sh
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out test-only-private.pem
openssl rsa -in test-only-private.pem -pubout -out test-only-public.pem
```

The private key is intentionally committed and is not a secret. Never provision it
in an identity provider or trust its JWKS outside automated tests.

from intersight_auth import repair_pem

def test_fix_pem():
    inp = "-----BEGIN EC PRIVATE KEY-----ABCDEFGHIJKLMNOPQRSTUVWXYZ012345678900abcdefghizjklmnopqrstuvwxyABCDEFGHIJKLMNOPQRSTUVWXYZ012345678900abcdefghizjklmnopqrstuvwxyABCDEFGHIJKLMNOPQRSTUVWXYZ012345678900abcdefghizjklmnopq-----END EC PRIVATE KEY-----"
    expected = """-----BEGIN EC PRIVATE KEY-----
ABCDEFGHIJKLMNOPQRSTUVWXYZ012345678900abcdefghizjklmnopqrstuvwxy
ABCDEFGHIJKLMNOPQRSTUVWXYZ012345678900abcdefghizjklmnopqrstuvwxy
ABCDEFGHIJKLMNOPQRSTUVWXYZ012345678900abcdefghizjklmnopq
-----END EC PRIVATE KEY-----
"""
    assert expected == repair_pem(inp)



import unittest

from server import xor_encrypt, xor_decrypt

class TestServer(unittest.TestCase):
    def test_encryption_decryption(self):
        plaintext = "Hello, World!"
        encrypted_text = xor_encrypt(plaintext)
        decrypted_text = xor_decrypt(encrypted_text)
        self.assertEqual(plaintext, decrypted_text)

    def test_large_text_encryption_decryption(self):
        plaintext = "Lorem ipsum dolor sit amet, consectetur adipiscing elit. Donec nec magna eget justo malesuada eleifend."
        encrypted_text = xor_encrypt(plaintext)
        decrypted_text = xor_decrypt(encrypted_text)
        self.assertEqual(plaintext, decrypted_text)

    def test_empty_text_encryption_decryption(self):
        plaintext = ""
        encrypted_text = xor_encrypt(plaintext)
        decrypted_text = xor_decrypt(encrypted_text)
        self.assertEqual(plaintext, decrypted_text)

if __name__ == "__main__":
    unittest.main()

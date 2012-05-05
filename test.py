import unittest

from Crypto.PublicKey import RSA
from Crypto.Signature import PKCS1_v1_5
from Crypto.Hash import SHA

from base64 import b64decode
from urllib import unquote

class SanityCheckTest(unittest.TestCase):


    RAVEN_PUB_KEY = "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAAAgQC/9qcAW1XCSk0RfAfiu"\
            "lvTouMZKD4jm99rXtMIcO2bn+3ExQpObbwWugiO8DNEffS7bzSxZqGp7U6bPdi4xf"\
            "X76wgWGQ6qWi55OXJV0oSiqrd3aOEspKmJKuupKXONo2efAt6JkdHVH0O6O8k5LVa"\
            "p6w4y1W/T/ry4QH7khRxWtQ=="

    RAVEN_RESPONSE = "1!200!!20120504T220258Z!1336168978-26673-6!https%3A%2F%2"\
            "Ftextmonster.caret.cam.ac.uk%2F!hwtb2!pwd!!36000!foo%2521bar%2521"\
            "baz!2!q-VLPI3tE3Qrxe6Or6dxNs8jBnCN8iYzdTYSPuc9LbzjQay9JpTU59Xpl37"\
            "dg5AaewOXuxmrjTngPGp.qmNtmdcKzV8cLL6I4cane23QwQJt0vvLcTZc1n.fyYd."\
            "qBTjUjHs3aa-8eLc5kdWwNDTHN6N0On.A9sDwv6kGqsZJYA_"

    def testResponseValidity(self):
        key = RSA.importKey(SanityCheckTest.RAVEN_PUB_KEY)

        bits = unquote(SanityCheckTest.RAVEN_RESPONSE).split("!")
        response = "!".join(bits[0:11])

        binary_signature = b64decode(self.fixRavenBase64(bits[-1]))
        self.assertEqual(128, len(binary_signature))

        response_hash = SHA.new(response)

        verifier = PKCS1_v1_5.new(key)
        self.assertTrue(verifier.verify(response_hash, binary_signature))

    def fixRavenBase64(self, ravenb64):
        return ravenb64.replace("-", "+").replace(".", "/").replace("_", "=")

if __name__ == "__main__":
    #import sys;sys.argv = ['', 'Test.testName']
    unittest.main()

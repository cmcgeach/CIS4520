from Crypto.PublicKey import RSA
from Crypto.Signature import pss
from Crypto.Hash import SHA256

class User:
    def __init__(self, username, password):
        self.username = username

        key = RSA.generate(1024)
        with open('../data/' + username + '_private.pem', 'wb') as f:
            data = key.export_key('PEM', password)
            f.write(data)

        with open('../data/' + username + '_public.pem', 'wb') as f:
            data = key.public_key().export_key()
            f.write(data)

        password_hash = SHA256.new(password.encode())
        self.password = password_hash.hexdigest()

    def sign(self, message, password):
        with open('../data/' + self.username + '_private.pem', 'rb') as f:
            data = f.read()
            key = RSA.import_key(data, passphrase=password)
            hash = SHA256.new(str(message).encode())
        return pss.new(key).sign(hash)

    def __str__(self):
        return self.username
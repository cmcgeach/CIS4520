from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA
from Crypto.Signature import pss
import datetime
    

class Block:
    def __init__(self, index, timestamp, author, signature, data, previous_hash):
        self.index = index
        self.timestamp = timestamp
        self.author = author
        self.signature = signature
        self.data = data
        self.previous_hash = previous_hash
        self.nonce = 0
        self.hash = self.calculate_hash()
    
    def calculate_hash(self):
        # concatenate all the block attributes
        hash_string = str(self.index) + str(self.timestamp) + str(self.author) + str(self.signature) + str(self.data) + str(self.previous_hash) + str(self.nonce)
        # convert to hex and return the sha256 hash
        hash = SHA256.new(hash_string.encode())
        return hash.hexdigest()
    
    def mine_block(self, difficulty):
        while self.hash[:difficulty] != "0" * difficulty:
            self.nonce += 1
            self.hash = self.calculate_hash()

    def verify_author(self):
        with open('../data/' + self.author.username + '_public.pem', 'rb') as f:
            key = RSA.import_key(f.read())
            hash = SHA256.new(self.data.encode())
            verifier = pss.new(key)

        try:
            verifier.verify(hash, self.signature)
            return True
        except (ValueError):
            return False

    def __str__(self):
        return "Block " + str(self.index) + "\n" \
                + "Timestamp: " + str(self.timestamp) + "\n" \
                + "Author: " + str(self.author) + "\n" \
                + "Signature: " + self.signature.hex() + "\n" \
                + "Data: " + str(self.data) + "\n" \
                + "Previous Hash: " + str(self.previous_hash) + "\n" \
                + "Hash: " + str(self.hash) + "\n" \

    
class Blockchain:
    # number of preceding zeros the hash requires
    # increase this number to make mining more difficult
    difficulty = 2
    chain = []

    def __init__(self):
        self.chain = [self.create_genesis_block()]

    def create_genesis_block(self):
        return Block(0, datetime.datetime.now(), None, bytes(0), "Genesis Block", 0)
    
    def add_block(self, author, signature, data):
        index = self.chain[-1].index + 1
        timestamp = datetime.datetime.now()
        signature = signature
        previous_hash = self.chain[-1].hash
        new_block = Block(index, timestamp, author, signature, data, previous_hash)

        new_block.mine_block(self.difficulty)
        self.chain.append(new_block)

    def search(self, hash):
        for block in self.chain:
            if str(block.data) == str(hash):
                return block.author, block.timestamp
            
        return None
    
    def validate(self):
        i = 1
        while i < len(self.chain):
            previous_hash = self.chain[i - 1].calculate_hash()
            if previous_hash != self.chain[i].previous_hash:
                return False
            i += 1
            
        return True


    def print_chain(self):
        for block in self.chain:
            print(block)
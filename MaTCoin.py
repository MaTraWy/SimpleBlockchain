from Crypto.Hash import SHA256, RIPEMD
from Crypto.PublicKey import RSA
from Crypto.Signature import PKCS1_v1_5
import pprint
from datetime import datetime


class Transaction:
    def __init__(self, input, output):
        self.input = input
        self.output = output

    def getSerializable(self):
        s = b""
        for x in self.input:
            s = s + bytes.fromhex(x['srcHash']) + bytes(x['index']) + bytes.fromhex(x['srcAddress'])
        for y in self.output:
            s = s + bytes(y['amount']) + bytes.fromhex(y['DistAddress'])
        return s

    def calcTransactionHash(self):
        return SHA256.new(SHA256.new(self.getSerializable()).digest()).digest()

    def getIndexAmount(self, index):
        return (self.output[index])['amount']

    def printTransactionData(self):
        pprint.pprint({'input ': self.input})
        pprint.pprint({'output': self.output})

    def getPrintData(self):
        return {'Transaction Hash': self.calcTransactionHash().hex(),
                'TransactionData': {'input': self.input, 'output': self.output}}


class Block:
    def __init__(self, nonce, tstamp, transactionList, prevhash, target):
        self.nonce = nonce
        self.tstamp = tstamp
        self.transactionList = transactionList
        self.transactionNumber = len(transactionList)
        self.calcMerkleTree()
        self.prevhash = prevhash
        self.target = target
        self.hash = ''
        self.target = target

    def calcHash(self):
        # concatenating all the data for calculate hash
        blockString = (bytes.fromhex(self.prevhash)
                       + bytes.fromhex(self.merkleTree)
                       + self.tstamp.encode()
                       + bytes(self.target)
                       + bytes(self.nonce)
                       + bytes(self.transactionNumber))

        self.hash = SHA256.new(blockString).hexdigest()
        return self.hash

    def calcMerkleTree(self):
        hashList = [tran.calcTransactionHash() for tran in self.transactionList]
        # for tran in self.transactionList:
        # print('HashList',tran.output)
        self.merkleTree = self.merkle(hashList).hex()
        # contain digest, array of bytes

    def merkle(self, hashList):
        if len(hashList) == 1:
            return hashList[0]
        newHashList = []
        for i in range(0, len(hashList) - 1, 2):
            newHashList.append(self.HashPair(hashList[i], hashList[i + 1]))
        if len(hashList) % 2 == 1:  # odd, hash last item twice
            newHashList.append(self(hashList[-1], hashList[-1]))
        return self.merkle(newHashList)

    def HashPair(self, a, b):
        return SHA256.new(SHA256.new(a + b).digest()).digest()

    def printBlockData(self):
        dict = {
            'MerkleTreeHash': self.merkleTree,
            'prevHash': self.prevhash,
            'Target': self.target,
            'Transaction': [tran.getPrintData() for tran in self.transactionList],
            'Timestamp': self.tstamp,
            'TransactionNumbers': self.transactionNumber,
        }
        pprint.pprint({"BlockHash": self.hash, "BlockData": dict})
        # for tran in self.transactionList:
        # tran.printTransactionData()


class Blockchain:

    def __init__(self):
        self.blockchain = []

    def calcGensisBlock(self, listOfAddress, peers):
        listOfTransaction = []
        for address in listOfAddress:
            listOfTransaction.append(Transaction([{'srcHash': '00', 'index': 0, 'srcAddress': '00'}, ]
                                                 ,
                                                 [{'amount': address['amount'], 'DistAddress': address['address']}, ]))
        # for tran in listOfTransaction:
        # print(tran.output)
        gensisBlock = Block(0, '2012/8/5', listOfTransaction, '00', 0)
        gensisBlock.calcHash()
        self.blockchain.append(gensisBlock)
        i = 0
        for peer in peers:
            peer.utxo.append({'transaction': listOfTransaction[0], 'index': 0})
            i = i + 1

    def printBlockData(self):
        for block in self.blockchain:
            block.printBlockData()


class Actor:
    def __init__(self, fileName, blockchain):
        f = open(fileName, 'r')
        self.rsaKey = RSA.importKey(f.read())
        self.address = RIPEMD.new(self.rsaKey.publickey().exportKey()).digest()
        self.amount = 0
        self.blockchain = blockchain
        self.utxo = []
        f.close()

    def CalcAmount(self):  ##to do
        self.amount = 0
        for raw in self.utxo:
            self.amount = raw['transaction'].getIndexAmount(raw['index'])

    def SendCoin(self, to, Amount):
        if len(self.utxo) == 0:
            print('Address: ', self.address.hex(), " do not have coins")
            return
        listOfInput = []
        count = 0
        for raw in self.utxo:  # hna a3mel array a7ot feha hash, amount, index
            tran = raw['transaction']
            count += tran.getIndexAmount(raw['index'])
            listOfInput.append(
                {'srcHash': tran.calcTransactionHash().hex(), 'index': raw['index'], 'srcAddress': self.address.hex()})
            if count >= Amount:
                break
        if (count < Amount):
            print('Address: ', self.address, " coins is not enough")
            return
        diff = count - Amount
        newTransaction = Transaction(listOfInput, [{"amount": (Amount), "DistAddress": to.address.hex()}])
        self.utxo = self.utxo[len(listOfInput)::]
        if count != Amount:
            newTransaction.output.append({'amount': diff, 'DistAddress': self.address.hex()})
            self.utxo.append({'transaction': newTransaction, 'index': 1})  # hard coded :(
        to.utxo.append({'transaction': newTransaction, 'index': 0})
        return newTransaction

    def getAddressCoin(self, address):
        addressBalance = 0
        isSource = False
        for block in self.blockchain.blockchain:
            for transaction in block.transactionList:
                if transaction.input[0]["srcAddress"] == address:
                    isSource = True
                for output in transaction.output:
                    if isSource and output['DistAddress'] != address:
                        addressBalance -= output['amount']
                    if not isSource and output['DistAddress'] == address:
                        addressBalance += output['amount']
            isSource = False
        return addressBalance


class Miner(Actor):
    def __init__(self, fileName, blockchain):
        Actor.__init__(self, fileName, blockchain)
        self.pendingTransaction = []
        self.numberOfBlockMined = 0

    def Mining(self, currentTarget):
        currentTime = datetime.now().strftime("%m/%d/%Y%H:%M:%S")
        minedBlock = Block(0, currentTime, self.pendingTransaction.copy(),
                           self.getTopBlock().hash, currentTarget)

        while minedBlock.hash[:currentTarget] != "0" * currentTarget:
            minedBlock.nonce += 1
            minedBlock.hash = minedBlock.calcHash()
        print("Mined Successfully")
        self.pendingTransaction.clear()
        self.blockchain.blockchain.append(minedBlock)

    def getTopBlock(self):
        return self.blockchain.blockchain[-1]

mainBlockchain = Blockchain()

print("Welcome to crypto currency simulator MatCoin")
print("Current users are "+())
Alice = Actor('alice.pem', mainBlockchain)
Bob = Actor('bob.pem', mainBlockchain)
Joe = Actor('joe.pem', mainBlockchain)
Mahmoud = Miner('mahmoud.pem', mainBlockchain)

listOfPeers = [Alice, Bob, Joe, Mahmoud]

# print Address
# for peer in listOfPeers:
# print(peer.address.hex())

# Gensis Transaction
listOfGensisTransaction = [{'amount': 50, 'address': Alice.address.hex()},
                           {'amount': 150, 'address': Bob.address.hex()}]

mainBlockchain.calcGensisBlock(listOfGensisTransaction, [Alice, Bob])

tran = Alice.SendCoin(Bob, 10)
Mahmoud.pendingTransaction.append(tran)
Mahmoud.Mining(2)
Mahmoud.pendingTransaction.append(Alice.SendCoin(Bob, 40))
Mahmoud.Mining(2)
Mahmoud.pendingTransaction.append(Bob.SendCoin(Alice, 40))
mainBlockchain.printBlockData()
Mahmoud.Mining(2)
print(Mahmoud.getAddressCoin(Bob.address.hex()))
print(Mahmoud.getAddressCoin(Alice.address.hex()))

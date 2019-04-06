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
            "BlockHash": self.hash,
            'MerkleTreeHash': self.merkleTree,
            'prevHash': self.prevhash,
            'Target': self.target,
            'Timestamp': self.tstamp,
            'TransactionNumbers': self.transactionNumber,
            'Transactions List': [tran.getPrintData() for tran in self.transactionList],
        }
        pprint.pprint(dict)
        # for tran in self.transactionList:
        # tran.printTransactionData()


class Blockchain:

    def __init__(self):
        self.blockchain = []
        self.peers = []

    def calcGensisBlock(self, listOfAddress, peers):
        listOfTransaction = []
        for address in listOfAddress:
            listOfTransaction.append(Transaction([{'srcHash': '00', 'index': 0, 'srcAddress': '00'}, ]
                                                 ,
                                                 [{'amount': address['amount'], 'DistAddress': address['address']}, ]))
        # for tran in listOfTransaction:
        #   print(tran.output,tran.calcTransactionHash().hex())
        gensisBlock = Block(0, '2012/8/5', listOfTransaction, '00', 0)
        gensisBlock.calcHash()
        self.blockchain.append(gensisBlock)
        i = 0
        for i in range(0, len(peers)):
            peers[i].utxo.append({'transaction': listOfTransaction[i], 'index': 0})
            i = i + 1

    def printBlockData(self):
        for block in self.blockchain:
            block.printBlockData()

    def printAllTransaction(self):
        list = []
        for block in self.blockchain:
            for transaction in block.transactionList:
                fromm = transaction.input[0]["srcAddress"]
                to = ', '.join([self.resolveAddress(output['DistAddress']) + output['DistAddress'] for output in
                                transaction.output])
                amount = ', '.join([str(output['amount']) for output in transaction.output])
                list.append({"Transaction Hash: ": transaction.calcTransactionHash().hex(),
                             "From Address ": self.resolveAddress(fromm) + " " + fromm,
                             "To Address": to, "Amount": amount})
        return list

    def resolveAddress(self, address):
        if address == "00":
            return "Gensis"
        for peer in self.peers:
            if (self.peers[peer].address.hex() == address):
                return peer


class Actor:
    def __init__(self, fileName, blockchain):
        f = open(fileName, 'r')
        self.rsaKey = RSA.importKey(f.read())
        self.address = RIPEMD.new(self.rsaKey.publickey().exportKey()).digest()
        print(self.rsaKey.exportKey().hex())
        self.amount = 0
        self.blockchain = blockchain
        self.utxo = []
        f.close()

    def CalcAmount(self):  ##to do
        self.amount = 0
        for raw in self.utxo:
            self.amount += raw['transaction'].getIndexAmount(raw['index'])

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
        to.CalcAmount()
        self.CalcAmount()
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

    def getUserTransaction(self):
        listOfTran = []
        for block in self.blockchain.blockchain:
            for transaction in block.transactionList:
                if transaction.input[0]["srcAddress"] == self.address.hex():
                    listOfTran.append(transaction)
                    continue
                for output in transaction.output:
                    if output["DistAddress"] == self.address.hex():
                        listOfTran.append(transaction)
                        break
        return listOfTran

    def getUserData(self):
        # print(self.rsaKey.exportKey().hex())
        self.CalcAmount()
        return {"Public key: ": (self.rsaKey.publickey().exportKey()[27::])[:-25].hex(),
                "Private key: ": (self.rsaKey.exportKey()[32::])[:-30].hex(),
                "Coin address:": self.address.hex(),
                "Amount ": self.amount,
                "Transaction UTXO": [tran['transaction'].calcTransactionHash().hex() for tran in self.utxo]}


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
pprint.sorted = lambda x, key=None: x

# intializing the users
Alice = Actor('alice.pem', mainBlockchain)
Bob = Actor('bob.pem', mainBlockchain)
Joe = Actor('joe.pem', mainBlockchain)
Mahmoud = Miner('mahmoud.pem', mainBlockchain)

listOfPeers = {"Alice": Alice, "Bob": Bob, "Joe": Joe}
listOfMiners = {"Mahmoud": Mahmoud}
mainBlockchain.peers = listOfPeers
listOfGensisTransaction = [{'amount': 50, 'address': Alice.address.hex()},
                           {'amount': 150, 'address': Bob.address.hex()}]
mainBlockchain.calcGensisBlock(listOfGensisTransaction, [Alice, Bob])

tran = Alice.SendCoin(Bob, 10)
Mahmoud.pendingTransaction.append(tran)
Mahmoud.Mining(2)
Mahmoud.pendingTransaction.append(Alice.SendCoin(Bob, 40))
Mahmoud.Mining(2)
Mahmoud.pendingTransaction.append(Bob.SendCoin(Joe, 40))
# mainBlockchain.printBlockData()
Mahmoud.Mining(2)
print("Welcome to crypto currency simulator <MatCoin/>")
print("Current users are : ", ", ".join(key for key in listOfPeers))
print("Current miners are : ", ", ".join(key for key in listOfMiners))
choice = 0

'''data = []
for user in listOfPeers:
    data.append({user: listOfPeers[user].getUserData()})
pprint.pprint(data)
pprint.pprint(mainBlockchain.printAllTransaction())'''

while (True):
    print("Please Choose through the list")
    print("Enter '0' to show current users data \n" +
          "Enter '1' to show current transactions data \n" +
          "Enter '2' to show current blockchain data \n" +
          "Enter '3' to show users address \n" +
          "Enter '4' to show users balance \n" +
          "Enter '5' to select a specific user \n" +
          "Enter '-1' to exit")
    choice = int(input())
    if choice == -1:
        break
    if choice == 0:
        data = []
        for user in listOfPeers:
            data.append({user: listOfPeers[user].getUserData()})
        pprint.pprint(data)
    if choice == 1:
        pprint.pprint(mainBlockchain.printAllTransaction())
    if choice == 2:
        pprint.pprint(mainBlockchain.printBlockData())
    if choice == 3:
        print(",\n".join(peer + " -> "+listOfPeers[peer].address.hex() for peer in listOfPeers))
    if choice == 4:
        print(",\n".join(peer +" ("+listOfPeers[peer].address.hex()+") "+ " -> "+str(listOfPeers[peer].amount) for peer in listOfPeers))
    if choice == 5:
        print("Please select one of the peers: " + ", ".join(peer for peer in listOfPeers))
        peerChoice = str(input())
        while (peerChoice not in listOfPeers):
            print("Invalid peer!!, Please select one of the peers: " + ", ".join(peer for peer in listOfPeers))
            peerChoice = str(input())
        print("\n You Selected peer: " + peerChoice)
        while (choice != -1):
            print("Please Choose through the list")
            print("Enter '0' to show current user data \n" +
                  "Enter '1' to send coin \n" +
                  "Enter '-1' to exit")
            choice = int(input())
            if choice == 0:
                pprint.pprint(listOfPeers[peerChoice].getUserData())
            if choice == 1:
                print("Please select the one you want send coin to ! " + " ".join(
                    (peer if peer != peerChoice else "") for peer in listOfPeers))
                selected = str(input())
                print("Please enter the amount of coin: ")
                amount = int(input())
                print("You selected the recipient peer name: "+selected+"and the amount to send "+str(amount))
                print("you want to proceed 1/0")
                proceed = bool(input())
                if proceed:
                    Mahmoud.Mining(listOfPeers[peerChoice].SendCoin(listOfPeers[selected],amount),2)

# print Address
# for peer in listOfPeers:
# print(peer.address.hex())

# Gensis Transaction


# print(Mahmoud.getAddressCoin(Bob.address.hex()))
# print(Mahmoud.getAddressCoin(Alice.address.hex()))

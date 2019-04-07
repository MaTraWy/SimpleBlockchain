from Crypto.Hash import SHA256, RIPEMD
from Crypto.PublicKey import RSA
from Crypto.Signature import PKCS1_v1_5
import pprint
from datetime import datetime


# A class contain all transaction data
class Transaction:

    # class constructor, remember each transaction contain array of inputs and outputs
    def __init__(self, input, output):
        self.input = input
        self.output = output

    # this function to return array of bytes of the transaction data concatenated, later used for hashing
    def getSerializable(self):
        s = b""  # this define empty array of bytes, b stand for byte!
        for x in self.input:
            s = s + bytes.fromhex(x['srcHash']) + bytes(x['index']) + bytes.fromhex(x['srcAddress'])  # concat inputs
        for y in self.output:
            s = s + bytes(y['amount']) + bytes.fromhex(y['DistAddress'])  # concat outputs
        return s

    # calculate the double hash of the transaction data
    def calcTransactionHash(self):
        return SHA256.new(
            SHA256.new(self.getSerializable()).digest()).digest()  # .digest(), return hash as array of bytes

    # Get amount of coin for specific output index
    def getIndexAmount(self, index):
        return (self.output[index])['amount']

    # Print the transaction data
    def printTransactionData(self):
        pprint.pprint({'input ': self.input})
        pprint.pprint({'output': self.output})

    # Get data of transaction for further print, used to print block with transaction
    def getPrintData(self):
        return {'Transaction Hash': self.calcTransactionHash().hex(),
                'TransactionData': {'input': self.input, 'output': self.output}}


# A class contain all block data
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

    # Calculate a hash of a block
    def calcHash(self):
        # concatenating all the data for calculate hash
        blockString = (bytes.fromhex(self.prevhash)
                       + bytes.fromhex(self.merkleTree)
                       + self.tstamp.encode()
                       + bytes(self.target)
                       + bytes(self.nonce)
                       + bytes(self.transactionNumber))  # remeber that out goal to create array of bytes

        self.hash = SHA256.new(blockString).hexdigest()
        return self.hash

    # Calculate merkle tree of transactions in a block
    def calcMerkleTree(self):
        hashList = [tran.calcTransactionHash() for tran in
                    self.transactionList]  # hash list contain hash's of all transaction in block
        self.merkleTree = self.merkle(hashList).hex()  # .hex() convert array of bytes to string of hex!

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


# A class contain all blockchain data, i.e contain chain of block's
class Blockchain:

    def __init__(self):
        self.blockchain = []
        self.peers = []

    # Gensis block, is the initial block that contain initial transaction !
    def calcGensisBlock(self, listOfAddress, peers):
        listOfTransaction = []
        for address in listOfAddress:
            listOfTransaction.append(
                Transaction([{'srcHash': '00', 'index': 0, 'srcAddress': '00'}, ]  # 00 equivalent to null
                            ,
                            [{'amount': address['amount'], 'DistAddress': address['address']}, ]))

        gensisBlock = Block(0, '2012/8/5', listOfTransaction, '00', 0)  # first block created was in  2012
        gensisBlock.calcHash()
        self.blockchain.append(gensisBlock)  # Add the gensis block to blockchain
        i = 0
        for i in range(0, len(peers)):  # Update the utxo(unspend transaction output)
            peers[i].utxo.append({'transaction': listOfTransaction[i], 'index': 0})
            i = i + 1

    # function to print all the block data in the blockchain
    def printBlockData(self):
        for block in self.blockchain:  # loop thorugh blockchain and print each block data
            block.printBlockData()

    # function to print all the transaction in the blockchain without block data
    def printAllTransaction(self):
        list = []
        for block in self.blockchain:
            for transaction in block.transactionList:
                fromm = transaction.input[0]["srcAddress"]  # to know transaction sender
                to = ', '.join([self.resolveAddress(output['DistAddress']) + output['DistAddress'] for output in
                                transaction.output])  # to know the receiver
                amount = ', '.join(
                    [str(output['amount']) for output in transaction.output])  # amount of money send to each receiver
                list.append({"Transaction Hash: ": transaction.calcTransactionHash().hex(),
                             "From Address ": self.resolveAddress(fromm) + " " + fromm,
                             "To Address": to, "Amount": amount})
        return list

    # function take address and return user name!
    def resolveAddress(self, address):
        if address == "00":
            return "Gensis"
        if address == "0000":
            return "Reward"
        for peer in self.peers:
            if (self.peers[peer].address.hex() == address):
                return peer
        return 'unknown'


# A class contain data for users in blockchain
class Actor:
    ''' parameters
    fileName : contain  the path to pem of the user
    blockchain : contain the main object of blockchain '''

    def __init__(self, fileName, blockchain):
        f = open(fileName, 'r')  # open the file
        self.rsaKey = RSA.importKey(f.read())  # using RSA module to import kye from pem
        self.address = RIPEMD.new(
            (self.rsaKey.publickey().exportKey()[27::])[:-25]).digest()  # address is hash 160 of public key
        self.amount = 0  # init amount of coin to 0
        self.blockchain = blockchain  # assign blockchain object
        self.utxo = []  # utxo is empty now
        f.close()  # close pem file

    # function to calculate amount of money for a user
    def CalcAmount(self):
        self.amount = 0
        for raw in self.utxo:  # loop through the user utxo and calc amount
            self.amount += raw['transaction'].getIndexAmount(raw['index'])

    # send coin function
    ''' parameters
        to : object of the receiver (instance from Actor)
        Amount : amount of coin you want to send to receiver '''

    def SendCoin(self, to, Amount):
        if len(self.utxo) == 0:  # check the utxp if empty, then he don't have coin!
            print('Address: ', self.address.hex(), " do not have coins")
            return
        listOfInput = []
        count = 0  # counter to know value for every input transaction
        # 3la 7sb b2a, mmoken ast5dm aktr mn input, 3shan msln lw input wa7d  mmoken mekfesh el coin el feh
        for raw in self.utxo:  # hna 3mel array a7ot feha hash, amount, index
            tran = raw['transaction']
            count += tran.getIndexAmount(raw['index'])
            # here i define the input of the transaction
            listOfInput.append(
                {'srcHash': tran.calcTransactionHash().hex(), 'index': raw['index'], 'srcAddress': self.address.hex()})
            if count >= Amount:  # here break because count is grater than amount to be send
                break

        if (count < Amount):  # here the coin is not enough
            print('Address: ', self.address, " coins is not enough")
            return

        diff = count - Amount  # calculate the diff
        newTransaction = Transaction(listOfInput, [
            {"amount": (Amount), "DistAddress": to.address.hex()}])  # define output of transaction

        self.utxo = self.utxo[len(listOfInput)::]  # remove used transaction from utxo
        if count != Amount:  # here make new  transaction and assign diff to the sender again
            newTransaction.output.append({'amount': diff, 'DistAddress': self.address.hex()})
            self.utxo.append({'transaction': newTransaction, 'index': 1})  # hard coded :(

        to.utxo.append({'transaction': newTransaction, 'index': 0})

        # here update the balance for each send and receiver
        to.CalcAmount()
        self.CalcAmount()
        return newTransaction  # when done return the new transaction for mining later

    # Function to return balance for specific address, another way to calculate balance
    ''' parameters
            address : address of actor to want to know his balance '''

    def getAddressCoin(self, address):
        addressBalance = 0  # counter for knowing the balance
        # el fekra lma 2l2eh sender hashel mno, lw l2to receiver hadef 3leh
        isSource = False  # isSource to know if he is sender if speceific transaction

        for block in self.blockchain.blockchain:
            for transaction in block.transactionList:  # loop in every transaction
                # here we check if he is sender for this transaction
                if transaction.input[0]["srcAddress"] == address:
                    isSource = True
                # loop through the output of the transaction
                for output in transaction.output:
                    # check if he is sender and output address not his address
                    if isSource and output['DistAddress'] != address:
                        addressBalance -= output['amount']  # subtract from his balance
                    # check if he is not sender and output address is his address
                    if not isSource and output['DistAddress'] == address:
                        addressBalance += output['amount']

            isSource = False  # when done loop trough transaction output, make isSource false again

        return addressBalance  # finally return the balance

    # A function to return all the transaction for the user he involved in !
    def getUserTransaction(self):
        listOfTran = []  # list of transaction he involved in ( swa2 b2a sender or receiver)

        for block in self.blockchain.blockchain:
            for transaction in block.transactionList:  # loop through all the transaction
                # if he is the sender add the transaction in list and continue
                if transaction.input[0]["srcAddress"] == self.address.hex():
                    listOfTran.append(transaction)
                    continue
                # loop thorugh the output, to check wheater if his address exsist or not
                for output in transaction.output:
                    # if found the address, add transaction to lsit and break, to continue checking other transaction
                    if output["DistAddress"] == self.address.hex():
                        listOfTran.append(transaction)
                        break

        return listOfTran  # return list contain the transaction

    # function to get user data in a printable format
    def getUserData(self):
        self.CalcAmount()
        return {"Public key: ": (self.rsaKey.publickey().exportKey()[27::])[:-25].hex(),
                "Private key: ": (self.rsaKey.exportKey()[32::])[:-30].hex(),
                "Coin address:": self.address.hex(),
                "Amount ": self.amount,
                "Transaction UTXO": [tran['transaction'].calcTransactionHash().hex() for tran in self.utxo]}


# A class contain all miner data, i.e, miner is a child from the Actor
class Miner(Actor):

    def __init__(self, fileName, blockchain):
        Actor.__init__(self, fileName, blockchain)
        self.pendingTransaction = []  # list of pending transaction to be mined later
        self.reward = 0

    # Function to return balance for specific address, another way to calculate balance
    ''' parameters
        currentTarget : define the difficulty of mathematical puzzle '''

    def Mining(self, currentTarget):
        currentTime = datetime.now().strftime("%m/%d/%Y%H:%M:%S")  # get current time!

        # create new object from block for mining
        minedBlock = Block(0, currentTime, self.pendingTransaction.copy(),
                           self.getTopBlock().hash, currentTarget)

        # adding the reward transaction!, fees for mining
        # src address 0000 it's a mining fee
        minedBlock.transactionList.append(
            Transaction([{'srcHash': '0000', 'index': 0, 'srcAddress': '0000'}, ]
                        ,
                        [{'amount': self.reward, 'DistAddress': self.address.hex()}, ]))

        '''here in the loop every time we calculate the has of the block and compare the leading chars 
         in the hash if they are zeros or not according to the target, for example, if target is 2, then
          we compare the leading two char  if they are 00 or not, it yes mining done, if not, increment 
          the nonce var and then calculate the hash again, and you loop until you satisfies the condition '''

        while minedBlock.hash[:currentTarget] != "0" * currentTarget:  # mining condition
            minedBlock.nonce += 1
            minedBlock.hash = minedBlock.calcHash()

        print("Mined Successfully")
        self.pendingTransaction.clear()
        self.blockchain.blockchain.append(minedBlock)

    def getTopBlock(self):
        return self.blockchain.blockchain[-1]


mainBlockchain = Blockchain()  # take object from blockChain class
pprint.sorted = lambda x, key=None: x  # here an configuration for pprint lib

# initializing the users, @TODO we need to automate this part rather than hard coded!
Alice = Actor('alice.pem', mainBlockchain)
Bob = Actor('bob.pem', mainBlockchain)
Joe = Actor('joe.pem', mainBlockchain)
Mahmoud = Miner('mahmoud.pem', mainBlockchain)  # Mahmoud is the miner

listOfPeers = {"Alice": Alice, "Bob": Bob, "Joe": Joe}
listOfMiners = {"Mahmoud": Mahmoud}

mainBlockchain.peers = listOfPeers

listOfGensisTransaction = [{'amount': 50, 'address': Alice.address.hex()},
                           {'amount': 150, 'address': Bob.address.hex()}] # Define the gensis transaction!

mainBlockchain.calcGensisBlock(listOfGensisTransaction, [Alice, Bob]) # Calculate the gensis block
Mahmoud.reward = 2 # setting mining reward

# here a list of transaction to check if every thing is working properly

# Alice send 10 coin to bob and add this transaction to pending transaction
Mahmoud.pendingTransaction.append(Alice.SendCoin(Bob, 10))
Mahmoud.Mining(2) # start mining !!

# Alice send 40 coin to Bob and add this transaction to pending transaction
Mahmoud.pendingTransaction.append(Alice.SendCoin(Bob, 40))
Mahmoud.Mining(2)# start mining !!

# Bob send to Joe 40 coin and add this transaction to pending transaction
Mahmoud.pendingTransaction.append(Bob.SendCoin(Joe, 40))
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
        print("\n".join(peer + " -> " + listOfPeers[peer].address.hex() for peer in listOfPeers))
    if choice == 4:
        print("\n".join(
            peer + " (" + listOfPeers[peer].address.hex() + ") " + " -> " + str(listOfPeers[peer].amount) for peer in
            listOfPeers))
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
                print("You selected the recipient peer name: " + selected + "and the amount to send " + str(amount))
                print("you want to proceed 1/0")
                proceed = bool(input())
                if proceed:
                    Mahmoud.Mining(listOfPeers[peerChoice].SendCoin(listOfPeers[selected], amount), 2)

# print(Mahmoud.getAddressCoin(Bob.address.hex()))
# print(Mahmoud.getAddressCoin(Alice.address.hex()))

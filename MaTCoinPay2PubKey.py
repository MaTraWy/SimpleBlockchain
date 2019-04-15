from Crypto.Hash import SHA256, RIPEMD
from Crypto.PublicKey import RSA
from Crypto.Signature import PKCS1_v1_5
import pprint
from datetime import datetime

__author__ = "Mahmoud Matrawy"

'''The following project was created to simulate Bitcoin operations and functionality
based on developer guide: https://www.lopp.net/pdf/Bitcoin_Developer_Reference.pdf
feel free to contribute and add new functionality, check @Todo list'''

'''
Transaction Output: <sig> <pubKey> OP_DUP OP_HASH160 <pubKeyHash> OP_EQUALVERIFY OP_CHECKSIG 
Transaction Input: <sig> <pubKey>
'''

# A class contain all transaction data
class Transaction:

    # class constructor, remember each transaction contain array of inputs and outputs
    def __init__(self, input, output):
        self.input = input  # []
        self.output = output

    # calculate the double hash of the transaction data
    def calcTransactionHash(self):
        s = b""  # this define empty array of bytes, b stand for byte!
        for x in self.input:
            s = s + bytes.fromhex(x['srcHash']) + bytes(x['index']) + bytes.fromhex(x['srcAddress'])  # concat inputs
        for y in self.output:
            s = s + bytes(y['amount']) + (y['DistAddress'].encode())  # concat outputs
            return SHA256.new(
            SHA256.new(s).digest())
        return SHA256.new(
            SHA256.new(s).digest()).digest()  # .digest(), return hash as array of bytes

    # Get amount of coin for specific output index
    def getIndexAmount(self, index):
        return (self.output[index])['amount']

    # Print the transaction data
    def printTransactionData(self):
        pprint.pprint({'input ': self.input})
        pprint.pprint({'output': self.output})

    # Get data of transaction for further print, used to print block with transaction
    def getPrintData(self):
        return {'Transaction Hash': self.calcTransactionHash().hexdigest(),
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
        hashList = [tran.calcTransactionHash().digest() for tran in
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
        for address,peer in zip(listOfAddress,peers):
            print(peer.address.hex())
            distAddress = "OP_DUP OP_HASH160 "+peer.address.hex()+" OP_EQUALVERIFY OP_CHECKSIG"

            listOfTransaction.append(
                Transaction([{'srcHash': '00', 'index': 0, 'srcAddress': '00'}, ]  # 00 equivalent to null
                            ,
                            [{'amount': address['amount'], 'DistAddress': distAddress}, ]))

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
                to = ', '.join([output['DistAddress'] for output in
                                transaction.output])  # to know the receiver
                amount = ', '.join(
                    [str(output['amount']) for output in transaction.output])  # amount of money send to each receiver
                list.append({"Transaction Hash: ": transaction.calcTransactionHash().hexdigest(),
                             "From Address ": fromm ,
                             "To Address": to, "Amount": amount})
        return list


# A class contain data for users in blockchain
class Actor:
    ''' parameters
    fileName : contain  the path to pem of the user
    blockchain : contain the main object of blockchain '''

    def __init__(self, fileName, blockchain):
        f = open(fileName, 'r')  # open the file
        self.rsaKey = RSA.importKey(f.read())  # using RSA module to import kye from pem
        self.address = RIPEMD.new(self.rsaKey.publickey().exportKey()).digest()  # address is hash 160 of public key
        self.amount = 0  # init amount of coin to 0
        self.blockchain = blockchain  # assign blockchain object
        self.utxo = []  # utxo is empty now
        self.publicKey = self.rsaKey.publickey().exportKey()
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
        if len(self.utxo) == 0:  # check the utxo if empty, then he don't have coin!
            print('Address: ', self.address.hex(), " do not have coins")
            return None
        listOfInput = []
        count = 0  # counter to know value for every input transaction
        # 3la 7sb b2a, mmoken ast5dm aktr mn input, 3shan msln lw input wa7d  mmoken mekfesh el coin el feh
        singer = PKCS1_v1_5.new(self.rsaKey)

        for raw in self.utxo:
            tran = raw['transaction']
            count += tran.getIndexAmount(raw['index'])
            #print(self.rsaKey.publickey().exportKey().hex())
            srcAdd = singer.sign(tran.calcTransactionHash()).hex() + " "+self.rsaKey.publickey().exportKey().hex()
            listOfInput.append(
                {'srcHash': tran.calcTransactionHash().digest().hex(), 'index': raw['index'], 'srcAddress': srcAdd})
            if count >= Amount:  # here break because count is grater than amount to be send
                break
        print("hi ",len(listOfInput))
        if (count < Amount):  # here the coin is not enough
            print('Address: ', self.address, " coins is not enough")
            return None

        diff = count - Amount  # calculate the diff

        distRec = "OP_DUP OP_HASH160 "+to.address.hex()+" OP_EQUALVERIFY OP_CHECKSIG"
        newTransaction = Transaction(listOfInput, [
            {"amount": (Amount), "DistAddress": distRec}])  # define output of transaction

        self.utxo = self.utxo[len(listOfInput)::]  # remove used transaction from utxo
        if count != Amount:
            distSend = "OP_DUP OP_HASH160 "+self.address.hex()+" OP_EQUALVERIFY OP_CHECKSIG"
            newTransaction.output.append({'amount': diff, 'DistAddress':distSend})
            self.utxo.append({'transaction': newTransaction, 'index': 1})  # hard coded :(

        to.utxo.append({'transaction': newTransaction, 'index': 0})

        # here update the balance for each send and receiver
        to.CalcAmount()
        self.CalcAmount()
        return newTransaction  # when done return the new transaction for mining later

    # function to get user data in a printable format
    def getUserData(self):
        self.CalcAmount()
        return {"Public key: ": (self.rsaKey.publickey().exportKey()[27::])[:-25].hex(),
                "Private key: ": (self.rsaKey.exportKey()[32::])[:-30].hex(),
                "Coin address:": self.address.hex(),
                "Amount ": self.amount,
                "Transaction UTXO": [tran['transaction'].calcTransactionHash().digest().hex() for tran in self.utxo]}


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

        # *new part
        distAddress = "OP_DUP OP_HASH160 " + self.address.hex() + " OP_EQUALVERIFY OP_CHECKSIG"
        # *

        for tran in self.pendingTransaction:
            if not self.Verify(tran):
                return False

        minedBlock.transactionList.append(
            Transaction([{'srcHash': '0000', 'index': 0, 'srcAddress': '0000'}, ]
                        ,
                        [{'amount': self.reward, 'DistAddress': distAddress}, ]))

        '''here in the loop every time we calculate the hash of the block and compare the leading chars 
         in the hash if they are zeros or not according to the target, for example, if target is 2, then
          we compare the leading two char  if they are 00 or not, it yes mining done, if not, increment 
          the nonce var and then calculate the hash again, and you loop until you satisfies the condition '''

        while minedBlock.hash[:currentTarget] != "0" * currentTarget:  # mining condition
            minedBlock.nonce += 1
            minedBlock.hash = minedBlock.calcHash()

        print("Mined Successfully")
        self.pendingTransaction.clear()
        self.blockchain.blockchain.append(minedBlock)

    # to Do you have to replace None with correct Solution ^^
    # first we need to check that the referanced transction exisit in the blockchain
    # if found then check the script..
    def Verify(self, Tran):
        for input in None:
            for block in None:
                for prevTran in None:
                    if input['srcHash'] == prevTran.calcTransactionHash().hexdigest():
                        if not self.checkScript(input, prevTran.output[input['index']], prevTran.calcTransactionHash()):
                            return False
        return True

    '''
    the checkScript function, a function where it checks the correctness of a script, here we do the stack table 
        CurrentTransactionInput: input part in the current transaction, we need it to get the signature & public key
        prevTran: output part in the referenced transaction, we need it to get the script part :D 
        TranHash: the hash of the referenced transaction
    '''

    def checkScript(self, CurrentTransactionInput, prevTran, TranHash):

        # concate the signture and address with the script part
        concate = CurrentTransactionInput['srcAddress'] + " " + prevTran['DistAddress']

        # we need to split the data into a list
        # remember that it's separated by a space, aktr mn kda agy a3mel el split ana 😂
        # concate = (here we put the function of split)

        # concate data = < sig > < pubKey > OP_DUP OP_HASH160 < pubKeyHash > OP_EQUALVERIFY OP_CHECKSIG
        l = []

        operation = ['OP_DUP', 'OP_HASH160', 'OP_EQUALVERIFY', 'OP_CHECKSIG']

        for data in concate:
            if data not in operation:
                l.append(data)
            if data == "OP_DUP":
                top = l.pop()
                # fill here, what we do after we do a pop ?
            if data == "OP_HASH160":
                top = l.pop()
                # fill here, remeber, that the public key ia a string of hex, convert it back to array of byte
                # by bytes.fromhex() , then hash then push to stack
            if data == 'OP_EQUALVERIFY':
                print("")
                # fill here, what we do here?
            if data == 'OP_CHECKSIG':
                pub_Key = l.pop()
                sig = l.pop()
                pub_Key = RSA.importKey(bytes.fromhex(pub_Key))
                # here you have Sig, pub_Key, you need to verify the signature, if it's correct return true

        # if the for loop reach it's end and didn't return true, then the verification scheme failed
        return False

    def getTopBlock(self):
        return self.blockchain.blockchain[-1]


mainBlockchain = Blockchain()  # take object from blockChain class
pprint.sorted = lambda x, key=None: x  # here an configuration for pprint lib

Alice = Actor('alice.pem', mainBlockchain)
Bob = Actor('bob.pem', mainBlockchain)
Mahmoud = Miner('mahmoud.pem', mainBlockchain)  # Mahmoud is the miner

listOfPeers = {"Alice": Alice, "Bob": Bob}
listOfMiners = {"Mahmoud": Mahmoud}


mainBlockchain.peers = listOfPeers

listOfGensisTransaction = [{'amount': 50, 'address': Alice.address.hex()},
                           {'amount': 150, 'address': Bob.address.hex()}] # Define the gensis transaction!

mainBlockchain.calcGensisBlock(listOfGensisTransaction, [Alice, Bob]) # Calculate the gensis block
pprint.pprint(Bob.getUserData())



Mahmoud.reward = 2 # setting mining reward

# here a list of transaction to check if every thing is working properly

# Alice send 10 coin to bob and add this transaction to pending transaction
Mahmoud.pendingTransaction.append(Alice.SendCoin(Bob, 10))
Mahmoud.Mining(2) # start mining !!

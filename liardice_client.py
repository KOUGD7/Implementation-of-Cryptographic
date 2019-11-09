# Client to implement simple program to get dice rolled on a server.
# The dice are then printed on the client and the user mkes a bid and
# poses the choice of a bid or challenge to the server.
# Author: D.Delahaye 2018-06-14
# Version: 0.1
#!/usr/bin/python3

import socket
import sys
import random

import math
import time
import simplified_AES
import hashlib

#-----------------------------------------------------------------------
def expMod(b,n,m):
    """Computes the modular exponent of a number returns (b^n mod m)"""
    if n==0:
        return 1
    elif n%2==0:
        return expMod((b*b)%m, n/2, m)
    else:
        return(b*expMod(b,n-1,m))%m


def is_prime(n):
    for i in range(3, n-1):
        if n % i == 0:
            return False
    return True

def gcd(u, v):
    """Iterative Euclidean algorithm"""
    while v:
        u, v = v, u % v
    return abs(u)


def IsValidGenerator(g, p):
    """Validation of generator and prime"""
    """Write code to validate the generator and prime"""
    if is_prime(g) and is_prime(p) and g<p:
        return True
    return False

def sendGeneratorPrime(g,p):
    """Sends server generator"""
    status = "110 Generator: " + str(g) + ", Prime: " + str(p)
    return status

def computeSecretKey(g, p):
    """Computes this node's secret key"""
    secretKey = random.randint(int(g), int(p))
    #return 3
    return secretKey

def computePublicKey(g, p, s):
    """Computes a node's public key"""
    """Complete this function"""
    return expMod(g,s,p)

def computeSessionKey(server_pub, client_secret, p):
    """Computes this node's session key"""
    return expMod(server_pub, client_secret, p)

def sendPublicKey(g, p, s):
    """Sends node's public key"""
    status = "120 PubKey " + str(computePublicKey(g, p, s))
    return status

def generateNonce():
    """This method returns a 16-bit random integer derived from hashing the
        current time. This is used to test for liveness"""
    hash = hashlib.sha1()
    hash.update(str(time.time()).encode('utf-8'))
    return int.from_bytes(hash.digest()[:2], byteorder=sys.byteorder)


# M   = message, an integer
# Pub = receiver's public key, an integer
# p   = prime number, an integer
# gen = generator, an integer
#def encryptMsg(M, Pub, p, gen):
"Method was updated to use AES symetric encyption that was"
"provided in the starter code as option of symetric encrytion using shared secret keys is generated."
def encryptMsg(plaintext, symmetricKey, p, gen):
    """Encrypts a message M given parameters above"""
    simplified_AES.keyExp(symmetricKey)              # Generating round keys for AES.
    ciphertext = simplified_AES.encrypt(plaintext)   # Running simplified AES.
    return ciphertext
   

# C    = second part of ciphertext, an integer
# s    = first part of ciphertext, an integer
# priv = sender's public key, an integer
# p    = prime number, an integer
"Method was updated to use AES symetric decryption that was"
"provided in the starter code as option of symetric encrytion using shared secret keys is generated."
def decryptMsg(C, symmetricKey, priv, p):
    """Decrypt a cipher C given parameters above"""
    simplified_AES.keyExp(symmetricKey)
    plaintext=simplified_AES.decrypt(C)
    return plaintext


# M   = message, an integer
# Pub = receiver's public key, an integer
# p   = prime number, an integer
# gen = generator, an integer
def sendEncryptedMsg(M, Pub, p, gen):
    """Sends encrypted message """
    y1 = encryptMsg(M, Pub, p, gen)
    status = "130 Ciphertext " + str(int(y1))
    return status

def xor(m, k):
    """Given strings m and k of characters 0 or 1,
    it returns the string representing the XOR
    between each character in the same position.
    This means that m and k should be of the same length.
    Use this function both for encrypting and decrypting!"""
    r = []
    for i, j in zip(m, k):
        r.append(str(int(i) ^ int(j)))  # xor between bits i and j
    return "".join(r)
    """Reference: https://codereview.stackexchange.com/questions/116044/
        one-time-pad-algorithm-for-encryption-and-decryption"""

def isBinary(n):
    "check if a number is binary"
    for i in str(n):
        if i in '10':
            b = True
        else:
            b=False
            break
    return b

#---------------------------------------------------------------------------
def serverHello():
    """Generates server hello message"""
    status = "100 Hello message"
    return status

def RollDice():
    """Generates message to get server to roll some or all dice."""
    toRoll = input('Roll all the dice? (y/n): ')
    toRoll = str(toRoll)
    if toRoll == 'y' or toRoll == 'Y':
        status = "200 Roll Dice"
    else:
        status = "You exited the game."
    return status
    
def make_bid(bid, msg):
    """This function processes messages that are read through the socket. It
    determines whether or not the bid made is valid and returns a status.
    """
    """You will need to complete this method """
    #toBid = input('Make Bid? (y/n): ')
    #toBid = str(toBid)
    #if toBid == 'y' or toBid == 'Y':
    status = "300 Bid"
    bid[1] = input('Enter the Value: ')
    bid[1] = str(bid[1]);
    bid[0] = input('Enter the Frequency: ')
    bid[0] = str(bid[0]);
    value = bid[1]
    frequency = bid[0]
    if (int(value)<=6 and int(frequency) <=10) and (int(value)>serverbid[0] or int(frequency)>serverbid[1]):
        return status+' Val: '+value+' Freq: '+frequency
    else:
        print ('Invalid Bid - Server was challenged')
        status= challenge(clientdice, msg)   
        return status


""
def checkBoard(bid):
    "Counts the face equal to the bid's face value and compare the count against the Frequency's Value in the bid"
    ValCount=0
    for x in serverdice:
        if bid[0]==x:
            ValCount=ValCount+1
    for x in clientdice:
        if bid[0]==x:
            ValCount=ValCount+1       
    if ValCount>=bid[1] and bid[1] != 0 :
        return True
    return False

def clientchallenge(clientdice, serverdice):
    "Challenge check the client bid to see if it valid if not Server is the winner"
    if checkBoard(clientbid):
        #status='Client is the Winner !!!! '
        #print(status)
        print("Server roll is: " + ', '.join(str(e) for e in serverdice))
        print("Client's roll is: " + ', '.join(str(e) for e in clientdice))
        status=-1
        return status
    else:
        #status="Server is the Winner !!!! "
        #print(status)
        print("Server roll is: " + ', '.join(str(e) for e in serverdice))
        print("Client's roll is: " + ', '.join(str(e) for e in clientdice))
        status=-1
        return status
    print("Server roll is: " + ', '.join(str(e) for e in serverdice))
    print("Client's roll is: " + ', '.join(str(e) for e in clientdice))


def challenge(c, s):
    """This function processes messages that are read through the socket. It
    receives the client's roll and 0shows the server's roll. It also determines
    whether or not the challenge made is valid and returns a status.
    """
    """You will need to complete this method """
    
    print("Server roll is: " + ', '.join(str(e) for e in s))
    print("Client's roll is: " + ', '.join(str(e) for e in c))
    "Challenge check the client bid to see if it valid if not Server is the winner"
    if checkBoard(serverbid):
        status='Server is the Winner !!!! ' + ', '.join(str(e) for e in s)
        print(status)
        return status
    else:
        status="Client is the Winner !!!! " + ', '.join(str(e) for e in c)
        print(status)
        return status

    #if clientbid > serverbid:
       
    #elif clientbid < serverbid

    #print('Client roll is: ' + ', '.join(str(e) for e in clientdice))
    #print('Opponent\'s roll is: ' + ', '.join(str(e) for e in serverdice))
  



def strToBid(String, Dice):
    "Converts the String in message to integer and store in specified dice array"
    Dice=[]
    for x in String[3:]:
        if x in ['10','1','2','3','4','5','6','7','8','9']:
            Dice.append(int(x))
    return Dice


#Global Variable used to store bids and dices throught the different process msg cycles
clientdice=[]
clientbid=[0,0]
serverdice=[]
serverbid=[0,0]
# s       = socket
# msg     = initial message being processed
def processMsgs(s, msg, state):
    """This function processes messages that are read through the socket. It
        returns a status, which is an integer indicating whether the operation
        was successful"""
    """You will need to complete this method """

    #Retreive and store the values from variable outside of the method
    global clientdice
    global clientbid
    global serverdice
    global serverbid

    msg=bytes.decode(msg)

#---------------------------------------------------------------------------
    status = -2
    gen = int(state['gen'])                     # integer generator
    prime = int(state['prime'])                 # integer prime
    sKey = int(state['SecretKey'])              # secret key
    rcvrPK = int(state['RcvrPubKey'])           # receiver's public key
    nonce = int(state['nonce'])                 # Number used only once
    symmetricKey = int(state['SymmetricKey'])   # shared symmetric key
    
    strTest = serverHello()
    if (strTest in msg and status==-2):
        msg = sendGeneratorPrime(gen,prime)  #Complete this line
        print("Message sent: " + msg)
        s.sendall(bytes(msg, 'utf-8'))
        status = 1
    
    strTest = "111 Generator and Prime Rcvd"
    if (strTest in msg and status==-2):
        #print('g:    ', gen)
        #print('p:    ', prime)
        print('Secret Key: ', sKey)
        msg = sendPublicKey(gen, prime, sKey)  #Complete this line
        s.sendall(bytes(msg, 'utf-8'))
        print('Sent: ',msg)
        status = 1
    
    strTest = "120 PubKey"
    if (strTest in msg and status==-2):
        RcvdStr = msg.split(' ')
        rcvrPK = int(RcvdStr[2])
        nonce = generateNonce()
        while (nonce >= prime):
            nonce = generateNonce()
        SymmKey = computeSessionKey(rcvrPK, sKey, prime)                #Computes Shared key secretly using receiver public key, send secret key and prime
        state['SymmetricKey'] = SymmKey
        "PrintKeys to user"
        print('Client Secret', sKey)
        print('Server public', rcvrPK)
        print('SymmetricKey', SymmKey)
        print("Nonce", nonce)
        msg = sendEncryptedMsg(nonce, SymmKey, prime, gen)              #encrypt msg using shared secret key genarate using Diffie Hellman for AES encrytion
        print("Message sent: " + str(msg))
        s.sendall(bytes(msg, 'utf-8'))
        state['nonce'] = nonce
        state['RcvrPubKey'] = rcvrPK
        status = 1
    
    strTest = "130 Ciphertext"
    if (strTest in msg and status==-2):
        #Pub = computePublicKey(gen, prime, sKey)
        RcvdStr = msg.split(' ')
        y1 = int(RcvdStr[2])
        srvrCtxt = int(RcvdStr[2])
        print("Ciphertext received: " + str(y1))
        dcryptedNonce = decryptMsg(srvrCtxt, symmetricKey, gen, prime)   #decrypt cipher using AES thaen compare with Nonce
        print("Decrypted Ciphertext: " + str(dcryptedNonce))
        if (abs(nonce - dcryptedNonce) == 5):
            print("Final status code: 150 OK")
            msg = "150 OK"
            s.sendall(bytes(msg, 'utf-8'))
            status = 1
            print("Message sent: " + str(msg))
        else:
            print("Final status code: 400 Error")
            status = 0   # To terminate loop at client.
        print("Let's Start........... " )

    "One time pad added for the extra credit. Encrypted Symetric Key from server, decrypt enter generated key manually."
    strTest = "140 One Time Pad"
    if (strTest in msg and status==-2):
        RcvdStr = msg.split(' ')
        Ctxt = RcvdStr[4]                                   #Get Cipher from msg
        print("Onetime pad Cipher",Ctxt)
        while (True):
            key = input('Enter One Time Pad Key, base 2 or 10: ')
            if (isBinary(key)):
                if len(key)==len(Ctxt):
                    plaintext = xor(key, Ctxt)              #Xor decryption
                    break
                print ("Invalid length")
            else:
                key='{0:015b}'.format(int(key))             #Convertion of int to binary
                "".join(format(ord(x), 'b') for x in key)
                plaintext = xor(key, Ctxt)
                break
        if int(plaintext,2)== symmetricKey:
            print("Key is correct. Decrpytion was successful")
        else:
            print("INCORRECT KEY!!!. Key was not decrypted properly")
        print("Plain text/SymmKey  (binary):", plaintext)
        print("Plain text/SymmKey (decimal): ", int(plaintext,2))
        msg = "155 OK"
        s.sendall(bytes(msg, 'utf-8'))
        status = 1
#--------------------------------------------------------------------------- 
    #HELLO & ROLL DICE   
    if msg == "105 Hello message":
 
        print('105 Received: ',msg )
        roll = RollDice()
        # Add code to send data into the socket
        data=str.encode(roll)
        s.sendall(data)
        status = 1

              
    #BID
    if "205 Roll" in msg:                            #Receive the rolled dice from server
        clientdice=strToBid(msg, clientdice)
                
        print('205 Received: ',msg )
        print ("Client Roll: ", clientdice)
        bid=[0,0]
        bid = make_bid(bid, msg)
        # Add code to send data into the socket
        data=str.encode(bid)
        s.sendall(data)
        clientbid=strToBid(bid, clientbid)
        #print('Please wait on Server response ....')
        status = 1

    if "Challenge" in msg:
        print('Challenge Received: ',msg)
        #serverdice=strToBid(msg, serverdice)
        chal=clientchallenge(clientdice, serverdice)
        data=str.encode(chal)
        s.sendall(data)
        status = -1

    if ("305 Bid ACK" and ",") in msg:
        #print ("Test Message received: ",msg )
        serverdice=strToBid(msg, serverdice)            #msg to dice
        #print(" TEST serverdice", serverdice)
        #msg='305 Bid ACK'
        #print('305 Received: ',msg )
        status = 1
        

    if "305 Bid ACK" and 'Val' in msg:
        print('Received: ',msg )
        serverbid=strToBid(msg, serverbid)

        query = input('Enter c to Challenge or b to Bid ')
        query=str(query)
        if query == 'b' or query == 'B':
            bid=[0,0]
            bid=make_bid(bid, msg)
            data=str.encode(bid)
            s.sendall(data)
            clientbid=strToBid(bid, clientbid)
            print (clientbid)
            status = 1
        else:
        #elif query == 'c' or 'C':
            chal=challenge(clientdice, serverdice)
            data=str.encode(chal)
            s.sendall(data)
            status = 1
        #print (serverdice)
        #print (serverbid)
        #print (clientdice)
        #print (clientbid)
        status = 1
        
    if 'Winner' in msg: 
        print ('Server challenge your bid. \n'+ msg)
        print ('Client Roll: ' +', '.join(str(e) for e in clientdice)) 
        print ('Server Roll: ' +', '.join(str(e) for e in serverdice))
        
        status = -1
    return status
    #pass



def main():
    """Driver function for the project"""
    args = sys.argv

    #if len(args) != 3:
    #    print ("Please supply a server address and port.")
    #    sys.exit()
    #serverHost = str(args[1])          # The remote host
    #serverPort = int(args[2])          # The same port as used by the server


    serverHost = 'localhost'            # The remote host
    serverPort = 12001                  #The same port as used by the server
        
    print("\nClient of Goldson")
    print('''
      The dice in this program have a face value in the range 1--6.
    No error checking is done, so ensure that the bids are in the correct range.
    Follow the on-screen instructions.
    ''')

#-----------------------------------------------------------------------
    random.seed()
    while (True):
        prime = int(input('Enter a valid prime between 1024 and 65536: '))
        generator = int(input('Enter a positive prime integer less than the prime just entered: '))
        if (IsValidGenerator(generator, prime)):
        #if generator < prime:
            print('Valid')
            break
        print('Not Valid')
    nonce = generateNonce()
    
    # To ensure that the nonce can always be encrypted correctly.
    while (nonce >= prime):
        nonce = generateNonce()
    # Bogus values that will be overwritten with values read from the socket.
    secretKey = computeSecretKey(generator, prime)
    rcvrPK = 60769
    symmKey = 32767
    state = {'prime': prime, 'gen': generator, 'SecretKey': secretKey,
    'RcvrPubKey': rcvrPK, 'nonce': nonce, 'SymmetricKey': symmKey}

#--------------------------------------------------------------------------- 
    clientSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)# Add code to initialize the socket
    clientSocket.connect((serverHost, serverPort))

    hello = serverHello()
    # Add code to send data into the socket
    data=str.encode(hello)
    clientSocket.sendall(data)          #encode hello and send

    

    
    # Handle the data that is read through the socket by using processMsgs(s, msg)
    status = 1 
    while (status == 1):
        print ('Waiting on Server response..........')
        msg = clientSocket.recv(1024)                   #message for client
        if not msg:                                     #If there is no message then the status change to -1 to end while loop
            status = -1
            #print("not a message")
        else:
            status = processMsgs(clientSocket, msg, state)     #if there is a message then the socket and the message is processed
        if status < 0:
            print("Invalid data received. Closing")
            input('Press any ENTER to continue')
            clientSocket.close()
            print("Closed connection socket")    
    # Close the socket.  
    
if __name__ == "__main__":
    main()

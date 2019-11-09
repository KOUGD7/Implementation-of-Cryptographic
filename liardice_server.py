# Server to implement simple program to get dice rolled on a server.
#  The dice values are then sent through a socket and printed on the client.
#  The user is given a choice of getting some of the dice rolled again.
# Author: fokumdt 2017-10-02
# Version: 0.1
#!/usr/bin/python3
 
import socket
import sys
import random

import math
import hashlib
import time
import simplified_AES

from random import choice
import string

#---------------------------------------------------------------------
def expMod(b,n,m):
    """Computes the modular exponent of a number"""
    """returns (b^n mod m)"""
    if n==0:
        return 1
    elif n%2==0:
        return expMod((b*b)%m, n/2, m)
    else:
        return(b*expMod(b,n-1,m))%m



def gcd_iter(u, v):
    """Iterative Euclidean algorithm"""
    while v:
        u, v = v, u % v
    return abs(u)


def genKeys(p, q):
    """Generate n, phi(n), e, and d."""
    n = p * q
    phi = (p-1)*(q-1)
    #e = findE(phi, p, q)
    e = findE(phi)
    
    d = ext_Euclid(phi, e) #Using the extended Euclidean algorithm to compute d
    if (d < 0):
        d += phi
    print ("n = "+ str(n))
    print ("phi(n) = "+ str(phi))
    print ("e = "+ str(e))
    print ("d = "+ str(d))
    print
    return n, e, d   



def computePublicKey(g, p, s):
    return expMod(g,s,p)
    """expMod(b,n,m) returns (b^n mod m)"""

def sendPublicKey(g, p, s):
    """Sends node's public key"""
    status = "120 PubKey " + str(computePublicKey(g, p, s))
    return status

        
def gcd(x, y):
    while y:
        x, y = y, x % y
    return abs(x)
  

def computeSecretKey(g, p):
    """Computes this node's secret key."""
    """You will need to implement this function."""
    return random.randint(1, p-1)


def computeSessionKey(client_pub, server_secret, p):
    """Computes this node's session key"""
    return expMod(client_pub, server_secret, p)


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
def DHencrypt(plaintext, symmetricKey, p, gen):
    """Encrypts a message M given parameters above"""
    "Method was updated to use AES symetric decryption that was"
    "provided in the starter code as option of symetric encrytion using shared secret keys is generated."
    simplified_AES.keyExp(symmetricKey)              # Generating round keys for AES.
    ciphertext = simplified_AES.encrypt(plaintext)   # Running simplified AES.
    return ciphertext



# C    = second part of ciphertext, an integer
# s    = first part of ciphertext, an integer
# priv = receiver's secret key, an integer
# p    = prime number, an integer
"""Decrypt a cipher C given parameters above"""
"Method was updated to use AES symetric decryption that was"
"provided in the starter code as option of symetric decrytion using shared secret keys is generated."
def DHdecrypt(C, symmetricKey, priv, p):
    simplified_AES.keyExp(symmetricKey)
    plaintext=simplified_AES.decrypt(C)
    return plaintext

def clientHello():
    """Generates client hello message"""
    status = "100 Hello"
    return status


# M   = message, an integer
# Pub = receiver's public key, an integer
# p   = prime number, an integer
# gen = generator, an integer
def sendEncryptedMsg(M, Pub, p, gen):
    """Sends encrypted message """
    #y1, y2 = encryptMsg(M, Pub, p, gen)
    y1 = DHencrypt(M, Pub, p, gen)
    
    status = "130 Ciphertext " + str(int(y1))
    return status

def nonceVerification(nonce, decryptedNonce):
    """Verifies that the transmitted nonce matches that received
       from the client."""
    if (nonce == decryptedNonce):
        status = "150 OK"
    else:
        status = "400 Error"
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
#---------------------------------------------------------------------

def clientHello():
    """Generates client hellko message"""
    status = "100 Hello message"
    return status

#Use with string value of dice
def RollDiceACK(dice):
    """Sends client their rolled dice"""
    #strDice = ','.join([str(x) for x in dice])
    #status = "205 Roll Dice ACK " + strDice
    status = "205 Roll Dice ACK " + dice
    return status

def bidACK(dice, query):
    """Generates message with query"""
    status=""
    strDice = ','.join([str(x) for x in dice])
    if query == 'b' or query=='B':
        status = "305 Bid ACK " + strDice
    elif query == 'c' or query=='C':
        status = "305 Bid ACK Challenge. Server roll: " +strDice
    #print ("TEST", status)
    return status

def rollDice(dice, toRoll=[0,1,2,3,4]):
    """Rolls the dice."""
    randomText = " "
    for i in toRoll:
        dice[i] = random.randint(1,6)
        strDice = str(dice[i])
        randomText += strDice + ', '
        randomText.rstrip(', ')
    return randomText


#Request the value and frequency. Clallenges when the bid doesnt fulfil critera
def make_bid(bid, msg):
    """This function processes messages that are read through the socket. It
    determines whether or not the bid made is valid and returns a status.
    """"""You will need to complete this method """
    msg = msg.split(' ')
    frequency = bid[0]
    value = bid[1]
    status = "305 Bid ACK"
    bid[1] = input('Enter the Value: ')
    bid[1] = str(bid[1]);
    value = bid[1]
    bid[0] = input('Enter the Frequency: ')
    bid[0] = str(bid[0]);
    frequency = bid[0]
    if (int(value)<=6 and int(frequency) <=10) and (int(value)>clientbid[0] or int(frequency)>clientbid[1]):
        return status+' Val: '+value+' Freq: '+frequency
    else:
        print ('Invalid Bid - Client was challenged')
        status= challenge(', '.join(str(e) for e in serverdice), ', '.join(str(e) for e in clientdice), msg)   
        return status



#Counts the value for a given bid and compare to its frequency
def checkBoard(bid):
    ValCount=0
    for x in serverdice:
        if bid[0]==x:
            ValCount=ValCount+1
    for x in clientdice:
        if bid[0]==x:
            ValCount=ValCount+1       
    if ValCount>=bid[1]:
        return True
    return False

#Print the rolls and winner based on the client bid
def challenge(roll, clientRoll, msg):
    print("Server roll is: " + roll)
    print("Client's roll is: " + clientRoll)
    """This function processes messages that are read through the socket. It
    receives the client's roll and shows the server's roll. It also determines
    whether or not the challenge made is valid and returns a status.
    """
    """You will need to complete this method """
    if checkBoard(clientbid):
        status="Client is the Winner !!!!. Client roll:  "+', '.join(str(e) for e in clientdice)
        print(status)
        return status
    else:
        status="Server is the Winner !!!!. Server Roll:  "+', '.join(str(e) for e in serverdice)
        print(status)
        return status

#Convert String to list range 1-6
def strToDice(String, Dice):
    for x in String:
        if x in ['1,','2,','3,','4,','5,','6,']:
            Dice.append(int(x[0]))
    return Dice

#Convert String to list bid range 1-10
def strToBid(String, bid):
    bid=[]
    for x in String[3:]:
        if x in ['10','1','2','3','4','5','6','7','8','9']:
            bid.append(int(x))
    return bid


#store the roll until the challenge phase
clientdice=[0,0,0,0,0]
clientbid=[0,0]
serverdice=[0,0,0,0,0]
serverbid=[0,0]

def processMsgs(s, msg, state):
# s      = socket
# msg     = initial message being processed  
    """This function processes messages that are read through the socket. It
        returns a status, which is an integer indicating whether the operation
        was successful"""
    """You will need to complete this method """

    global clientdice
    global clientbid
    global serverdice
    global serverbid
    
#---------------------------------------------------------------------------
    status = -2
    gen = int(state['Gen'])                     # integer generator
    prime = int(state['prime'])                 # integer prime
    sKey = int(state['SecretKey'])              # secret key
    rcvrPK = int(state['RcvrPubKey'])           # receiver's public key
    nonce = int(state['Nonce'])
    symmetricKey = int(state['SymmetricKey'])   # shared symmetric key
        
    strTest = clientHello()
    if strTest in msg and status == -2:
        print("Message received: "+ msg)
        msg = clientHello()
        s.sendall(bytes(msg,'utf-8'))
        print ('Sent',msg)
        status = 1
    
    strTest = "110 Generator:"
    if strTest in msg and status == -2:
        print("Message received: "+ msg)
        RcvdStr = msg.split(' ')
        gen = int(RcvdStr[2][0:-1])
        prime = int(RcvdStr[4])
        sKey = computeSecretKey(gen, prime)     #Computes Shared key secretly using receiver public key, send secret key and prime
        msg = "111 Generator and Prime Rcvd"
        s.sendall(bytes(msg, 'utf-8'))
        print("Message sent: "+ msg)
        state['Gen'] = gen
        state['prime'] = prime
        state['SecretKey'] = sKey
        status = 1

    strTest = "120 PubKey"
    if strTest in msg and status == -2:
        print("Message received: " + msg)
        RcvdStr = msg.split(' ')
        rcvrPK = int(RcvdStr[2])
        #print('g:    ', gen)
        #print('p:    ', prime)
        print('Secret Key: ', sKey)
        msg = sendPublicKey(gen, prime, sKey)   # Complete this
        print("Message sent: " + str(msg))
        s.sendall(bytes(msg, 'utf-8'))
        state['RcvrPubKey'] = rcvrPK
        status = 1
    
    strTest = "130 Ciphertext"
    if strTest in msg and status == -2:
        print("Message received: " + str(msg))
        Pub = rcvrPK                            
        RcvdStr = msg.split(' ')
        y1 = int(RcvdStr[2])
        clntCtxt = int(RcvdStr[2])
        SymmKey = computeSessionKey(rcvrPK, sKey, prime)
        state['SymmetricKey'] = SymmKey
        print('Server Secret', sKey)
        print('Client public', rcvrPK)
        print('SymmetricKey', SymmKey)
        dcryptedNonce = DHdecrypt(clntCtxt, SymmKey, gen, prime)        #decrypt msg using shared secret key genarate using Diffie Hellman for AES encrytion
        print("Decrypted Ciphertext: ", dcryptedNonce)
        dcryptedNonce = dcryptedNonce-5
        msg = sendEncryptedMsg(dcryptedNonce,SymmKey, gen, prime)   
        s.sendall(bytes(msg, 'utf-8'))
        print("Message sent: " + msg)
        status = 1 # To terminate loop at server.
        print("Let's Start........... " )

    strTest = "150 OK"
    if strTest in msg and status == -2:
        BsymmetricKey = '{0:015b}'.format(symmetricKey)
        """Converts string s to a string containing only 0s or 1s, representing the original string."""
        "".join(format(ord(x), 'b') for x in BsymmetricKey)
        
        """Generates a random key of bits (with 0s or 1s) of length n"""
        k = []
        for i in range(len(BsymmetricKey)):
            k.append(choice(["0", "1"]))
        gen_random_key = "".join(k)
        cipher = xor(BsymmetricKey, gen_random_key)
        print("Plain Text(SymmKey)   : ", BsymmetricKey)
        print("Generated Key(Binary) : ", gen_random_key)
        print("Generated Key(decimal): ", int(gen_random_key,2))
        print("Cipher Text           : ", cipher)
        msg = "140 One Time Pad: " +  cipher
        s.sendall(bytes(msg, 'utf-8'))
        print ("Message sent: ", msg)
        status = 1   
#---------------------------------------------------------------------------

    #process hello message
    strTest = "155 OK"
    if strTest in msg and status == -2:
    #if msg == "105 OK":
        print('Received: ',msg)                 

        hello = "105 Hello message"                   
        data=str.encode(hello)
        s.sendall(data)  
        status = 1               

    #process roll dice message  
    if msg == "200 Roll Dice":
        print('Received: ',msg)
        
        #Roll Client Die, assign to global variable and send to client
        clientDiceStr=rollDice(clientdice, toRoll=[0,1,2,3,4])       
        clientdice = strToDice(clientDiceStr, clientdice)#Collect dice roll for msg
        rDice = RollDiceACK(clientDiceStr)
        data=str.encode(rDice)
        s.sendall(data)

        #Roll Server Die and assign to global variable
        ServerDiceStr=rollDice(serverdice, toRoll=[0,1,2,3,4])
        serverdice=strToDice(ServerDiceStr, serverdice)#Collect dice roll for msg
        print('Server Roll: ', serverdice)
        
        status = 1

    #process bid message
    if "300 Bid" in msg:                            
        print('Received: ',msg)

        #store client bid for challenge phase (comparison)
        clientbid=strToBid(msg,clientbid)
   

        #Server Challenges or Bid
        query = input('Enter c to Challenge or b to Bid ')
        bidAck= bidACK(serverdice, query)
        data=str.encode(bidAck)
        s.sendall(data)
        
        if query == 'b' or query == 'B':
            bid=[0,0]
            bid=make_bid(bid, msg)
            data=str.encode(bid)
            s.sendall(data)
            serverbid=strToBid(bid,serverbid)
            #print('Please wait on client response ....')
            status = 1
        else:
        #Challenge Client
            chal=challenge(', '.join(str(e) for e in serverdice), ', '.join(str(e) for e in clientdice), msg)
            data=str.encode(chal)
            s.sendall(data)
            #print('Message sent: ',chal)
            status = 0
        #Test if info is stored
        #print (serverdice)
        #print (serverbid)
        #print (clientdice)
        #print (clientbid)
        status = 1
        
    if 'Winner' in msg:
        print ('Client challenge your bid. \n'+ msg)
        print ('Server Roll: ' +', '.join(str(e) for e in serverdice))
        print ('Client Roll: ' +', '.join(str(e) for e in clientdice))       
        
        status = -1

    return status
  
    

def main():
    """Driver function for the project"""
    args = sys.argv
    
    #if len(args) != 2:
    #    print ("Please supply a server port.")
    #    sys.exit()
    HOST = ''                # Symbolic name meaning all available interfaces
    #PORT = int(args[1])

    PORT = 12001
         # The port on which the server is listening
    if PORT < 1023 or PORT > 65535:
        print("Invalid port specified.")
        sys.exit()

#--------------------------------------------------------------------------

# Initializing generator, prime, secret key, and receiver's public key with
    # bogus values. The actual values will come from values read from the socket
    generator = 3
    prime = 127
    secretKey = computeSecretKey(generator, prime)
    rcvrPK = 5     # Initial value for receiver's public key
    nonce = generateNonce()
    
    #bids = 0
    symmKey = 32767
    state = {'Gen': generator, 'prime': prime, 'SecretKey': secretKey,
     'RcvrPubKey': rcvrPK, 'Nonce': nonce, 'SymmetricKey': symmKey}

        
#--------------------------------------------------------------------------       
    print("\nServer of Goldson")
    '''Specify socket parameters to use TCP'''        
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind((HOST,PORT))# Bind socket
        s.listen(1)# listen
        conn, addr = s.accept() # accept connection using socket
        with conn:
            print('Connected by', addr)
            status = 1
            while (status == 1):
                print ('Waiting on Client response..........')
                msg = conn.recv(1024).decode('utf-8')   #message for client
                if not msg:                             #If there is no message then the status change to -1 to end while loop
                    status = -1
                else:
                    status = processMsgs(conn, msg, state)     #if there is a message then the socket and the message is processed
            if status < 0:
                print("Invalid data received. Closing")
                input('Press any ENTER to continue')
            conn.close()
            print("Closed connection socket")    

if __name__ == "__main__":
    main()

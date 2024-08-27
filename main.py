import sys
import threading
import subprocess
import time
import os
import queue
import secrets
import hashlib
import base64
import scapy
from scapy.all import sniff, ICMP, IP, send
import tkinter as tk
from cryptography.fernet import Fernet
from sympy import isprime, primerange
from ipaddress import ip_interface, ip_network
import netifaces
import socket
from colorama import init, Fore

sys.argv += ['--no-qt-log']
init()

class ICMPController():
    # only code 1 and code 55 will be used, 1 for sentinel and 55 for msg
    def __init__(self,IPAddr,EncrypterObject,connectedUser):
        self.connectedIP = IPAddr
        self.connectedUsername = connectedUser
        self.encryptionModule = EncrypterObject

    def sendICMP(self,msg):
        msg = '$chatMsg:'+msg
        packet = IP(dst=self.connectedIP)/ICMP(type=0,code=55)/msg
        send(packet, verbose=False)

    def stopSniffing(self,packet):
        if packet.haslayer(ICMP):
            if packet[ICMP].type == 0 and packet[ICMP].code == 1:
                # sentinel packet found, stop
                return True

    def packetFilter(self,packet):
        if packet.haslayer(ICMP):
            if packet[ICMP].type==0 and packet[ICMP].code>0:
                # packet sent by the app detected!
                return True
        return False

    def packet_found(self,packet):
        if packet.haslayer(ICMP) and packet[IP].src == self.connectedIP:
            if packet[ICMP].code==55:
                # 55 is the code for every message

                packetLoad = packet.payload.payload.load.decode() # i need the packet payload here

                if len(packetLoad.split(':')) != 2:
                    print(Fore.RED+"ERROR! - Incorrect ICMP packet received. (Not usual)"+Fore.RESET)
                    return

                packetCode = packetLoad.split(':')[0]
                packetData = packetLoad.split(':')[1]
                if packetCode == "$chatMsg":
                    # packetData contains the message
                    print(Fore.CYAN+self.connectedUsername+": "+self.encryptionModule.decryptMessage(packetData)+Fore.RESET)

    def sendSentinel(self): # code 1 is for sentinel packets, which will help in terminating the network sniff
        packet = IP(dst='0.0.0.0')/ICMP(type=0,code=1)/"sentinel packet - ignore"
        send(packet, verbose=False)

    def startSniffing(self):
        icmpListenThread = threading.Thread(target=self.sniffICMP)
        icmpListenThread.start()

    def sniffICMP(self):
        sniff(filter="icmp", prn=self.packet_found, lfilter=self.packetFilter, store=False, stop_filter=self.stopSniffing)

class DFH():
    def __init__(self,destIP,initiator,connectedUser): # initiater specifies whether you iniated the convo or was it the other person? (True|False)
        self.icmpConn = None
        self.success = None
        self.listenSock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.startListening()
        print(Fore.BLUE+"* Establishing connection..."+Fore.RESET)
        self.__prime = -1
        self.generator = 5 # usually 2 or 5 is used as generator numbers
        self.__key = -1
        self.__pvtNum = None
        self.recvPartialKey = None
        self.publicNumsRecv = threading.Event()
        self.partialKeyRecv = threading.Event()
        self.IPAddr = self.getIPAddr()

        if initiator:
            print(Fore.BLUE+"-- Generating safe prime number..."+Fore.RESET)
            self.__prime = self.generatePrime()
            print(Fore.BLUE+"-- Prime number generated!"+Fore.RESET)
            send_public_nums_thread = threading.Thread(target=self.sendPublicNums, args=(destIP,))
            send_public_nums_thread.start()
            send_public_nums_thread.join()
            if self.success ==  False:
                self.listenSock.close()
                return

        else:
            print(Fore.BLUE+"-- Waiting for prime number..."+Fore.RESET)
            while not self.publicNumsRecv.is_set():
                # receiver is waiting for the sender to send pub nums
                pass
            print(Fore.BLUE+"-- Prime number received!"+Fore.RESET)

        print(Fore.BLUE+"-- Generating private number..."+Fore.RESET)
        self.__pvtNum = self.generatePrivate()
        print(Fore.BLUE+"-- Private number generated!"+Fore.RESET)
        print(Fore.BLUE+"-- Generating Partial Key..."+Fore.RESET)
        self.partialKey = pow(self.generator,self.__pvtNum,self.__prime)
        print(Fore.BLUE+"-- Partial Key generated!"+Fore.RESET)

        send_partial_key_thread = threading.Thread(target=self.sendPartialKey, args=(destIP,))
        send_partial_key_thread.start()
        send_partial_key_thread.join()
        while self.recvPartialKey == None:
            # now im waiting for the partial key
            pass

        self.generateKey(self.recvPartialKey)

        if self.success == False:
            self.listenSock.close()
            return

        while not self.partialKeyRecv.is_set():
            pass

        print(Fore.BLUE+"* Connection established!"+Fore.RESET)
        
        self.success = True
        self.listenSock.close()
        self.encryptionModule = Encrypt(self.__key)
        self.icmpConn = ICMPController(destIP,self.encryptionModule,connectedUser)

        self.icmpConn.startSniffing()


    def startListening(self):
        broadcastThread = threading.Thread(target=self.listenBroadcast)
        broadcastThread.start()

    def listenBroadcast(self):
        self.listenSock.bind(('', 51000))

        while True:
            msg = ''
            addr = ''
            try:
                msg, addr = self.listenSock.recvfrom(1024)
            except socket.error:
                break
            addr = addr[0]
            if addr == self.IPAddr:
                continue
            msg = msg.decode()
            if msg.find('!chatupDFH') == 0:
                # "!chatupDFH" is the first word found in the msg received
                responseList = msg.split(':')
                responseCode = responseList[1]
                if responseCode == '$publicNums':
                    # the sender is sending the public nums
                    self.__prime = int(responseList[2]) # this is the prime num
                    self.generator = int(responseList[3]) # this is the generator
                    self.sendBroadcast('$publicNumsACK')
                    self.publicNumsRecv.set()

                elif responseCode == '$publicNumsACK':
                    # the sender got the public nums, they sent the ack
                    if not self.publicNumsRecv.is_set():
                        self.publicNumsRecv.set()
                    else:
                        # if this ever happens, it means, that the publicNumsRecv flag was already set, but still got a packet
                        pass
                    pass

                elif responseCode == '$partialKey':
                    # the sender is sending the partial key
                    if self.__key != -1:
                        continue
                    self.recvPartialKey = int(responseList[2])
                    self.sendBroadcast('$partialKeyACK')
                    pass

                elif responseCode == '$partialKeyACK':
                    # they got the partial key, they sent back an ACK
                    self.partialKeyRecv.set()

            else:
                continue

    def getIPAddr(self):
        interfaceAddr = netifaces.gateways()['default'][netifaces.AF_INET][1]
        IPAddr = netifaces.ifaddresses(interfaceAddr)[netifaces.AF_INET][0]['addr']
        return IPAddr

    def sendBroadcast(self, taskName, taskData=""):
        self.sendSock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sendSock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        self.sendSock.bind((self.IPAddr,0))

        # this is the broadcast message crafted
        msg = "!chatupDFH:"+taskName
        if taskData != "":
            msg+=":"+taskData
        
        self.sendSock.sendto(msg.encode(), ('<broadcast>', 51000))
        self.sendSock.close()

    def sendPartialKey(self,destIP):
        print(Fore.BLUE+"-- Sending partial key abroad..."+Fore.RESET)

        for _ in range(3):
            self.sendBroadcast('$partialKey',str(self.partialKey))
            countdown_recvPartialKeyACKCountdown = threading.Thread(target=self.timerCountdown, args=(5,'partialKey'))
            countdown_recvPartialKeyACKCountdown.start()
            countdown_recvPartialKeyACKCountdown.join()
            if self.partialKeyRecv.is_set():
                print(Fore.BLUE+"-- Partial key sent."+Fore.RESET)
                return

            print(Fore.BLUE+"-- Trying again..."+Fore.RESET)
        print(Fore.RED+"-- Error sending partial key, check network and try later!"+Fore.RESET)
        self.success = False

    def generateKey(self,partialKey):
        self.__key = pow(partialKey,self.__pvtNum,self.__prime)

    def timerCountdown(self,timer,whatToCheck):
        while(timer>0):
            if whatToCheck == 'publicNum':
                if self.publicNumsRecv.is_set():
                    return
            elif whatToCheck == 'partialKey':
                if self.partialKeyRecv.is_set():
                    return
            time.sleep(1)
            timer-=1

    def sendPublicNums(self,destIP):
        print(Fore.BLUE+"-- Sending prime number abroad..."+Fore.RESET)
        # now before i send this packet i need to start another thread to look for the response of this packet
        for _ in range(3):
            self.sendBroadcast('$publicNums',str(self.__prime)+":"+str(self.generator))
            countdown_recvPublicACKCountdown = threading.Thread(target=self.timerCountdown, args=(5,'publicNum'))
            countdown_recvPublicACKCountdown.start()
            countdown_recvPublicACKCountdown.join()
            if self.publicNumsRecv.is_set():
                print(Fore.BLUE+"-- Prime number sent."+Fore.RESET)
                return
        
            print(Fore.BLUE+"-- Trying again..."+Fore.RESET)

        print(Fore.RED+"-- Error sending prime number, check network and try later!"+Fore.RESET)
        self.success = False
        
    def generatePrime(self):
        while True:
            num = secrets.randbits(2048)
            num |= (1 << 2048 -1) | 1
            if isprime(num):
                return num

    def generatePrivate(self):
        return secrets.randbelow(self.__prime - 1)


class Encrypt:
    def __init__(self,symmKey):
        self.byteKey = symmKey.to_bytes((symmKey.bit_length()+7)//8, byteorder='big')
        self.hashKey = hashlib.sha256(self.byteKey).digest()
        self.key = base64.urlsafe_b64encode(self.hashKey)
        self.__f = Fernet(self.key)

    def encryptMessage(self,message):
        return self.__f.encrypt(message.encode()).decode()

    def decryptMessage(self,message):
        return self.__f.decrypt(message.encode()).decode()
            

class Instance():
    def __init__(self):
        self.dfhKey = None
        self.listenSock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.startListening()
        self.username = ""
        self.activeState = False
        self.connectedUser = False
        self.connectedUsername = ""
        self.connectedIP = ""
        self.IPAddr = self.getIPAddr()
        self.userList = {}
        self.userActiveList = {}
        self.userChatReqRecv = []
        self.userChatReqSent = []

    def startListening(self):
        broadcastThread = threading.Thread(target=self.listenBroadcast)
        broadcastThread.start()

    def listenBroadcast(self):  # when do i start this functionnn!!?? AAAAAAA T_T (in a seperate thread)
        self.listenSock.bind(('', 50000))

        while True:
            msg = ''
            addr = ''
            try:
                msg, addr = self.listenSock.recvfrom(1024)
            except socket.error:
                break
            addr = addr[0]
            if addr == self.IPAddr:
                continue
            # getting the network here, deal with it :)
            msg = msg.decode()
            if msg.find('!chatup') == 0:
                # "!chatup" is the first word found in the msg received
                responseList = msg.split(':')
                responseCode = responseList[1]
                broadcastSender = responseList[2]

                if responseCode == '$namecheck':
                    # case 2 - check if you got this name, if yes, send a personal icmp message to them, else ignore
                    if self.username == broadcastSender:
                        # we got same names, not allowing you
                        self.sendBroadcast('$duplicatename')
                       
                elif responseCode == '$duplicatename':
                    # if we receive this, we set our name back to ""
                    if broadcastSender == self.username:
                        print(Fore.RED+"ERROR: Someone in your network got the same name. Use a different name."+Fore.RESET)
                        self.username = ""

                elif responseCode == '$userlist':
                    if responseList[3] == "True":
                        # now update the user list to put this user too
                        self.userList[broadcastSender] = addr
                        # update the activeUserList too
                        self.userActiveList[broadcastSender] = "Active"

                    else:
                        self.userActiveList[broadcastSender] = "Inactive"

                    # now we send our name back to the user if we active
                    if self.activeState == True:
                        self.sendBroadcast('$meactive',self.activeState) #this is the broadcast wayy
                        
                elif responseCode == '$meactive':
                    # the user is active, update the list, thats all
                    if responseList[3] == "True":
                        self.userList[broadcastSender] = addr
                        self.userActiveList[broadcastSender] = "Active"

                elif responseCode == '$connrequest':
                    if responseList[3] == self.username:
                        # ok yes this is for me
                        if not (broadcastSender in self.userList.keys()):
                            self.userList[broadcastSender] = addr
                        if not (broadcastSender in self.userActiveList.keys()):
                            self.userActiveList[broadcastSender] = "Active"

                        self.userChatReqRecv.append(broadcastSender)
                        print(Fore.BLUE+"Chat request received from \""+str(broadcastSender)+"\"!"+Fore.RESET)

                elif responseCode == '$connresponse':
                    # this will contain the answer to the connrequest packet
                    connUser = responseList[3]
                    connAccept = responseList[4]
                    
                    if connUser == self.username:
                        # ok yes this is for me
                        if broadcastSender in self.userChatReqSent:
                            self.userChatReqSent.remove(broadcastSender)
                            if connAccept == "true":
                                self.connectedUser = True
                                self.connectedUsername = broadcastSender
                                self.connectedIP = self.userList[broadcastSender]
                                print(Fore.BLUE+str(broadcastSender)+" accepted your chat request!"+Fore.RESET)
                                self.sendBroadcast('$startdfh',str(broadcastSender))
                                self.initChat(addr, True)
                                

                elif responseCode == '$terminate':
                    # this will be used when we are disconnecting the user, are we expecting a reply? im not sure
                    connUser = responseList[3]
                    if connUser == self.username:
                        if self.dfhKey != None:
                            self.dfhKey.icmpConn.sendSentinel()
                            self.dfhKey = None
                        self.connectedUser = False
                        self.connectedUsername = ""
                        self.connectedIP = ""
                        print("Diconnected!")
                        

                elif responseCode == '$startdfh':
                    # this means that the connres is sent, and in response
                    # this is sent, to start the dfh on the receiver side
                    connUser = responseList[3]
                    if connUser == self.username:
                        self.initChat(addr, False)

            else:
                continue

    def connreqdialog(self,reqUser,app):
        print(Fore.BLUE+"Incoming request from \""+str(reqUser)+"\". Accept? [y/n] "+Fore.RESET,end='')
        acceptUser = input().lower()
        if acceptUser == 'y':
            # accepted
            # i need to send a response? that i accepted it?
            print(Fore.GREEN+"Request accepted!"+Fore.RESET)
            pass
        elif acceptUser == 'n':
            print(Fore.RED+"Request rejected!"+Fore.RESET)
            pass
        else:
            # rejected 
            # i need to send a reponse? that i rejected it?
            print(Fore.RED+"Incorrect response. Request rejected!"+Fore.RESET)
            pass

    def getIPAddr(self):
        interfaceAddr = netifaces.gateways()['default'][netifaces.AF_INET][1]
        IPAddr = netifaces.ifaddresses(interfaceAddr)[netifaces.AF_INET][0]['addr']
        return IPAddr

    def sendBroadcast(self, taskName, taskData=""):
        self.sendSock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sendSock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)

        self.sendSock.bind((self.IPAddr,0))

        # this is the broadcast message crafted
        msg = "!chatup:"+taskName+":"+self.username
        if taskData != '':
            msg += ":"+str(taskData)
        
        self.sendSock.sendto(msg.encode(), ('<broadcast>', 50000))
        self.sendSock.close()


    def startInstance(self):
        while True:
            cmd = input(">>> ").lower()

            if type(cmd) != str:
                print(Fore.RED+"ERROR: Only string inputs are valid!"+Fore.RESET)
                print(Fore.RED+"Use /help to see a full list of commands! "+Fore.RESET)
                continue

            if cmd == '/exit':
                self.listenSock.close()
                if self.dfhKey != None:
                    self.dfhKey.icmpConn.sendSentinel()
                break

            elif cmd == '/help':
                self.displayHelp()

            elif cmd == '/listusers':
                if self.activeState == False:
                    print(Fore.RED+"ERROR: You need to set yourself as active first to get active users list."+Fore.RESET)
                    continue

                if self.username == "":
                    print(Fore.RED+"ERROR: You need to set a name first to get active users list"+Fore.RESET)
                    continue

                activeUserList = self.listActiveUsers() # str[]

                if len(activeUserList) == 0:
                    print(Fore.RED+"ERROR: There are currently no active users on your network!"+Fore.RESET)
                    continue

                print("Active user(s) in your network:")
                for userIdx in range(len(activeUserList)):
                    print(str(userIdx+1)+".","\t",activeUserList[userIdx])

            elif cmd == '/name':
                if self.username == "":
                    print(Fore.RED+"ERROR: You've not set a username yet. Set your name using the command \"/setname <username>\""+Fore.RESET)
                else:
                    print("Your username is:",self.username)

            elif cmd == '/disconnect':
                if self.connectedUser ==  False:
                    print(Fore.RED+"ERROR: You're not connected to any user!"+Fore.RESET)
                    continue

                self.sendBroadcast('$terminate',str(self.connectedUsername))
                self.connectedUser = False
                self.connectedUsername = ""
                self.connectedIP = ""
                self.dfhKey.icmpConn.sendSentinel()
                print("Succesfully disconnected!")

            elif cmd == '/listreq':
                # list all users who've sent you a chat request, all of history, untill the req is accepted/rejected
                if len(self.userChatReqRecv) == 0:
                    print("No pending connection requests.")
                    continue
                    
                print("Pending connection request(s):")
                for connReqIdx in range(len(self.userChatReqRecv)):
                    print(str(connReqIdx+1)+".","\t",self.userChatReqRecv[connReqIdx])


            elif cmd.split(' ')[0] == '/setname': #done?
                if len(cmd.split(' ')) != 2:
                    print(Fore.RED+"ERROR: Only alphanumeric characters allowed in the name!"+Fore.RESET)
                    continue

                username = cmd.split(' ')[1]
                validUsername = True
                if username == "":
                    validUsername = False
                for ch in username:
                    if ch not in "abcdefghijklmnopqrstuvwxyz0123456789":
                        validUsername = False
                        break

                if not validUsername:
                    print(Fore.RED+"Only alphanumeric characters allowed in the name!"+Fore.RESET)
                    continue

                self.username = username
                self.checkusername(username)

            elif cmd.split(' ')[0] == '/setactive':
                if self.username == "":
                    print(Fore.RED+"ERROR: Set a username first using \"/setname <username>\""+Fore.RESET)
                    continue

                if len(cmd.split(' ')) != 2:
                    print(Fore.RED+"ERROR: Invalid arguments for the mentioned command. Expected only true OR false"+Fore.RESET)
                    continue

                active = cmd.split(' ')[1]
                if active == 'true':
                    if self.activeState:
                        print("You're already set as active on the network!")
                        continue
                    else:
                        self.activeState = True
                        print("You're now active!")
                elif active == 'false':
                    if self.activeState:
                        self.activeState = False
                        print("You're now inactive!")
                    else:
                        print("You're already set as inactive on the network!")
                        continue
                else:
                    print(Fore.RED+"ERROR: Expected \"True\" OR \"False\" as arguments"+Fore.RESET)

            elif cmd.split(' ')[0] == '/reqchat':
                if self.username == "":
                    print(Fore.RED+"ERROR: Set a username first using \"/setname <username>\""+Fore.RESET)
                    continue

                if self.activeState == False:
                    print(Fore.RED+"ERROR: You need to set yourself as active first. \"/setactive true\""+Fore.RESET)
                    continue

                if len(cmd.split(' ')) != 2:
                    print(Fore.RED+"ERROR: Invalid arguments for the mentioned command. Expected format: \"/reqchat <username>\""+Fore.RESET)
                    continue

                if len(self.userList) == 0:
                    print(Fore.RED+"ERROR: Either there are no active users in your network or you haven't used the command \"/listusers\" yet."+Fore.RESET)
                    continue

                reqchatUsername = cmd.split(' ')[1]
                if not (reqchatUsername in self.userList.keys()):
                    print(Fore.RED+"ERROR: The required user does not exist in your network. Please use /listusers to check a list of active users in your network or recheck the username you entered!"+Fore.RESET)
                    continue

                if (not (reqchatUsername in self.userActiveList.keys())) or self.userActiveList[reqchatUsername] == "Inactive":
                    print(Fore.RED+"ERROR: The user is currently not active to receive any message requests!"+Fore.RESET)
                    continue
                else:
                    self.userChatReqSent.append(reqchatUsername)
                    self.sendBroadcast('$connrequest',reqchatUsername)

            elif cmd.split(' ')[0] == '/chat':
                if len(cmd.split(' ')) != 3:
                    print(Fore.RED+"ERROR: Invalid arguments for the mentioned command. Expected usage: \"/chat <username> <true|false>\""+Fore.RESET)
                    continue
                reqChatUser = cmd.split(' ')[1]
                reqChatAccept = cmd.split(' ')[2]
                if not (reqChatUser in self.userChatReqRecv):
                    print(Fore.RED+"ERROR: You've not received a connection request from that user. To check list of all connections use the command \"/listreq\""+Fore.RESET)
                    continue
                if not (reqChatAccept in ['true','false']):
                    print(Fore.RED+"ERROR: Expected \"True\" OR \"False\" as arguments"+Fore.RESET)
                    continue

                self.userChatReqRecv.remove(reqChatUser)
                self.connectedUser = True
                self.connectedUsername = reqChatUser
                self.connectedIP = self.userList[self.connectedUsername]
                self.sendBroadcast('$connresponse',reqChatUser+':'+reqChatAccept)
    
            elif cmd.split(' ')[0] == '/chatmsg':
                if len(cmd.split(' ')) == 1:
                    continue
                if self.connectedUser == False:
                    print(Fore.RED+"ERROR: You're not connected to any user!"+Fore.RESET)
                    continue
                message = ' '.join(cmd.split(' ')[1::])
                encMessage = self.encryptMessage(message)
                self.dfhKey.icmpConn.sendICMP(encMessage)

            else:
                print("Invalid command entered. Please refer to the help manual using /help")
                continue

        print("Quitting applicaiton...")

    def initChat(self, destIP, initiator):
        # funtion to initialise chat using dfh and everything
        print("Initialising dfh and everything...")
        self.dfhKey = DFH(destIP, initiator, self.connectedUsername)
        if self.dfhKey.success == False:
            # something wrong
            print('something wrong happened!')
            self.sendBroadcast('$terminate', self.connectedUsername)
            self.connectedUsername = ""
            self.connectedUser = False
            self.connectedIP = ""
            self.dfhKey = None

    def displayHelp(self):
        print("List of all possible commands:\n")
        print('/help \t\t\t\t | \t Displays this help window')
        print('/setname <username> \t\t | \t Set\'s your username in the network to the one mentioned.')
        print('/name \t\t\t\t | \t Check your username.')
        print('/setactive <true|false> \t | \t Toggle your active state in the network')
        print('/listusers \t\t\t | \t List all the active users present in the network running this application.')
        print('/reqchat <username> \t\t | \t Send a connection request to <username>')
        print('/listreq \t \t \t | \t List all chat requests you\'ve got.')
        print('/chat <username> <true|false> \t | \t Accept or reject someone\'s chat request!')
        print('/chatmsg <message> \t \t | \t Sends the message to the connected user.')
        print('/disconnect \t\t\t | \t Disconnects the chat with the connected user.')
        print('/exit \t\t\t\t | \t Exits the application.\n')

    def checkusername(self,username):
        # function to check if the desired username already exists in the network
        # return True if it does, False if its a new username
        self.sendBroadcast('$namecheck')

    def listActiveUsers(self):
        # function that will send a packet to all devices on the network
        # all devices that are set as active will send a response packet along with their username
        # this function will return a list of all those usernames, str[]

        self.sendBroadcast("$userlist",self.activeState)
        # a small timeout to receive, process and update the userlist as required
        time.sleep(2)
        activeList = []
        for user in self.userList.keys():
            if user in self.userActiveList.keys() and self.userActiveList[user] == "Active":
                activeList.append(user)

        return activeList

    def encryptMessage(self,message):
        return self.dfhKey.encryptionModule.encryptMessage(message)

    def decryptMessage(self,message):
        return self.dfhKey.encryptionModule.decryptMessage(message)

def printBanner():
    print("""
 -------------------------------------------------
 | |    _____ _           _   _    _       _   | |
 | |   / ____| |         | | | |  | |     | |  | |
 | |  | |    | |__   __ _| |_| |  | |_ __ | |  | |
 | |  | |    | '_ \ / _` | __| |  | | '_ \| |  | |
 | |  | |____| | | | (_| | |_| |__| | |_) |_|  | |
 | |   \_____|_| |_|\__,_|\__|\____/| .__/(_)  | |
 | |                                | |        | |
 | |                                |_|        | |
 -------------------------------------------------
 """)

    print("Welcome to ChatUp CLI! Use this to chat with other users present in your private network.\n")  

    print("Follow this order if you're new here:")
    print("1. Set your name. (/setname <janedoe>)")
    print("2. Set yourself active in the network. (/setactive true)")
    print("3. Check active users list. (/listusers)")
    print("4. Select user you wanna talk to. (/reqchat <username>)")
    print("5. See a list of users who have sent you a chat request (/listreq)")
    print("6. Accept/Reject a user's request (/chat <username> true/false)")
    print("7. Send message to the user (/chatmsg <username>)")
    print("8. Disconnect the chat when done. (/disconnect)\n")

    print('+++++++++++++++++++++++++++++++++++++++++++++++++++++++\n')
    print(" - Use /help to display the different commands!\n")
    
def main():
    printBanner()
    mainInstance = Instance()
    mainInstance.startInstance()

if __name__ == '__main__':
    main()
    sys.exit()

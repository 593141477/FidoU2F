#! /usr/bin/env python
import sys

USE_PCSC = 1

connection = None

if USE_PCSC:
    from smartcard.System import readers
    from smartcard.CardConnection import CardConnection

    # get all the available readers
    r = readers()
    print "Available readers:", r

    reader = r[0]
    print "Using:", reader

    connection = reader.createConnection()
    connection.connect()
else:
    import pn532_reader
    pn532_reader.initialize()
    pn532_reader.activation_card()
    connection = pn532_reader

def print_hex_array(arr):
    print ' '.join(format(n,'02x') for n in arr)

def read_binary(sfi, length, offset):
    return connection.transmit([0x00,0xb0,0x80|x,offset,length])

def read_binary_long(length, offset):
    return connection.transmit([0x00,0xb0,0x7f&(offset>>8),offset&0xff,length])

def read_record(sfi, number, length):
    return connection.transmit([0x00,0xb2,number,(sfi<<3)|4,length])

def select_by_fid(fid):
    return connection.transmit([0x00,0xa4,0x00,0x00,0x02,fid>>8,fid])

def select_by_aid(aid):
    return connection.transmit([0x00,0xa4,0x04,0x00,len(aid)]+aid)

def load_cert(offset,data,extended=False):
    length = len(data)
    print('offset={} length={}'.format(offset,length))
    lc = [0,length>>8,length&0xff] if extended else ([length] if length>0 else [])
    apdu = [0x80,0x01,offset>>8,offset&0xff]+lc+data
    # print_hex_array(apdu)
    return connection.transmit(apdu)

data, sw1, sw2 = select_by_aid([0xA0,0x00,0x00,0x06,0x47,0x2F,0x00,0x01])
if not (sw1==0x90 and sw2==0x00):
    print("Status: %02X %02X" % (sw1, sw2))
    sys.exit(1)

with open(sys.argv[1],'rb') as f_cert:

    cert = [ord(i) for i in f_cert.read()]
    size = len(cert)
    # load_cert(0, cert, True)
    offset = 0
    while offset < size:
        l = size if size<64 else 64
        data, sw1, sw2 = load_cert(offset,cert[offset:offset+l])
        if sw1==0x90 and sw2==0x00:
            offset += l
        else:
            print("Status: %02X %02X" % (sw1, sw2))
            break

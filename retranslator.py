# -*- coding: utf-8 -*-

import binascii
import socket
import threading
from datetime import datetime
import json

CONNECTION = (socket.gethostname(), 6054)

server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

# prevent 'ERROR: Address already in use'
server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)


server.bind((socket.gethostname(), 6054))
server.listen(15)

def parse(fmt, binary, offset=0):
    '''
    Unpack the string

    fmt      @see https://docs.python.org/2/library/struct.html#format-strings
    value    value to be formated
    offset   offset in bytes from begining
    '''
    parsed = 0
    try:
        parsed = struct.unpack_from(fmt, binary, offset)
        parsed = parsed[0] if len(parsed) == 1 else parsed
    except:
        pass
    
    return parsed
    
def parsePacket(packet):
    '''
    Parse Wialon Retranslator v1.0 packet w/o first 4 bytes (packet size)
    '''

    # parsed message
    msg = {
        'id': 0,
        'time': 0,
        'flags': 0,
        'params': {},
        'blocks': []
    }

    # parse packet info
    controller_id_size = packet.find('\x00')
    (msg['id'], msg['time'], msg['flags']) = parse('> %ds x i i' % (controller_id_size), packet)

    # get data block
    data_blocks = packet[controller_id_size + 1 + 4 + 4:]

    while len(data_blocks):
        # name offset in data block
        offset = 2 + 4 + 1 + 1
        name_size = data_blocks.find('\x00', offset) - offset
        (block_type, block_length, visible, data_type, name) = parse('> h i b b %ds' % (name_size), data_blocks)

        # constuct block info
        block = {
            'type': block_type,
            'length': block_length,
            'visibility': visible,
            'data_type': data_type,
            'name': name
        }

        # get block data
        block['data_block'] = data_blocks[offset + name_size + 1:block_length * 1 + 6]

        v = ''
        if data_type == 1:
            # text
            # TODO
            pass
        if data_type == 2:
            # binary
            if name == 'posinfo':
                v = {'lat': 0, 'lon': 0, 'h': 0, 's': 0, 'c': 0, 'sc': 0}
                (v['lon'], v['lat'], v['h']) = parse('d d d', block['data_block'])
                (v['s'], v['c'], v['sc']) = parse('> h h b', block['data_block'], 24)
        elif data_type == 3:
            # integer
            v = parse('> i', block['data_block'])
        elif data_type == 4:
            # float
            v = parse('d', block['data_block'])
        elif data_type == 5:
            # long
            v = parse('> q', block['data_block'])

        # add param to message
        msg['params'][name] = v

        # data blocks parse information
        msg['blocks'].append(block)

        # delete parsed info
        data_blocks = data_blocks[block_length + 6:]

    return msg


def clientthread(conn):
    queue = ''
    while True:
    #Receiving from client
        data = conn.recv(1024) # 1024 stands for bytes of data to be received
        if not data:
            break
        # append to queue
        queue = queue + data
        
        for i in range(0,len(queue)):
            # get first packet size
            packet_size = parse('<i', queue)
            if packet_size + 4 <= len(queue):
                # get packet
                packet = queue[4:packet_size + 4]
                # print binascii.hexlify(packet)
            
                msg = parsePacket(packet)
                msg.pop('blocks', None)
                
                pwrb = msg['params'].get('adc12', None) # BCE
                pwrt = msg['params'].get('pwr_ext', None) #Teltonika
                fuelb = msg['params'].get('fuel level', None) # BCE
                if pwrb is not None:
                    adc = pwrb
                if pwrt is not None:
                    adc = pwrt
                if fuelb is not None:
                    fuel = fuelb
                elif fuelb is None:
                    fuel = "None"
            
                mil = msg['params'].get('mileage', None)
                posinfo = msg['params'].get('posinfo', None)
                if posinfo is not None:
                    lat = msg['params']['posinfo'].get('lat', None)
                    lon = msg['params']['posinfo'].get('lon', None)
                 
                    print ("Imei: " + str(msg['id']) + ". Pozitie: " + str(lat) + " | " + str(lon))
                else:
                    print ("Position Info is invalid.")
                 
            
                # remove packet from queue
                queue = queue[packet_size + 4:]
             
                # packet was received successfully
                conn.send(str(0x11))
            
while True:
    #Accepting incoming connections
    print "Server pornit {0} on {1}".format(*CONNECTION)
    # Accept connections
    sck, addr = server.accept()
    print "Conectare de la {0}:{1}".format(*addr)
    t = threading.Thread(target=clientthread, args=(sck,))
    t.daemon = True
    t.start()
    
    
   
conn.close()
sck.close()

import nfqueue
import socket
import commands
import os
import time
from scapy.layers.inet import *

def iptables_to_nfqueue():
    os.system("sudo iptables -A OUTPUT -j NFQUEUE")
    os.system("sudo iptables -A INPUT -j NFQUEUE")

def logger(packet_data,verdict):
    log=open('log.txt','a')
    localtime = time.asctime( time.localtime(time.time()) )
    log_data=localtime +': '+verdict+',Src:'+packet_data['packet_source']+',Dst:' + packet_data['packet_dst']
    log.write(log_data+'\n')
    log.close()

def get_my_ip():
    global my_ip
    intf = 'eth0'
    my_ip = commands.getoutput("ip address show dev " + intf).split()
    my_ip = my_ip[my_ip.index('inet') + 1].split('/')[0]
    return my_ip

def get_rule_data(line):
    i=0
    global rule_data
    row=line.split( )
    sipflag=dipflag=spflag=dpflag=pflag=sprflag=dprflag=0
    for i in range(len(row)):
        if (row[i]=='-a'):
            action=row[i+1]
        elif(row[i]=='-s'):
            source_ip=(row[i+1])
            sipflag=1
        elif(row[i]=='-d'):
            dst_ip=(row[i+1])
            dipflag=1
        elif(row[i]=='-sp'):
            sport=row[i+1]
            spflag=1
        elif(row[i]=='-dp'):
            dport=row[i+1]
            dpflag=1
        elif(row[i]=='-spr'):
            sportrange=row[i+1]
            sprflag=1
        elif(row[i]=='-dpr'):
            dportrange=row[i+1]
            dprflag=1
        elif (row[i]=='-p'):
            proto=row[i+1]
            pflag=1
            if proto=='any':
                protocol=proto
            else:
                protocol=socket.getprotobyname(proto)
    if (sipflag==0):
        source_ip='any' 
    if (dipflag==0):
        dst_ip='any' 
    if (spflag==0):
        sport='any' 
    if (dpflag==0):
        dport='any'
    if (sprflag==0):
        sportrange='any'
    if (dprflag==0):
        dportrange='any'
    if (pflag==0):
        protocol='any'        
    rule_data={'rule_action':action,'rule_sourceip':source_ip,'rule_sport':sport, 'rule_sport_range':sportrange,'rule_dport_range':dportrange,'rule_dstip':dst_ip,'rule_dport':dport,'rule_protocol':protocol}
    
    return rule_data

def compare(packet_data,payload):
    
    my_ip=get_my_ip()
    verdict='permit'
    if (packet_data['packet_dst']==my_ip):
        direction='In'
    else:
        direction='Out'
    
    rule_file=open('rules.txt','r')
    for line in rule_file:
        rule_data=get_rule_data(line)
        
        if ((rule_data['rule_protocol']==(packet_data['packet_protocol'])or (rule_data['rule_protocol']=='any'))and \
            ((rule_data['rule_sourceip']==packet_data['packet_source']) or (rule_data['rule_sourceip']=='any')) and \
            ((rule_data['rule_sport']==packet_data['packet_sport']) or (rule_data['rule_sport']=='any')) and \
            ((rule_data['rule_dstip']==packet_data['packet_dst']) or (rule_data['rule_dstip']=='any')) and \
            ((rule_data['rule_dport']==packet_data['packet_dport']) or (rule_data['rule_dport']=='any')) ):

            if(rule_data['rule_dport_range']=='any'):
                    if (rule_data['rule_action']=='deny'):
                        verdict='deny'
                    elif (rule_data['rule_action']=='permit'):
                        verdict='permit'
                
            if(rule_data['rule_sport_range']=='any'):
                    if (rule_data['rule_action']=='deny'):
                        verdict='deny'
                    elif (rule_data['rule_action']=='permit'):
                        verdict='permit'
            
            if(rule_data['rule_dport_range']!= 'any'):
                dstart,dend=rule_data['rule_dport_range'].split("-")
                if(dstart<=packet_data['packet_dport']<=dend):
                    if (rule_data['rule_action']=='deny'):
                        verdict='deny'
                    elif (rule_data['rule_action']=='permit'):
                        verdict='permit'
                else:
                    if (rule_data['rule_action']=='deny'):
                        verdict='permit'
                    elif (rule_data['rule_action']=='permit'):
                        verdict='deny'
                
            if(rule_data['rule_sport_range']!= 'any'):
                sstart,send=rule_data['rule_sport_range'].split("-")
                if(sstart<=packet_data['packet_sport']<=send):
                    if (rule_data['rule_action']=='deny'):
                        verdict='deny'
                    elif (rule_data['rule_action']=='permit'):
                        verdict='permit'
                else:
                    if (rule_data['rule_action']=='deny'):
                        verdict='permit'
                    elif (rule_data['rule_action']=='permit'):
                        verdict='deny'
                    

                         

    if verdict=='deny':
        payload.set_verdict(nfqueue.NF_DROP)
        print('packet of protocol no. '+ str(rule_data['rule_protocol'])+ ' dropped')
        logger(packet_data,verdict)
    elif verdict=='permit':
        payload.set_verdict(nfqueue.NF_ACCEPT)
        logger(packet_data,verdict)
               
def Packet_capture(i, payload):
        data = payload.get_data()
        
        '''IP Header'''
        IP_header = IP(data)
        src=IP_header.src
        dst=IP_header.dst
        protocol=IP_header.proto
        
        '''TCP Header'''
        TCP_header=TCP(data)
        sport=TCP_header.sport
        dport=TCP_header.dport
        packet_data={'packet_protocol':protocol,'packet_source':src,'packet_dst':dst,'packet_sport':sport,'packet_dport':dport}
        compare(packet_data,payload)

def main():
    iptables_to_nfqueue()
    packet_queue = nfqueue.queue()
    packet_queue.open()
    packet_queue.bind(socket.AF_INET)
    packet_queue.set_callback(Packet_capture)
    if(packet_queue.create_queue(0)<0):
        print("Error while creating queue , exiting the program")
        packet_queue.unbind(socket.AF_INET)
        packet_queue.close()
        os.system('sudo iptables -F')
        sys.exit(1)
    try:
        packet_queue.try_run()
    except KeyboardInterrupt:
        print ("Exiting...")
        packet_queue.unbind(socket.AF_INET)
        packet_queue.close()
        os.system('sudo iptables -F')
        sys.exit(1)

main()

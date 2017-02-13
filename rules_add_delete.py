import sys

def add(rule):
    lines=open('rules.txt','a')
    lines.write(rule+'\n')
    lines.close()
    return

def delete(rule):
    temp=[]
    lines = open("rules.txt", 'r+')
    for line in lines:
        if set(rule.split( ))!=set(line.split( )):
            temp.append(line)
            
    open('rules.txt','w').close()
    lines.seek(0)
    for i in range(len(temp)):
        lines.write(temp[i]) 
    return

def main():
    command=str(sys.argv[1])
    if len(sys.argv)>2:
        inputdata=str(sys.argv[2])
    lines=open('rules.txt','r')
    
    if command=='add':
        rfound=0
        for line in lines:
            if set(inputdata.split( ))==set(line.split( )):
                print('Similar Rule found')
                rfound=1
        if rfound==0:
            add(inputdata)
            print('Rule '+'" ' +inputdata+' "'+ 'added')
    
    if command=='delete':
        rfound=0
        lines=open('rules.txt','r')
        for line in lines:
            if set(inputdata.split( ))==set(line.split( )):
                delete(inputdata)
                rfound=1
                print('Rule '+'" '+ inputdata +' "'+' deleted')
                break
        if rfound is 0:
            print('Rule not found')
            lines.close()

    if command=='show_rules':
        lines=open('rules.txt','r')
        count=1
        print('-----Rules-----')
        for line in lines:
            row=line.split( )
            sipflag=dipflag=spflag=dpflag=pflag=0
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
                elif (row[i]=='-p'):
                    proto=row[i+1]
                    pflag=1
                    protocol=proto
            if (sipflag==0):
                source_ip='any' 
            if (dipflag==0):
                dst_ip='any' 
            if (spflag==0):
                sport='any' 
            if (dpflag==0):
                dport='any'
            if (pflag==0):
                protocol='any'
            print('Rule '+str(count)+'=action:'+action+' sourceip:'+source_ip+' sport:'+sport+' dstip:'+dst_ip+' dport:'+dport+' protocol:'+protocol)
            count=count+1
        print('\n')
        lines.close()
    
    if command=='showrules':
        print('-----Rules-----')
        lines=open('rules.txt','r')
        count=1
        for line in lines:
            print('Rule '+str(count)+'='+line)
            count=count+1
        lines.close()
main()           

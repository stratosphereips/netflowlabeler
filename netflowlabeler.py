#! /usr/bin/env python
#  Copyright (C) 2009  Sebastian Garcia, Veronica Valeros
#
#  This program is free software; you can redistribute it and/or modify
#  it under the terms of the GNU General Public License as published by
#  the Free Software Foundation; either version 2 of the License, or
#  (at your option) any later version.
#
#  This program is distributed in the hope that it will be useful,
#  but WITHOUT ANY WARRANTY; without even the implied warranty of
#  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#  GNU General Public License for more details.
#
#  You should have received a copy of the GNU General Public License
#  along with this program; if not, write to the Free Software
#  Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
#
#
# Author:
# Sebastian Garcia, sebastian.garcia@agents.fel.cvut.cz, sgarcia@exa.unicen.edu.ar, eldraco@gmail.com
#
# Changelog

# Description
# A tool to add labels in netflow files
#
# TODO
# Take the flags into account


# standard imports
import getopt
import sys
import re

####################
# Global Variables

debug = 0
vernum = "0.3"
verbose = False

#########


# Print version information and exit
def version():
    print "+----------------------------------------------------------------------+"
    print "| netflowlabeler.py Version "+ vernum +"                                   |"
    print "| This program is free software; you can redistribute it and/or modify |"
    print "| it under the terms of the GNU General Public License as published by |"
    print "| the Free Software Foundation; either version 2 of the License, or    |"
    print "| (at your option) any later version.                                  |"
    print "|                                                                      |"
    print "| Author: Garcia Sebastian, eldraco@gmail.com                          |"
    print "| Author: Veronica Valeros, vero.valeros@gmail.com                     |"
    print "| UNICEN-ISISTAN, Argentina. CTU, Prague-ATG                           |"
    print "+----------------------------------------------------------------------+"
    print


# Print help information and exit:
def usage():
    print "+----------------------------------------------------------------------+"
    print "| netflowlabeler.py Version "+ vernum +"                                   |"
    print "| This program is free software; you can redistribute it and/or modify |"
    print "| it under the terms of the GNU General Public License as published by |"
    print "| the Free Software Foundation; either version 2 of the License, or    |"
    print "| (at your option) any later version.                                  |"
    print "|                                                                      |"
    print "| Author: Garcia Sebastian, eldraco@gmail.com                          |"
    print "| Author: Veronica Valeros, vero.valeros@gmail.com                     |"
    print "| UNICEN-ISISTAN, Argentina. CTU, Prague-ATG                           |"
    print "+----------------------------------------------------------------------+"
    print "\nusage: %s <options>" % sys.argv[0]
    print "options:"
    print "  -h, --help           Show this help message and exit"
    print "  -V, --version        Output version information and exit"
    print "  -v, --verbose        Output more information."
    print "  -D, --debug          Debug. In debug mode the statistics run live."
    print "  -f, --file           Input netflow file to label."
    print "  -c, --conf           Input configuration file to create the labels."
    print
    sys.exit(1)



class labeler():
    """
    This class handles the adding of new labeling conditions and the return of the lables
    """

    conditionsGroup = []
    """
    conditionsGroup = [ 
            {'Background': [ 
                [ {'srcIP': 'all'} ] 
                ] }, 
            {'Normal': [ 
                [ {'Proto':'IGMP'} ],
                [ {'Proto':'ARP'} ]
                ] }, 
            {'Botnet-CC': [
                [ {'srcIP': '10.0.0.151'} ], 
                [ {'dstIP': '10.0.0.151'} ]
                ] }, 
            {'Botnet-SPAM': [
                [ {'Proto': 'TCP'}, {'srcPort': '25'} ], 
                [ {'Proto': 'TCP'}, {'dstPort': '25'} ]
                ] }, 
            {'Botnet-DGA': [ 
                [ {'Proto':'UDP'}, {'srcPort':'53'} ] ,
                [ {'Proto':'UDP'}, {'dstPort':'53'} ] 
                ] } 
                      ]
    """

    def addCondition(self,condition):
        """
        Add a condition.
        Input: condition is a string?
        """
        try:
            global debug
            global verbose

            self.conditionsGroup.append(condition)

            if debug:
                print '\tCondition added: {0}'.format(condition)

        except Exception as inst:
            print 'Problem in addCondition() in class labeler'
            print type(inst)     # the exception instance
            print inst.args      # arguments stored in .args
            print inst           # __str__ allows args to printed directly
            exit(-1)


    def getLabel(self,netflowLine):
        """
        Get a netflow line and return a label
        Input: netflowLine is a string? or a dictionary?
        """
        try:
            global debug
            global verbose


            #if debug:
            #    print 'Netflow line asked: {0}'.format(netflowLine)

            # Default to empty label
            labelToReturn= ""

            # Convert the neflowLine array to a dict...
            netflowDict = {}
            for item in netflowLine:
               name = item.keys()[0]
               netflowDict[name] = item[name]

        
            # Process all the conditions 
            #if debug:
            #    print 'Processing the conditions'
            for group in self.conditionsGroup:
                labelToVerify = group.keys()[0]
                if debug:
                    print '\tLabel to verify {0}'.format(labelToVerify)

                orConditions = group[labelToVerify]
                #if debug:
                    #print '\t\tOr conditions group : {0}'.format(orConditions)


                # orConditions is an array. Each position of this array should be ORed with the next position
                for andcondition in orConditions:
                    # If any of these andConditions groups is true, just return the label, because this for is an 'OR'
                    #if debug:
                        #print '\t\tAnd condition group : {0}'.format(andcondition)

                    # With this we keep control of how each part of the and is going...
                    allTrue = True
                    for acond in andcondition:
                        #if debug:
                           #print '\t\t\tAnd this with : {0}'.format(acond)

                        condColumn = acond.keys()[0]
                        condValue = acond[condColumn].upper()

                        netflowValue = netflowDict[condColumn]
                        if debug:
                            print '\t\tField: {0}, Condition value: {1}, Netflow value: {2}'.format(condColumn, condValue, netflowValue)
                    
                        if condValue.find('!') != -1:
                            # This is negative condition
                            temp = condValue.split('!')[1]
                            condValue = temp
                            if (condValue != netflowValue) or (condValue == 'ALL') :
                                allTrue = True
                                if debug:
                                    print '\t\t\tTrue (negative)'
                                continue
                            else:
                                if debug:
                                    print '\t\t\tFalse (negative)'
                                allTrue = False
                                break
                        elif condValue.find('!') == -1:
                            # This is positive condition
                            if (condColumn == 'Bytes') or (condColumn == 'Packets'):
                                # We should be greater than or equal to these values...
                                if (int(condValue) <= int(netflowValue)) or (condValue == 'ALL') :
                                    allTrue = True
                                    if debug:
                                        print '\t\t\tTrue'
                                    continue
                                else:
                                    if debug:
                                        print '\t\t\tFalse'
                                    allTrue = False
                                    break
                            elif (condValue == netflowValue) or (condValue == 'ALL') :
                                allTrue = True
                                #if debug:
                                #    print '\t\t\tTrue'
                                continue
                            else:
                                if debug:
                                    print '\t\t\tFalse'
                                allTrue = False
                                break

                    if allTrue:
                        labelToReturn = labelToVerify
                        if debug:
                            print '\tNew label assigned: {0}'.format(labelToVerify)
                        
            if verbose:
                if 'Background' in labelToReturn:
                    #if verbose:
                    print '\tFinal label assigned: {0}'.format(labelToReturn)
                else:
                    print '\tFinal label assigned: \x1b\x5b1;31;40m{0}\x1b\x5b0;0;40m'.format(labelToReturn)
                #if debug:
                #    raw_input()
            return labelToReturn




        except Exception as inst:
            print 'Problem in getLabel() in class labeler'
            print type(inst)     # the exception instance
            print inst.args      # arguments stored in .args
            print inst           # __str__ allows args to printed directly
            exit(-1)




def output_netflow_line_to_file(outputfile, netflowArray):
    """
    Get a netflow dictionary and store it on a new file
    """
    try:
        global debug
        global verbose
        #if debug:
        #    print 'NetFlowArray: {}'.format(netflowArray)
        
        if netflowArray[12].keys()[0] == 'Flows':
            # nfdump
            outputline = str(netflowArray[0]['Date']) + ' ' + str(netflowArray[1]['start']) + '\t\t' + str(netflowArray[2]['Duration']) + ' ' + str(netflowArray[3]['Proto']) + '\t' + str(netflowArray[4]['srcIP']) + ':' + str(netflowArray[5]['srcPort']) + '\t->' + ' ' + str(netflowArray[6]['dstIP']) + ':' + str(netflowArray[7]['dstPort']) + '        ' + str(netflowArray[8]['Flags']) + '   ' + str(netflowArray[9]['Tos']) + '     ' + str(netflowArray[10]['Packets']) + ' ' + str(netflowArray[11]['Bytes']) + '   ' + str(netflowArray[12]['Flows']) + '  ' + str(netflowArray[13]['Label']) + '\n'
        else:
            # argus
            outputline = str(netflowArray[0]['Date']) + ' ' + str(netflowArray[1]['start']) + '\t\t' + str(netflowArray[2]['Duration']) + ' ' + str(netflowArray[3]['Proto']) + '\t' + str(netflowArray[4]['srcIP']) + '\t' + str(netflowArray[5]['srcPort']) + '\t->' + ' ' + str(netflowArray[6]['dstIP']) + '\t' + str(netflowArray[7]['dstPort']) + '        ' + str(netflowArray[8]['Flags']) + '   ' + str(netflowArray[9]['Tos']) + '     ' + str(netflowArray[10]['Packets']) + ' ' + str(netflowArray[11]['Bytes']) + '  ' + str(netflowArray[12]['Label']) + '\n'
        outputfile.writelines(outputline)


        # write the line
        # keep it open!

    except Exception as inst:
        print 'Problem in output_labeled_netflow_file()'
        print type(inst)     # the exception instance
        print inst.args      # arguments stored in .args
        print inst           # __str__ allows args to printed directly
        exit(-1)




def process_netflow(netflowFile, labelmachine):
    """
    This function takes the netflowFile and parse it. Then it ask for a label and finally it calls a function to store the netflow in a file
    """
    try:
        global debug
        global verbose
        if verbose:
            print 'Processing the netflow file {0}'.format(netflowFile)


        # Read the netflow and parse the input
        try:
            f = open(netflowFile,'r')
        except Exception as inst:
            print 'Some problem opening the input netflow file. In process_netflow()'
            print type(inst)     # the exception instance
            print inst.args      # arguments stored in .args
            print inst           # __str__ allows args to printed directly
            exit(-1)

          
        # Just to monitor how many lines we read
        amountOfLines = 0
        line = f.readline()
        amountOfLines += 1
        

        ##################
        # nfdump processing...

        # What are we analyzing nfdump files or argus files?
        if 'Date' not in line and 'StartTime' not in line:
            print 'The file has not headers. Please add them.'
            sys.exit(-1)
        if 'Date' in line:
            # This is nfdump files...


            # Parse the file into an array of dictionaries. We will use the columns names as dictionary keys
            # Example: [ {'Date': '10/10/2013} , {'SrcIp':'1.1.1.1} , , ]
            netflowArray = []
            columnDict = {}

            # Replace the stupid TABs for spaces, if it has them..., and replace the : in the ports to spaces also, and strip the \n, and the word flow
            temp2 = line.replace('flow','')
            temp = re.sub( '\s+', ' ', temp2 ).replace(':',' ').strip()
            columnNames = temp.split(' ')

            # Only to separate src ip from dst ip
            addressType = ''

            #if debug:
            #    print 'Columns names: {0}'.format(columnNames)

            for cN in columnNames:
                # Separate between src ip and dst ip
                if 'Src' in cN:
                    addressType = 'src'
                elif 'Dst' in cN:
                    addressType = 'dst'
                elif 'IP' in cN:
                    columnDict[addressType+cN] = ""
                    netflowArray.append(columnDict)
                    columnDict = {}
                # Separate ports
                elif 'Port' in cN:
                    columnDict[addressType+cN] = ""
                    netflowArray.append(columnDict)
                    columnDict = {}
                elif 'Addr' in cN:
                    pass
                elif 'Prot' in cN:
                    columnDict['Proto'] = ""
                    netflowArray.append(columnDict)
                    columnDict = {}
                elif 'Durat' in cN:
                    columnDict['Duration'] = ""
                    netflowArray.append(columnDict)
                    columnDict = {}
                elif 'Flow' in cN:
                    columnDict['Flows'] = ""
                    netflowArray.append(columnDict)
                    columnDict = {}
                else:
                    columnDict[cN] = ""
                    netflowArray.append(columnDict)
                    columnDict = {}

            columnDict['Label'] = ""
            netflowArray.append(columnDict)
            columnDict = {}

            #if debug:
                #print 'netflowArray'
                #print netflowArray

            # Create the output file with the header
            outputfile = open(netflowFile+'.labeled','w+')
            
            # Write the column names
            columnnames = "Date flow start Duration        Proto   Src IP Addr:Port        Dst IP Addr:Port        Flags   Tos     Packets Bytes   Flows  Label\n"
            outputfile.writelines(columnnames)


            # Read the second line to start processing
            line = f.readline()
            amountOfLines += 1
            while (line):
                if verbose:
                    print 'Netflow line: {0}'.format(line),

                # Parse the columns
                # Strip and replace ugly stuff
                temp2 = line.replace('->','')
                temp = re.sub( '\s+', ' ', temp2 ).strip()
                columnValues = temp.split(' ')


                #if debug:
                #    print columnValues

                # Date
                date = columnValues[0]
                # Store the value in the dict
                dict = netflowArray[0]
                columnName = dict.keys()[0] 
                dict[columnName] = date
                netflowArray[0] = dict

                hour = columnValues[1]
                # Store the value in the dict
                dict = netflowArray[1]
                columnName = dict.keys()[0] 
                dict[columnName] = hour
                netflowArray[1] = dict

                duration = columnValues[2]
                # Store the value in the dict
                dict = netflowArray[2]
                columnName = dict.keys()[0] 
                dict[columnName] = duration
                netflowArray[2] = dict

                protocol = columnValues[3].upper()
                # Store the value in the dict
                dict = netflowArray[3]
                columnName = dict.keys()[0] 
                #columnName = 'Proto'
                dict[columnName] = protocol
                netflowArray[3] = dict

                
                if 'TCP' in protocol or 'UDP' in protocol or 'RTP' in protocol:
                    temp = columnValues[4]
                    if len(temp.split(':')) <= 2:
                        # It is IPV4
                        srcip = temp.split(':')[0]
                        # Store the value in the dict
                        dict = netflowArray[4]
                        columnName = dict.keys()[0] 
                        dict[columnName] = srcip
                        netflowArray[4] = dict

                        srcport = temp.split(':')[1]
                        # Store the value in the dict
                        dict = netflowArray[5]
                        columnName = dict.keys()[0] 
                        dict[columnName] = srcport
                        netflowArray[5] = dict

                        temp2 = columnValues[5]
                        dstip = temp2.split(':')[0]
                        # Store the value in the dict
                        dict = netflowArray[6]
                        columnName = dict.keys()[0] 
                        dict[columnName] = dstip
                        netflowArray[6] = dict

                        dstport = temp2.split(':')[1]
                        # Store the value in the dict
                        dict = netflowArray[7]
                        columnName = dict.keys()[0] 
                        dict[columnName] = dstport
                        netflowArray[7] = dict
                    elif len(temp.split(':')) > 2:
                        # We are using ipv6! THIS DEPENDS A LOT ON THE program that created the netflow..
                        srcip = temp[0:temp.rfind(':')]
                        # Store the value in the dict
                        dict = netflowArray[4]
                        columnName = dict.keys()[0] 
                        dict[columnName] = srcip
                        netflowArray[4] = dict

                        srcport = temp[temp.rfind(':')+1:]
                        # Store the value in the dict
                        dict = netflowArray[5]
                        columnName = dict.keys()[0] 
                        dict[columnName] = srcport
                        netflowArray[5] = dict

                        temp2 = columnValues[5]
                        dstip = temp2[0:temp2.rfind(':')]
                        # Store the value in the dict
                        dict = netflowArray[6]
                        columnName = dict.keys()[0] 
                        dict[columnName] = dstip
                        netflowArray[6] = dict

                        dstport = temp2[temp2.rfind(':')+1:]
                        # Store the value in the dict
                        dict = netflowArray[7]
                        columnName = dict.keys()[0] 
                        dict[columnName] = dstport
                        netflowArray[7] = dict
                    else:
                        print 
                        print 'Please implement this protocol!'
                        print line
                        sys.exit(-1)
                elif protocol == 'IPNIP' or protocol == 'RSVP' or protocol == 'GRE' or protocol == 'UDT' or protocol == 'ARP' or protocol == 'ICMP' or protocol == 'PIM' or protocol == 'ESP' or protocol == 'UNAS' or protocol == 'IGMP' or 'IPX' in protocol or 'RARP' in protocol or 'LLC' in protocol or 'IPV6' in protocol:
                    srcip = temp = columnValues[4]
                    # Store the value in the dict
                    dict = netflowArray[4]
                    columnName = dict.keys()[0] 
                    dict[columnName] = srcip
                    netflowArray[4] = dict

                    srcport = '0'
                    # Store the value in the dict
                    dict = netflowArray[5]
                    columnName = dict.keys()[0] 
                    dict[columnName] = srcport
                    netflowArray[5] = dict

                    dstip = temp = columnValues[5]
                    # Store the value in the dict
                    dict = netflowArray[6]
                    columnName = dict.keys()[0] 
                    dict[columnName] = dstip
                    netflowArray[6] = dict

                    dstport = '0'
                    # Store the value in the dict
                    dict = netflowArray[7]
                    columnName = dict.keys()[0] 
                    dict[columnName] = dstport
                    netflowArray[7] = dict

                flags = columnValues[6].upper()
                # Store the value in the dict
                dict = netflowArray[8]
                columnName = dict.keys()[0] 
                dict[columnName] = flags
                netflowArray[8] = dict

                tos = columnValues[7]
                # Store the value in the dict
                dict = netflowArray[9]
                columnName = dict.keys()[0] 
                dict[columnName] = tos
                netflowArray[9] = dict

                packets = columnValues[8]
                # Store the value in the dict
                dict = netflowArray[10]
                columnName = dict.keys()[0] 
                dict[columnName] = packets
                netflowArray[10] = dict

                bytes = columnValues[9]
                # Store the value in the dict
                dict = netflowArray[11]
                columnName = dict.keys()[0] 
                dict[columnName] = bytes
                netflowArray[11] = dict

                flows = columnValues[10]
                # Store the value in the dict
                dict = netflowArray[12]
                columnName = dict.keys()[0] 
                dict[columnName] = flows
                netflowArray[12] = dict

                # Empty the label in the dict
                dict = netflowArray[13]
                columnName = dict.keys()[0] 
                dict[columnName] = ""
                netflowArray[13] = dict

                #if debug:
                #    print date,hour,duration,protocol, srcip, srcport, dstip, dstport, flags, tos, packets, bytes, flows
                #    print netflowArray


                # Request a label
                label = labelmachine.getLabel(netflowArray)
                # Store the value in the dict
                dict = netflowArray[13]
                columnName = dict.keys()[0] 
                dict[columnName] = label
                netflowArray[13] = dict

                #if debug:
                    #print netflowArray

                # Ask to store the netflow
                output_netflow_line_to_file(outputfile, netflowArray)


                line = f.readline()
                amountOfLines += 1


        ##################
        # Argus processing...

        elif 'StartTime' in line:
            # This is argus files...

            # Parse the file into an array of dictionaries. We will use the columns names as dictionary keys
            # Example: [ {'Date': '10/10/2013} , {'SrcIp':'1.1.1.1} , , ]
            netflowArray = []
            columnDict = {}

            # Replace the stupid TABs for spaces, if it has them..., and replace the : in the ports to spaces also, and strip the \n, and the word flow
            temp = re.sub( '\s+', ' ', line ).strip()
            columnNames = temp.split(' ')

            #if debug:
            #    print 'Columns names: {0}'.format(columnNames)

            # So far argus does no have a column Date
            columnDict['Date'] = ""
            netflowArray.append(columnDict)
            columnDict = {}

            columnDict['start'] = ""
            netflowArray.append(columnDict)
            columnDict = {}
            
            columnDict['Duration'] = ""
            netflowArray.append(columnDict)
            columnDict = {}

            columnDict['Proto'] = ""
            netflowArray.append(columnDict)
            columnDict = {}

            columnDict['srcIP'] = ""
            netflowArray.append(columnDict)
            columnDict = {}

            columnDict['srcPort'] = ""
            netflowArray.append(columnDict)
            columnDict = {}

            columnDict['dstIP'] = ""
            netflowArray.append(columnDict)
            columnDict = {}

            columnDict['dstPort'] = ""
            netflowArray.append(columnDict)
            columnDict = {}

            columnDict['Flags'] = ""
            netflowArray.append(columnDict)
            columnDict = {}

            columnDict['Tos'] = ""
            netflowArray.append(columnDict)
            columnDict = {}

            columnDict['Packets'] = ""
            netflowArray.append(columnDict)
            columnDict = {}

            columnDict['Bytes'] = ""
            netflowArray.append(columnDict)
            columnDict = {}

            columnDict['Label'] = ""
            netflowArray.append(columnDict)
            columnDict = {}




            # Create the output file with the header
            outputfile = open(netflowFile+'.labeled','w+')
            
            # Write the column names
            columnnames = "Date Time       Dur     Proto   SrcAddr Sport   Dir     DstAddr Dport   State   sTos    TotPkts TotBytes Label\n"
            outputfile.writelines(columnnames)


            # Read the second line to start processing
            line = f.readline()
            amountOfLines += 1
            while (line):
                if verbose:
                    print 'Netflow line: {0}'.format(line),

                # Parse the columns
                # Strip and replace ugly stuff
                temp2 = line.replace('->','')
                temp = re.sub( '\s+', ' ', temp2 ).strip()
                columnValues = temp.split(' ')


                #if debug:
                #    print columnValues

                # Date
                date = columnValues[0]
                # Store the value in the dict
                dict = netflowArray[0]
                columnName = dict.keys()[0] 
                dict[columnName] = date
                netflowArray[0] = dict

                hour = columnValues[1]
                # Store the value in the dict
                dict = netflowArray[1]
                columnName = dict.keys()[0] 
                dict[columnName] = hour
                netflowArray[1] = dict

                duration = columnValues[2]
                # Store the value in the dict
                dict = netflowArray[2]
                columnName = dict.keys()[0] 
                dict[columnName] = duration
                netflowArray[2] = dict

                protocol = columnValues[3].upper()
                # Store the value in the dict
                dict = netflowArray[3]
                columnName = dict.keys()[0] 
                dict[columnName] = protocol
                netflowArray[3] = dict

                srcIP = columnValues[4]
                # Store the value in the dict
                dict = netflowArray[4]
                columnName = dict.keys()[0] 
                dict[columnName] = srcIP
                netflowArray[4] = dict

                if 'ARP' in protocol:
                    srcPort = '0'   
                    # Store the value in the dict
                    dict = netflowArray[5]
                    columnName = dict.keys()[0] 
                    dict[columnName] = srcPort
                    netflowArray[5] = dict
                else:
                    srcPort = columnValues[5]
                    # Store the value in the dict
                    dict = netflowArray[5]
                    columnName = dict.keys()[0] 
                    dict[columnName] = srcPort
                    netflowArray[5] = dict


                dstIP = columnValues[6] 
                # Store the value in the dict
                dict = netflowArray[6]
                columnName = dict.keys()[0] 
                dict[columnName] = dstIP
                netflowArray[6] = dict


                if 'ARP' in protocol:
                    dstPort = '0'   
                    # Store the value in the dict
                    dict = netflowArray[7]
                    columnName = dict.keys()[0] 
                    dict[columnName] = dstPort
                    netflowArray[7] = dict

                    Flags = columnValues[8]
                    # Store the value in the dict
                    dict = netflowArray[8]
                    columnName = dict.keys()[0] 
                    dict[columnName] = Flags
                    netflowArray[8] = dict

                else:
                    dstPort = columnValues[7]
                    # Store the value in the dict
                    dict = netflowArray[7]
                    columnName = dict.keys()[0] 
                    dict[columnName] = dstPort
                    netflowArray[7] = dict

                    Flags = columnValues[8]
                    # Store the value in the dict
                    dict = netflowArray[8]
                    columnName = dict.keys()[0] 
                    dict[columnName] = Flags
                    netflowArray[8] = dict



                if 'LLC' in protocol:
                    Tos = '0'
                    # Store the value in the dict
                    dict = netflowArray[9]
                    columnName = dict.keys()[0] 
                    dict[columnName] = Tos
                    netflowArray[9] = dict

                    Packets = columnValues[9]
                    # Store the value in the dict
                    dict = netflowArray[10]
                    columnName = dict.keys()[0] 
                    dict[columnName] = Packets
                    netflowArray[10] = dict

                    Bytes = columnValues[10]
                    # Store the value in the dict
                    dict = netflowArray[11]
                    columnName = dict.keys()[0] 
                    dict[columnName] = Bytes
                    netflowArray[11] = dict

                    # Request a label
                    label = labelmachine.getLabel(netflowArray)
                    # Store the value in the dict
                    dict = netflowArray[12]
                    columnName = dict.keys()[0] 
                    dict[columnName] = label
                    netflowArray[12] = dict
                elif 'ARP' in protocol:
                    Tos = '0'
                    # Store the value in the dict
                    dict = netflowArray[9]
                    columnName = dict.keys()[0] 
                    dict[columnName] = Tos
                    netflowArray[9] = dict

                    Packets = columnValues[8]
                    # Store the value in the dict
                    dict = netflowArray[10]
                    columnName = dict.keys()[0] 
                    dict[columnName] = Packets
                    netflowArray[10] = dict

                    Bytes = columnValues[9]
                    # Store the value in the dict
                    dict = netflowArray[11]
                    columnName = dict.keys()[0] 
                    dict[columnName] = Bytes
                    netflowArray[11] = dict

                    # Request a label
                    label = labelmachine.getLabel(netflowArray)
                    # Store the value in the dict
                    dict = netflowArray[12]
                    columnName = dict.keys()[0] 
                    dict[columnName] = label
                    netflowArray[12] = dict
                else:
                    Tos = columnValues[9]
                    # Store the value in the dict
                    dict = netflowArray[9]
                    columnName = dict.keys()[0] 
                    dict[columnName] = Tos
                    netflowArray[9] = dict

                    Packets = columnValues[10]
                    # Store the value in the dict
                    dict = netflowArray[10]
                    columnName = dict.keys()[0] 
                    dict[columnName] = Packets
                    netflowArray[10] = dict

                    Bytes = columnValues[11]
                    # Store the value in the dict
                    dict = netflowArray[11]
                    columnName = dict.keys()[0] 
                    dict[columnName] = Bytes
                    netflowArray[11] = dict

                    # Request a label
                    label = labelmachine.getLabel(netflowArray)
                    # Store the value in the dict
                    dict = netflowArray[12]
                    columnName = dict.keys()[0] 
                    dict[columnName] = label
                    netflowArray[12] = dict

                #if debug:
                #    print netflowArray

                # Ask to store the netflow
                output_netflow_line_to_file(outputfile, netflowArray)

                line = f.readline()
                amountOfLines += 1

            # End while

        # Close the outputfile
        outputfile.close()

        print 'Amount of lines read: {0}'.format(amountOfLines)

        # Ask for a label
        # Call a function to store the new netflow
        

    except Exception as inst:
        print 'Problem in process_netflow()'
        print type(inst)     # the exception instance
        print inst.args      # arguments stored in .args
        print inst           # __str__ allows args to printed directly
        exit(-1)


def loadConditions(configFile, labelmachine):
    global debug
    global verbose

    conditionsList = []
    try:
        try:
            if verbose:
                print 'Opening the configuration file \'{0}\''.format(configFile)
            conf = open(configFile)
        except:
            print 'The file \'{0}\' couldn\'t be opened.'.format(configFile)
            exit(1)


        if debug:
            print 'Loading the conditions from the configuration file '                    

        # Read the conf file
        line = conf.readline()
        conditions = {}

        while (line):
            # Ignore comments
            if line.strip().find('#') == 0:
                line = conf.readline()
                continue

            # Read a label
            if line.strip()[0] != '-':
                label = line.split(':')[0]
                #if debug:
                #    print 'Label: {}'.format(label)
                conditions[label]=[]

                # Now read all the conditions for this label
                line = conf.readline()
                while (line):
                    if line.strip()[0] == '-':
                        # Condition
                        tempAndConditions = line.strip().split('-')[1]
                        #if debug:
                        #    print 'Condition: {}'.format(tempAndConditions)
                        andConditions = []
                        for andCond in tempAndConditions.split('&'):
                            tempdict = {}
                            tempdict[andCond.strip().split('=')[0]] = andCond.strip().split('=')[1]
                            andConditions.append(tempdict)

                        conditions[label].append(andConditions)

                        line = conf.readline()
                    else:
                        break
            labelmachine.addCondition(conditions) 
            conditions = {}

    except KeyboardInterrupt:
        # CTRL-C pretty handling.
        print "Keyboard Interruption!. Exiting."
        sys.exit(1)
    except Exception as inst:
        print 'Problem in main() function at configurationParser.py '
        print type(inst)     # the exception instance
        print inst.args      # arguments stored in .args
        print inst           # __str__ allows args to printed directly
        return False




def main():
    try:
        global debug
        global verbose

        netflowFile = ""
        confFile = ""

        opts, args = getopt.getopt(sys.argv[1:], "VvDhf:c:", ["help","version","verbose","debug","file=","conf="])
    except getopt.GetoptError: usage()

    for opt, arg in opts:
        if opt in ("-h", "--help"): usage()
        if opt in ("-V", "--version"): version();exit(-1)
        if opt in ("-v", "--verbose"): verbose = True
        if opt in ("-D", "--debug"): debug = 1
        if opt in ("-f", "--file"): netflowFile = str(arg)
        if opt in ("-c", "--conf"): confFile = str(arg)
    try:
        try:
            if debug:
                verbose = True

            if netflowFile == "" or confFile == "":
                usage()
                sys.exit(1)
            
            elif netflowFile != "" and confFile != "":
                    # Print version information
                    version()

                    # Create an instance of the labeler
                    labelmachine = labeler()

                    # Load conditions
                    loadConditions(confFile,labelmachine)

                    # Direct process of netflow flows
                    process_netflow(netflowFile, labelmachine)

            else:
                    usage()
                    sys.exit(1)

        except Exception, e:
                print "misc. exception (runtime error from user callback?):", e
        except KeyboardInterrupt:
                sys.exit(1)


    except KeyboardInterrupt:
        # CTRL-C pretty handling.
        print "Keyboard Interruption!. Exiting."
        sys.exit(1)


if __name__ == '__main__':
    main()


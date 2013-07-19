#! /usr/bin/env python
#  Copyright (C) 2009  Sebastian Garcia
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


# standard imports
import getopt
import sys
import re
import yaml

####################
# Global Variables

debug = 0
vernum = "0.1"
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
    print "| Author: Garcia Sebastian, sebastiangarcia@conicet.gov.ar             |"
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

    def addCondition(self,condition):
        """
        Add a condition.
        Input: condition is a string?
        """
        try:
            global debug
            global verbose

            #self.conditionsGroup.append(condition)

            if debug:
                print 'Condition added: {0}'.format(condition)

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
            if debug:
                print 'Processing the conditions'
            for group in self.conditionsGroup:
                labelToVerify = group.keys()[0]
                if debug:
                    print '\tLabel to verify {0}'.format(labelToVerify)

                orConditions = group[labelToVerify]
                if debug:
                    print '\t\tOr conditions group : {0}'.format(orConditions)


                # orConditions is an array. Each position of this array should be ORed with the next position
                for andcondition in orConditions:
                    # If any of these andConditions groups is true, just return the label, because this for is an 'OR'
                    #if debug:
                    #    print '\t\tAnd condition group : {0}'.format(andcondition)

                    # With this we keep control of how each part of the and is going...
                    allTrue = True
                    for acond in andcondition:
                        #if debug:
                        #   print '\t\t\tAnd this with : {0}'.format(acond)

                        condColumn = acond.keys()[0]
                        condValue = acond[condColumn]
                        netflowValue = netflowDict[condColumn]
                        if debug:
                            print '\t\tField: {0}, Condition value: {1}, Netflow value: {2}'.format(condColumn, condValue, netflowValue)

                        if (condValue == netflowValue) or (condValue == 'all') :
                            allTrue = True
                            if debug:
                                print '\t\t\tTrue'
                            continue
                        else:
                            if debug:
                                print '\t\t\tFalse'
                            allTrue = False
                            break

                    if allTrue:
                        if debug:
                            print '\tNew label assigned: {0}'.format(labelToVerify)
                        labelToReturn = labelToVerify
                        
            if verbose:
                if 'Background' in labelToReturn:
                    print '\tFinal label assigned: {0}'.format(labelToReturn)
                else:
                    print '\tFinal label assigned: \x1b\x5b1;31;40m{0}\x1b\x5b0;0;40m'.format(labelToReturn)
                if debug:
                    raw_input()
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


        # Date
        outputline = netflowArray[0]['Date'] + ' ' + netflowArray[1]['start'] + '\t\t' + netflowArray[2]['Duration'] + ' ' + netflowArray[3]['Proto'] + '\t' + netflowArray[4]['srcIP'] + ':' + netflowArray[5]['srcPort'] + '\t->' + ' ' + netflowArray[6]['dstIP'] + ':' + netflowArray[7]['dstPort'] + '        ' + netflowArray[8]['Flags'] + '   ' + netflowArray[9]['Tos'] + '     ' + netflowArray[10]['Packets'] + ' ' + netflowArray[11]['Bytes'] + '   ' + netflowArray[12]['Flows'] + '  ' + netflowArray[13]['Label'] + '\n'
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
        except:
            print 'Some problem opening the input netflow file. In process_netflow()'
            exit(-1)

          
        # Just to monitor how many lines we read
        amountOfLines = 0
        line = f.readline()
        amountOfLines += 1

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

            protocol = columnValues[3]
            # Store the value in the dict
            dict = netflowArray[3]
            columnName = dict.keys()[0] 
            dict[columnName] = protocol
            netflowArray[3] = dict

            
            if 'TCP' in protocol or 'UDP' in protocol or 'RTP' in protocol or 'IGMP' in protocol:
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
                else:
                    # We are using ipv6! THIS DEPENDS A LOT ON THE program that created the netflow... so I'm leaving this for later
                    continue
            elif protocol == 'IPNIP' or protocol == 'RSVP' or protocol == 'GRE' or protocol == 'UDT' or protocol == 'ARP' or protocol == 'ICMP' or protocol == 'PIM' or protocol == 'ESP' or protocol == 'UNAS':
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

            elif 'IPV6' in protocol or 'IPX' in protocol or 'RARP' in protocol or 'LLC' in protocol:
                # Not now.... so do it later
                continue

            flags = columnValues[6]
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
            if debug:
                print 'Opening the configuration file \'{0}\''.format(configFile)
            conf = open(configFile)
        except:
            print 'The file \'{0}\' couldn\'t be opened.'.format(configFile)
            exit(1)
        try:
            if debug:
                print 'Loading the conditions from the configuration file '                    
            parsedFile = yaml.load(conf)
        except:
            print 'The format of the configuration file is wrong. You should see the config.example for reference.'
            exit(1)

        try:
            if debug:
                print 'Formatting the conditions' 
            conditions = {}
            for key in parsedFile.keys():
                if debug:
                    print 'KEY: {}'.format(key)
                conditions[key]=[]
                for cond in parsedFile[key]:
                    ands=[]
                    for pair in cond.split(' & '):
                        i={}
                        i[pair.split('=')[0]]=pair.split('=')[1]
                        ands.append(i)
                        if debug:
                            print 'I: {}'.format(i)
                            print 'ANDS: {}'.format(ands)
                    conditions[key].append(ands)
                    if debug: 
                        print 'CONDITIONS: {}'.format(conditions)
                conditionsList.append(conditions)
                if debug: 
                    print 'conditionsList: {}'.format(conditionsList)
                conditions = {}
        except:
            print 'Error formatting the conditions on loadConditions()'

        try:
            if debug:
                print 'Adding the conditions'
            for cond in conditionsList:
                labelmachine.addCondition(cond) 
                if debug:
                    print 'Condition added: {}'.format(cond)
            print 'Conditions loaded sucessfully.'
        except:
            print 'Error formatting the conditions on loadConditions()'

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


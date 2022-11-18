#! /usr/bin/env python3
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
# Authors:
# Sebastian Garcia, sebastian.garcia@agents.fel.cvut.cz, sgarcia@exa.unicen.edu.ar, eldraco@gmail.com
# Veronica Valeros, vero.valeros@gmail.com
# Stratosphere Laboratory, Czech Technical University in Prague

# Description
# A tool to add labels in netflow files based on a configuration. Flow file include Zeek, Argus, and NFdump. Both in CSV and TSV

import getopt
import sys
import re
import json
import argparse
import ipaddress

version = "0.4"


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

    def addCondition(self, condition):
        """
        Add a condition.
        Input: condition is a string?
        """
        try:
            self.conditionsGroup.append(condition)

            if args.debug > 0:
                print('\tCondition added: {0}'.format(condition))

        except Exception as inst:
            print('Problem in addCondition() in class labeler')
            print(type(inst))     # the exception instance
            print(inst.args)      # arguments stored in .args
            print(inst)           # __str__ allows args to printed directly
            exit(-1)


    def getLabel(self, column_values):
        """
        Get the values of the columns of a netflow line and return a label
        Input: column_values is a dict, where each key is the standard field in a netflow
        """
        try:
            # Default to empty genericlabel and detailedlabel
            labelToReturn= ("(empty)", "(empty)")

            # Process all the conditions
            for group in self.conditionsGroup:
                # The first key of the group is the label to put
                labelline = list(group.keys())[0]
                genericlabelToVerify = labelline.split(',')[0].strip()
                try:
                    detailedlabelToVerify = labelline.split(',')[1].strip()
                except IndexError:
                    # There is no detailedlabel
                    detailedlabelToVerify = '(empty)'

                if args.debug > 0:
                    print(f'\tLabel to verify {labelline}')

                orConditions = group[labelline]
                if args.debug > 0:
                    print('\t\tOr conditions group : {0}'.format(orConditions))

                # orConditions is an array. Each position of this array should be ORed with the next position
                for andcondition in orConditions:
                    # If any of these andConditions groups is true, just return the label, because this for is an 'OR'
                    if args.debug > 0:
                        print('\t\tAnd condition group : {0}'.format(andcondition))

                    # With this we keep control of how each part of the and is going...
                    allTrue = True
                    for acond in andcondition:
                        if args.debug > 0:
                           print('\t\t\tAnd this with : {0}'.format(acond))

                        condColumn = list(acond.keys())[0]
                        condValue = acond[condColumn].lower()
                        condColumn = condColumn.lower()

                        if condColumn.find('!') != -1:
                            # Negation condition
                            condColumn = condColumn.replace('!', '')
                            netflowValue = column_values[condColumn]
                            if args.debug > 0:
                                print(f'\t\tTo compare field: {condColumn}, Condition value: {condValue}, Netflow value: {netflowValue}')

                            if (condValue != netflowValue) or (condValue == 'all'):
                                allTrue = True
                                if args.debug > 0:
                                    print('\t\t\tTrue (negative)')
                                continue
                            else:
                                if args.debug > 0:
                                    print('\t\t\tFalse (negative)')
                                allTrue = False
                                break
                        elif condColumn.find('!') == -1:
                            # Normal condition, no negation

                            # Is the column a number?
                            if ('bytes' in condColumn) or ('packets' in condColumn) or ('srcport' in condColumn) or ('dstport' in condColumn) or ('sbytes' in condColumn) or ('dbyets' in condColumn) or ('spkts' in condColumn) or ('dpkts' in condColumn) or ('ip_orig_bytes' in condColumn) or ('ip_resp_bytes' in condColumn):
                                # It is a colum that we can treat as a number
                                # Find if there is <, > or = in the condition
                                if '>' in condColumn[-1]:
                                    condColumn = condColumn[:-1]
                                    netflowValue = column_values[condColumn]
                                    if args.debug > 0:
                                        print(f'\t\tTo compare field: {condColumn}, Condition value: {condValue}, Netflow value: {netflowValue}')
                                    # Pay attention to directionality of condition 'condValue < flowvalue'
                                    if (int(condValue) < int(netflowValue)) or (condValue == 'all'):
                                        allTrue = True
                                        if args.debug > 0:
                                            print('\t\t\tTrue')
                                        continue
                                    else:
                                        if args.debug > 0:
                                            print('\t\t\tFalse')
                                        allTrue = False
                                        break
                                elif '<' in condColumn[-1]:
                                    condColumn = condColumn[:-1]
                                    netflowValue = column_values[condColumn]
                                    if args.debug > 0:
                                        print(f'\t\tTo compare field: {condColumn}, Condition value: {condValue}, Netflow value: {netflowValue}')
                                    # Pay attention to directionality of condition 'condValue > flowvalue'
                                    if (int(condValue) > int(netflowValue)) or (condValue == 'all'):
                                        allTrue = True
                                        if args.debug > 0:
                                            print('\t\t\tTrue')
                                        continue
                                    else:
                                        if args.debug > 0:
                                            print('\t\t\tFalse')
                                        allTrue = False
                                        break
                                elif '<=' in condColumn[-2]:
                                    condColumn = condColumn[:-2]
                                    netflowValue = column_values[condColumn]
                                    if args.debug > 0:
                                        print(f'\t\tTo compare field: {condColumn}, Condition value: {condValue}, Netflow value: {netflowValue}')
                                    # Pay attention to directionality of condition 'condValue >= flowvalue'
                                    if (int(condValue) >= int(netflowValue)) or (condValue == 'all'):
                                        allTrue = True
                                        if args.debug > 0:
                                            print('\t\t\tTrue')
                                        continue
                                    else:
                                        if args.debug > 0:
                                            print('\t\t\tFalse')
                                        allTrue = False
                                        break
                                elif '>=' in condColumn[-2]:
                                    condColumn = condColumn[:-2]
                                    netflowValue = column_values[condColumn]
                                    if args.debug > 0:
                                        print(f'\t\tTo compare field: {condColumn}, Condition value: {condValue}, Netflow value: {netflowValue}')
                                    # Pay attention to directionality of condition 'condValue <= flowvalue'
                                    if (int(condValue) <= int(netflowValue)) or (condValue == 'all'):
                                        allTrue = True
                                        if args.debug > 0:
                                            print('\t\t\tTrue')
                                        continue
                                    else:
                                        if args.debug > 0:
                                            print('\t\t\tFalse')
                                        allTrue = False
                                        break
                                else:
                                    netflowValue = column_values[condColumn]
                                    if args.debug > 0:
                                        print(f'\t\tTo compare field: {condColumn}, Condition value: {condValue}, Netflow value: {netflowValue}')
                                    if (int(condValue) == int(netflowValue)) or (condValue == 'all'):
                                        allTrue = True
                                        if args.debug > 0:
                                            print('\t\t\tTrue')
                                        continue
                                    else:
                                        if args.debug > 0:
                                            print('\t\t\tFalse')
                                        allTrue = False
                                        break

                            # Is the column related to an IP and the value has a / for the CIDR?
                            elif ('ip' in condColumn) and ('/' in condValue):
                                netflowValue = column_values[condColumn]
                                if ':' in condValue:
                                    temp_net = ipaddress.IPv6Network(condValue)
                                else:
                                    temp_net = ipaddress.IPv4Network(condValue)
                                temp_ip = ipaddress.ip_address(netflowValue)
                                if temp_ip in temp_net:
                                    if args.debug > 0:
                                        print(f'\t\tTo compare field: {condColumn}, Condition value: {condValue}, Netflow value: {netflowValue}')
                                    allTrue = True
                                    if args.debug > 0:
                                        print('\t\t\tTrue')
                                    continue
                                else:
                                    if args.debug > 0:
                                        print(f'\t\tTo compare field: {condColumn}, Condition value: {condValue}, Netflow value: {netflowValue}')
                                    if args.debug > 0:
                                        print('\t\t\tFalse')
                                    allTrue = False
                                    break
                            else:
                                # It is not a colum that we can treat as a number
                                netflowValue = column_values[condColumn]
                                if (condValue == netflowValue) or (condValue == 'all'):
                                    netflowValue = column_values[condColumn]
                                    if args.debug > 0:
                                        print(f'\t\tTo compare field: {condColumn}, Condition value: {condValue}, Netflow value: {netflowValue}')
                                    allTrue = True
                                    if args.debug > 0:
                                        print('\t\t\tTrue')
                                    continue
                                else:
                                    netflowValue = column_values[condColumn]
                                    if args.debug > 0:
                                        print(f'\t\tTo compare field: {condColumn}, Condition value: {condValue}, Netflow value: {netflowValue}')
                                    if args.debug > 0:
                                        print('\t\t\tFalse')
                                    allTrue = False
                                    break

                    if allTrue:
                        labelToReturn = (genericlabelToVerify, detailedlabelToVerify)
                        if args.debug > 0:
                            print('\tNew label assigned: {0}'.format(genericlabelToVerify, detailedlabelToVerify))

            if args.verbose > 0:
                if 'Background' in labelToReturn:
                    print(f'\tFinal label assigned: {labelToReturn}')
                else:
                    print(f'\tFinal label assigned: \x1b\x5b1;31;40m{labelToReturn}\x1b\x5b0;0;40m')
            return labelToReturn

        except Exception as inst:
            print('Problem in getLabel() in class labeler')
            print(type(inst))     # the exception instance
            print(inst.args)      # arguments stored in .args
            print(inst)           # __str__ allows args to printed directly
            exit(-1)

def output_netflow_line_to_file(outputfile, originalline, filetype='', genericlabel='', detailedlabel=''):
    """
    Get data and store it on a new file
    If genericlabel is empty, it is a headler line to process
    """
    try:
        if 'csv' in filetype:
            separator = ','
        elif 'tab' in filetype:
            separator = '\t'

        if type(originalline) == str and genericlabel == '':
            # It is a headerline

            # Should we add the 'label' string? Zeek has many headerlines
            if '#fields' in originalline:
                outputline = originalline.strip() + separator + 'label' + separator + 'detailedlabel' + '\n'
                outputfile.writelines(outputline)
            elif '#types' in originalline:
                outputline = originalline.strip() + separator + 'string' + separator + 'string' + '\n'
                outputfile.writelines(outputline)
            else:
                outputfile.writelines(originalline)
            # We are not putting the 'label' string in the header!
        elif type(originalline) == str and genericlabel != '':
            # These are values to store
            outputline = originalline.strip() + separator + genericlabel + separator + detailedlabel + '\n'
            outputfile.writelines(outputline)
            if args.debug > 1:
                print(f'Just outputed label {genericlabel} in line {outputline}')
            # keep it open!

    except Exception as inst:
        print('Problem in output_labeled_netflow_file()')
        print(type(inst))     # the exception instance
        print(inst.args)      # arguments stored in .args
        print(inst)           # __str__ allows args to printed directly
        exit(-1)


def process_nfdump(f, headers, labelmachine):
    """
    DEPRECATED!! NEEDS UPDATE COMPLETELY
    Process and label an nfdump file
    """
    # Just to monitor how many lines we read
    amount_lines_processed = 0

    # Parse the file into an array of dictionaries. We will use the columns names as dictionary keys
    # Example: [ {'Date': '10/10/2013} , {'SrcIp':'1.1.1.1} , , ]
    netflowArray = []
    columnDict = {}

    # Replace the TABs for spaces, if it has them..., and replace the : in the ports to spaces also, and strip the \n, and the word flow
    temp2 = headers.replace('flow', '')
    temp = re.sub('\s+', ' ', temp2).replace(':', ' ').strip()
    columnNames = temp.split(' ')

    # Only to separate src ip from dst ip
    addressType = ''

    # if args.debug > 0:
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

    # if args.debug > 0:
    #    print 'netflowArray'
    #    print netflowArray

    # Create the output file with the header
    outputfile = open(args.netflowFile+'.labeled', 'w+')

    # Write the column names
    columnnames = "Date flow start Duration        Proto   Src IP Addr:Port        Dst IP Addr:Port        Flags   Tos     Packets Bytes   Flows  Label\n"
    outputfile.writelines(columnnames)


    # Read the second line to start processing
    line = f.readline()
    amount_lines_processed += 1
    while (line):
        if args.verbose > 0:
            print('Netflow line: {0}'.format(line), end=' ')

        # Parse the columns
        # Strip and replace ugly stuff
        temp2 = line.replace('->', '')
        temp = re.sub('\s+', ' ', temp2).strip()
        columnValues = temp.split(' ')

        # Date
        date = columnValues[0]
        # Store the value in the dict
        dict = netflowArray[0]
        columnName = list(dict.keys())[0]
        dict[columnName] = date
        netflowArray[0] = dict

        hour = columnValues[1]
        # Store the value in the dict
        dict = netflowArray[1]
        columnName = list(dict.keys())[0]
        dict[columnName] = hour
        netflowArray[1] = dict

        duration = columnValues[2]
        # Store the value in the dict
        dict = netflowArray[2]
        columnName = list(dict.keys())[0]
        dict[columnName] = duration
        netflowArray[2] = dict

        protocol = columnValues[3].upper()
        # Store the value in the dict
        dict = netflowArray[3]
        columnName = list(dict.keys())[0]
        # columnName = 'Proto'
        dict[columnName] = protocol
        netflowArray[3] = dict

        if 'TCP' in protocol or 'UDP' in protocol or 'RTP' in protocol:
            temp = columnValues[4]
            if len(temp.split(':')) <= 2:
                # It is IPV4
                srcip = temp.split(':')[0]
                # Store the value in the dict
                dict = netflowArray[4]
                columnName = list(dict.keys())[0]
                dict[columnName] = srcip
                netflowArray[4] = dict

                srcport = temp.split(':')[1]
                # Store the value in the dict
                dict = netflowArray[5]
                columnName = list(dict.keys())[0]
                dict[columnName] = srcport
                netflowArray[5] = dict

                temp2 = columnValues[5]
                dstip = temp2.split(':')[0]
                # Store the value in the dict
                dict = netflowArray[6]
                columnName = list(dict.keys())[0]
                dict[columnName] = dstip
                netflowArray[6] = dict

                dstport = temp2.split(':')[1]
                # Store the value in the dict
                dict = netflowArray[7]
                columnName = list(dict.keys())[0]
                dict[columnName] = dstport
                netflowArray[7] = dict
            elif len(temp.split(':')) > 2:
                # We are using ipv6! THIS DEPENDS A LOT ON THE program that created the netflow..
                srcip = temp[0:temp.rfind(':')]
                # Store the value in the dict
                dict = netflowArray[4]
                columnName = list(dict.keys())[0]
                dict[columnName] = srcip
                netflowArray[4] = dict

                srcport = temp[temp.rfind(':')+1:]
                # Store the value in the dict
                dict = netflowArray[5]
                columnName = list(dict.keys())[0]
                dict[columnName] = srcport
                netflowArray[5] = dict

                temp2 = columnValues[5]
                dstip = temp2[0:temp2.rfind(':')]
                # Store the value in the dict
                dict = netflowArray[6]
                columnName = list(dict.keys())[0]
                dict[columnName] = dstip
                netflowArray[6] = dict

                dstport = temp2[temp2.rfind(':')+1:]
                # Store the value in the dict
                dict = netflowArray[7]
                columnName = list(dict.keys())[0]
                dict[columnName] = dstport
                netflowArray[7] = dict
            else:
                print()
                print('Please implement this protocol!')
                print(line)
                sys.exit(-1)
        elif protocol == 'IPNIP' or protocol == 'RSVP' or protocol == 'GRE' or protocol == 'UDT' or protocol == 'ARP' or protocol == 'ICMP' or protocol == 'PIM' or protocol == 'ESP' or protocol == 'UNAS' or protocol == 'IGMP' or 'IPX' in protocol or 'RARP' in protocol or 'LLC' in protocol or 'IPV6' in protocol:
            srcip = temp = columnValues[4]
            # Store the value in the dict
            dict = netflowArray[4]
            columnName = list(dict.keys())[0]
            dict[columnName] = srcip
            netflowArray[4] = dict

            srcport = '0'
            # Store the value in the dict
            dict = netflowArray[5]
            columnName = list(dict.keys())[0]
            dict[columnName] = srcport
            netflowArray[5] = dict

            dstip = temp = columnValues[5]
            # Store the value in the dict
            dict = netflowArray[6]
            columnName = list(dict.keys())[0]
            dict[columnName] = dstip
            netflowArray[6] = dict

            dstport = '0'
            # Store the value in the dict
            dict = netflowArray[7]
            columnName = list(dict.keys())[0]
            dict[columnName] = dstport
            netflowArray[7] = dict

        flags = columnValues[6].upper()
        # Store the value in the dict
        dict = netflowArray[8]
        columnName = list(dict.keys())[0]
        dict[columnName] = flags
        netflowArray[8] = dict

        tos = columnValues[7]
        # Store the value in the dict
        dict = netflowArray[9]
        columnName = list(dict.keys())[0]
        dict[columnName] = tos
        netflowArray[9] = dict

        packets = columnValues[8]
        # Store the value in the dict
        dict = netflowArray[10]
        columnName = list(dict.keys())[0]
        dict[columnName] = packets
        netflowArray[10] = dict

        bytes = columnValues[9]
        # Store the value in the dict
        dict = netflowArray[11]
        columnName = list(dict.keys())[0]
        dict[columnName] = bytes
        netflowArray[11] = dict

        flows = columnValues[10]
        # Store the value in the dict
        dict = netflowArray[12]
        columnName = list(dict.keys())[0]
        dict[columnName] = flows
        netflowArray[12] = dict

        # Empty the label in the dict
        dict = netflowArray[13]
        columnName = list(dict.keys())[0]
        dict[columnName] = ""
        netflowArray[13] = dict

        # if args.debug > 0:
        #    print date,hour,duration,protocol, srcip, srcport, dstip, dstport, flags, tos, packets, bytes, flows
        #    print netflowArray


        # Request a label
        genericlabel, detailedlabel = labelmachine.getLabel(netflowArray)
        # Store the value in the dict
        dict = netflowArray[13]
        columnName = list(dict.keys())[0]
        dict[columnName] = genericlabel
        netflowArray[13] = dict

        # if args.debug > 0:
        #    print netflowArray

        # Ask to store the netflow
        output_netflow_line_to_file(outputfile, netflowArray)


        line = f.readline()
        amount_lines_processed += 1

    # Close the outputfile
    outputfile.close()


def define_columns(headerline, filetype):
    """ Define the columns for Argus and Zeek-tab from the line received """
    # These are the indexes for later fast processing
    column_idx = {}
    column_idx['starttime'] = False
    column_idx['endtime'] = False
    column_idx['dur'] = False
    column_idx['proto'] = False
    column_idx['appproto'] = False
    column_idx['srcip'] = False
    column_idx['srcport'] = False
    column_idx['dir'] = False
    column_idx['dstip'] = False
    column_idx['dstport'] = False
    column_idx['state'] = False
    column_idx['pkts'] = False
    column_idx['spkts'] = False
    column_idx['dpkts'] = False
    column_idx['bytes'] = False
    column_idx['sbytes'] = False
    column_idx['dbytes'] = False
    column_idx['orig_ip_bytes'] = False
    column_idx['resp_ip_bytes'] = False
    column_idx['history'] = False
    column_idx['event_type'] = False
    column_idx['uid'] = False
    column_idx['local_orig'] = False
    column_idx['local_resp'] = False
    column_idx['missed_bytes'] = False
    column_idx['tunnel_parents'] = False

    try:
        if 'csv' in filetype or 'tab' in filetype:
            # This should work for zeek-csv, zeek-tab, argus-csv, nfdump-csv
            if 'csv' in filetype:
                separator = ','
            elif 'tab' in filetype:
                separator = '\t'
            nline = headerline.strip().split(separator)
            try:
                # Remove the extra column of zeek if it is there
                nline.remove('#fields')
            except ValueError:
                # ignore if #fields is not there
                pass
            if args.debug > 1:
                print(f'Headers line: {nline}')
            for field in nline:
                if args.debug > 2:
                    print(f'Field: {field.lower()}, index: {nline.index(field)}')
                if 'time' in field.lower() or field.lower() == 'ts':
                    column_idx['starttime'] = nline.index(field)
                elif 'uid' in field.lower():
                    column_idx['uid'] = nline.index(field)
                elif 'dur' in field.lower():
                    column_idx['dur'] = nline.index(field)
                elif 'proto' in field.lower():
                    column_idx['proto'] = nline.index(field)
                elif 'srca' in field.lower() or 'id.orig_h' in field.lower():
                    column_idx['srcip'] = nline.index(field)
                elif 'srcport' in field.lower() or 'id.orig_p' in field.lower():
                    column_idx['srcport'] = nline.index(field)
                elif 'dir' in field.lower():
                    column_idx['dir'] = nline.index(field)
                elif 'dsta' in field.lower() or 'id.resp_h' in field.lower():
                    column_idx['dstip'] = nline.index(field)
                elif 'dstport' in field.lower() or 'id.resp_p' in field.lower():
                    column_idx['dstport'] = nline.index(field)
                elif 'state' in field.lower():
                    column_idx['state'] = nline.index(field)
                elif 'srcbytes' in field.lower() or 'orig_bytes' in field.lower():
                    column_idx['sbytes'] = nline.index(field)
                elif 'destbytes' in field.lower() or 'resp_bytes' in field.lower():
                    column_idx['dbytes'] = nline.index(field)
                elif 'service' in field.lower():
                    column_idx['appproto'] = nline.index(field)
                elif 'srcpkts' in field.lower() or 'orig_pkts' in field.lower():
                    column_idx['spkts'] = nline.index(field)
                elif 'destpkts' in field.lower() or 'resp_pkts' in field.lower():
                    column_idx['dpkts'] = nline.index(field)
                elif 'totpkts' in field.lower():
                    column_idx['pkts'] = nline.index(field)
                elif 'totbytes' in field.lower():
                    column_idx['bytes'] = nline.index(field)
                elif 'history' in field.lower():
                    column_idx['history'] = nline.index(field)
                elif 'orig_ip_bytes' in field.lower():
                    column_idx['orig_ip_bytes'] = nline.index(field)
                elif 'resp_ip_bytes' in field.lower():
                    column_idx['resp_ip_bytes'] = nline.index(field)
                elif 'local_orig' in field.lower():
                    column_idx['local_orig'] = nline.index(field)
                elif 'local_resp' in field.lower():
                    column_idx['local_resp'] = nline.index(field)
                elif 'missed_bytes' in field.lower():
                    column_idx['missed_bytes'] = nline.index(field)
                elif 'tunnel_parents' in field.lower():
                    column_idx['tunnel_parents'] = nline.index(field)
        elif 'json' in filetype:
            if 'timestamp' in headerline:
                # Suricata json
                column_idx['starttime'] = 'timestamp'
                column_idx['srcip'] = 'src_ip'
                column_idx['dur'] = False
                column_idx['proto'] = 'proto'
                column_idx['srcport'] = 'src_port'
                column_idx['dstip'] = 'dst_ip'
                column_idx['dstport'] = 'dest_port'
                column_idx['spkts'] = 'flow/pkts_toserver'
                column_idx['dpkts'] = 'flow/pkts_toclient'
                column_idx['sbytes'] = 'flow/bytes_toserver'
                column_idx['dbytes'] = 'flow/bytes_toclient'
                column_idx['event_type'] = 'event_type'
            elif 'ts' in headerline:
                # Zeek json
                column_idx['starttime'] = 'ts'
                column_idx['srcip'] = 'id.orig_h'
                column_idx['endtime'] = ''
                column_idx['dur'] = 'duration'
                column_idx['proto'] = 'proto'
                column_idx['appproto'] = 'service'
                column_idx['srcport'] = 'id.orig_p'
                column_idx['dstip'] = 'id.resp_h'
                column_idx['dstport'] = 'id.resp_p'
                column_idx['state'] = 'conn_state'
                column_idx['pkts'] = ''
                column_idx['spkts'] = 'orig_pkts'
                column_idx['dpkts'] = 'resp_pkts'
                column_idx['bytes'] = ''
                column_idx['sbytes'] = 'orig_bytes'
                column_idx['dbytes'] = 'resp_bytes'
                column_idx['orig_ip_bytes'] = 'orig_ip_bytes'
                column_idx['resp_ip_bytes'] = 'resp_ip_bytes'
                column_idx['history'] = 'history'

        # Some of the fields were not found probably,
        # so just delete them from the index if their value is False.
        # If not we will believe that we have data on them
        # We need a temp dict because we can not change the size of dict while analyzing it
        temp_dict = {}
        for i in column_idx:
            if type(column_idx[i]) == bool and column_idx[i] == False:
                continue
            temp_dict[i] = column_idx[i]
        column_idx = temp_dict

        return column_idx
    except Exception as inst:
        exception_line = sys.exc_info()[2].tb_lineno
        print(f'\tProblem in define_columns() line {exception_line}', 0, 1)
        print(str(type(inst)), 0, 1)
        print(str(inst), 0, 1)
        sys.exit(1)


def define_type(data):
    """
    Try to define very fast the type of input from :Zeek file, Suricata json, Argus binetflow CSV, Argus binetflow TSV
    Using a Heuristic detection
    Input: The first line after the headers if there were some, as 'data'
    Outputs types can be can be: zeek-json, suricata, argus-tab, argus-csv, zeek-tab
    """
    try:
        # If line json, it can be Zeek or suricata
        # If line CSV, it can be Argus
        # If line TSV, it can be Argus or zeek

        input_type = 'unknown'

        # Is it json?
        try:
            json_line = json.loads(data)
            # json
            try:
                # Zeek?
                _ = json_line['ts']
                input_type = 'zeek-json'
                return input_type
            except KeyError:
                # Suricata?
                _ = json_line['timestamp']
                input_type = 'suricata-json'
                return input_type
        except json.JSONDecodeError:
            # No json
            if type(data) == str:
                # string
                nr_commas = len(data.split(','))
                nr_tabs = len(data.split('	'))
                if nr_commas > nr_tabs:
                    # Commas is the separator
                    if nr_commas > 40:
                        input_type = 'nfdump-csv'
                    else:
                        # comma separated argus file
                        input_type = 'argus-csv'
                elif nr_tabs >= nr_commas:
                    # Tabs is the separator or it can be also equal number of commas and tabs, including both 0
                    # Can be Zeek conn.log with TABS
                    # Can be Argus binetflow with TABS
                    # Can be Nfdump binetflow with TABS
                    if '->' in data or 'StartTime' in data:
                        input_type = 'argus-tab'
                    elif 'separator' in data:
                        input_type = 'zeek-tab'
                    elif 'Date' in data:
                        input_type = 'nfdump-tab'

            return input_type

    except Exception as inst:
        exception_line = sys.exc_info()[2].tb_lineno
        print(f'\tProblem in define_type() line {exception_line}', 0, 1)
        print(str(type(inst)), 0, 1)
        print(str(inst), 0, 1)
        sys.exit(1)

def process_zeek(column_idx, input_file, output_file, labelmachine, filetype):
    """
    Process a Zeek file
    The filetype can be: 'tab', 'csv', 'json'
    """
    try:
        amount_lines_processed = 0
        column_values = {}

        # Read firstlines
        line = input_file.readline()

        # Delete headerlines
        while '#' in line:
            line = input_file.readline()

        while (line):
            # Count the first line
            amount_lines_processed += 1

            if args.verbose > 0:
                print(f'Netflow line: {line}', end='')

            if 'csv' in filetype or 'tab' in filetype:
                # Work with csv and tabs
                if 'csv' in filetype:
                    separator = ','
                elif 'tab' in filetype:
                    separator = '\t'
                # Transform the line into an array
                line_values = line.split(separator)

                # Read values from the flow line
                for key in column_idx:
                    column_values[key] = line_values[column_idx[key]]

                # Create the hand-made columns that are a sum of other columns
                # First empty them
                column_values['bytes'] = ''
                column_values['pkts'] = ''
                column_values['ipbytes'] = ''

                # Sum bytes
                # We do it like this because sometimes the column can be - or 0
                if column_values['sbytes'] == '-':
                    sbytes = 0
                else:
                    sbytes = int(column_values['sbytes'])
                if column_values['dbytes'] == '-':
                    dbytes = 0
                else:
                    dbytes = int(column_values['dbytes'])
                column_values['bytes'] = str(sbytes + dbytes)
                # print(f'New column bytes = {column_values["bytes"]}')

                # Sum packets
                # We do it like this because sometimes the column can be - or 0
                if column_values['spkts'] == '-':
                    spkts = 0
                else:
                    spkts = int(column_values['spkts'])
                if column_values['dpkts'] == '-':
                    dpkts = 0
                else:
                    dpkts = int(column_values['dpkts'])
                column_values['pkts'] = str(spkts + dpkts)
                # print(f'New column pkst = {column_values["pkts"]}')

                # Sum ip_bytes
                # We do it like this because sometimes the column can be - or 0
                if column_values['orig_ip_bytes'] == '-':
                    sip_bytes = 0
                else:
                    sip_bytes = int(column_values['orig_ip_bytes'])
                if column_values['resp_ip_bytes'] == '-':
                    dip_bytes = 0
                else:
                    dip_bytes = int(column_values['resp_ip_bytes'])
                column_values['ipbytes'] = str(sip_bytes + dip_bytes)
                # print(f'New column ipbytes = {column_values["ipbytes"]}')

                # Request a label
                genericlabel, detailedlabel = labelmachine.getLabel(column_values)
                if args.debug > 1:
                    print(f'Label {genericlabel} assigned in line {line}')

                # Store the netflow
                output_netflow_line_to_file(output_file, line, filetype, genericlabel=genericlabel, detailedlabel=detailedlabel)

                line = input_file.readline()
                while '#' in line:
                    line = input_file.readline()

            elif 'json' in filetype:
                # Count the first line
                amount_lines_processed += 1
                pass



        return amount_lines_processed
    except Exception as inst:
        exception_line = sys.exc_info()[2].tb_lineno
        print(f'\tProblem in process_zeek() line {exception_line}', 0, 1)
        print(str(type(inst)), 0, 1)
        print(str(inst), 0, 1)
        sys.exit(1)

def process_argus(column_idx, output_file, labelmachine, filetype):
    """
    DEPRECATED!! NEEDS UPDATE COMPLETELY
    Process an Argus file
    """
    try:
        print(column_idx)
        return 0

        # This is argus files...
        amount_lines_processed = 0

        # Parse the file into an array of dictionaries. We will use the columns names as dictionary keys
        # Example: [ {'Date': '10/10/2013} , {'SrcIp':'1.1.1.1} , , ]
        netflowArray = []
        columnDict = {}

        # Replace the TABs for spaces, if it has them..., and replace the : in the ports to spaces also, and strip the \n, and the word flow
        temp = re.sub('\s+', ' ', headers).strip()
        columnNames = temp.split(' ')

        # if args.debug > 0:
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

        # Write the column names
        columnnames = "Date Time       Dur     Proto   SrcAddr Sport   Dir     DstAddr Dport   State   sTos    TotPkts TotBytes Label\n"
        output_file.writelines(columnnames)


        # Read the second line to start processing
        line = f.readline()
        amount_lines_processed += 1
        while (line):
            if args.verbose > 0:
                print('Netflow line: {0}'.format(line), end=' ')

            # Parse the columns
            # Strip and replace ugly stuff
            temp2 = line.replace('->', '')
            temp = re.sub('\s+', ' ', temp2).strip()
            columnValues = temp.split(' ')

            # if args.debug > 0:
            #    print columnValues

            # Date
            date = columnValues[0]
            # Store the value in the dict
            dict = netflowArray[0]
            columnName = list(dict.keys())[0]
            dict[columnName] = date
            netflowArray[0] = dict

            hour = columnValues[1]
            # Store the value in the dict
            dict = netflowArray[1]
            columnName = list(dict.keys())[0]
            dict[columnName] = hour
            netflowArray[1] = dict

            duration = columnValues[2]
            # Store the value in the dict
            dict = netflowArray[2]
            columnName = list(dict.keys())[0]
            dict[columnName] = duration
            netflowArray[2] = dict

            protocol = columnValues[3].upper()
            # Store the value in the dict
            dict = netflowArray[3]
            columnName = list(dict.keys())[0]
            dict[columnName] = protocol
            netflowArray[3] = dict

            srcIP = columnValues[4]
            # Store the value in the dict
            dict = netflowArray[4]
            columnName = list(dict.keys())[0]
            dict[columnName] = srcIP
            netflowArray[4] = dict

            if 'ARP' in protocol:
                srcPort = '0'
                # Store the value in the dict
                dict = netflowArray[5]
                columnName = list(dict.keys())[0]
                dict[columnName] = srcPort
                netflowArray[5] = dict
            else:
                srcPort = columnValues[5]
                # Store the value in the dict
                dict = netflowArray[5]
                columnName = list(dict.keys())[0]
                dict[columnName] = srcPort
                netflowArray[5] = dict


            dstIP = columnValues[6]
            # Store the value in the dict
            dict = netflowArray[6]
            columnName = list(dict.keys())[0]
            dict[columnName] = dstIP
            netflowArray[6] = dict


            if 'ARP' in protocol:
                dstPort = '0'
                # Store the value in the dict
                dict = netflowArray[7]
                columnName = list(dict.keys())[0]
                dict[columnName] = dstPort
                netflowArray[7] = dict

                Flags = columnValues[8]
                # Store the value in the dict
                dict = netflowArray[8]
                columnName = list(dict.keys())[0]
                dict[columnName] = Flags
                netflowArray[8] = dict

            else:
                dstPort = columnValues[7]
                # Store the value in the dict
                dict = netflowArray[7]
                columnName = list(dict.keys())[0]
                dict[columnName] = dstPort
                netflowArray[7] = dict

                Flags = columnValues[8]
                # Store the value in the dict
                dict = netflowArray[8]
                columnName = list(dict.keys())[0]
                dict[columnName] = Flags
                netflowArray[8] = dict

            if 'LLC' in protocol:
                Tos = '0'
                # Store the value in the dict
                dict = netflowArray[9]
                columnName = list(dict.keys())[0]
                dict[columnName] = Tos
                netflowArray[9] = dict

                Packets = columnValues[9]
                # Store the value in the dict
                dict = netflowArray[10]
                columnName = list(dict.keys())[0]
                dict[columnName] = Packets
                netflowArray[10] = dict

                Bytes = columnValues[10]
                # Store the value in the dict
                dict = netflowArray[11]
                columnName = list(dict.keys())[0]
                dict[columnName] = Bytes
                netflowArray[11] = dict

                # Request a label
                genericlabellabel, detailedlabel = labelmachine.getLabel(netflowArray)
                # Store the value in the dict
                dict = netflowArray[12]
                columnName = list(dict.keys())[0]
                dict[columnName] = genericlabellabel
                netflowArray[12] = dict
            elif 'ARP' in protocol:
                Tos = '0'
                # Store the value in the dict
                dict = netflowArray[9]
                columnName = list(dict.keys())[0]
                dict[columnName] = Tos
                netflowArray[9] = dict

                Packets = columnValues[8]
                # Store the value in the dict
                dict = netflowArray[10]
                columnName = list(dict.keys())[0]
                dict[columnName] = Packets
                netflowArray[10] = dict

                Bytes = columnValues[9]
                # Store the value in the dict
                dict = netflowArray[11]
                columnName = list(dict.keys())[0]
                dict[columnName] = Bytes
                netflowArray[11] = dict

                # Request a label
                genericlabellabel, detailedlabel = labelmachine.getLabel(netflowArray)
                # Store the value in the dict
                dict = netflowArray[12]
                columnName = list(dict.keys())[0]
                dict[columnName] = genericlabellabel
                netflowArray[12] = dict
            else:
                Tos = columnValues[9]
                # Store the value in the dict
                dict = netflowArray[9]
                columnName = list(dict.keys())[0]
                dict[columnName] = Tos
                netflowArray[9] = dict

                Packets = columnValues[10]
                # Store the value in the dict
                dict = netflowArray[10]
                columnName = list(dict.keys())[0]
                dict[columnName] = Packets
                netflowArray[10] = dict

                Bytes = columnValues[11]
                # Store the value in the dict
                dict = netflowArray[11]
                columnName = list(dict.keys())[0]
                dict[columnName] = Bytes
                netflowArray[11] = dict

                # Request a label
                genericlabellabel, detailedlabel = labelmachine.getLabel(netflowArray)
                # Store the value in the dict
                dict = netflowArray[12]
                columnName = list(dict.keys())[0]
                dict[columnName] = genericlabellabel
                netflowArray[12] = dict

            # if args.debug > 0:
            #    print netflowArray

            # Ask to store the netflow
            output_netflow_line_to_file(output_file, netflowArray)

            line = f.readline()
            amount_lines_processed += 1
    except Exception as inst:
        exception_line = sys.exc_info()[2].tb_lineno
        print(f'\tProblem in process_argus() line {exception_line}', 0, 1)
        print(str(type(inst)), 0, 1)
        print(str(inst), 0, 1)
        sys.exit(1)

def process_netflow(labelmachine):
    """
    This function takes the flowFile and parse it. Then it ask for a label and finally it calls a function to store the netflow in a file
    """
    try:
        if args.verbose > 0:
            print('[+] Processing the flow file {0}'.format(args.netflowFile))

        # Open flows file
        try:
            input_file = open(args.netflowFile, 'r')
        except Exception as inst:
            print('Some problem opening the input netflow file. In process_netflow()')
            print(type(inst))     # the exception instance
            print(inst.args)      # arguments stored in .args
            print(inst)           # __str__ allows args to printed directly
            exit(-1)

        # ---- Define the type of file
        headerline = input_file.readline()

        # If there are no headers, get out. Most start with '#' but Argus starts with 'StartTime' and nfdump with 'Date'
        if '#' not in headerline[0] and 'Date' not in headerline and 'StartTime' not in headerline and 'ts' not in headerline and 'timestamp' not in headerline:
            print('The file has not headers. Please add them.')
            sys.exit(-1)

        filetype = define_type(headerline)
        if args.verbose > 0:
            print(f'[+] Type of flow file to label: {filetype}')

        # Create the output file for all cases
        output_file = open(args.netflowFile+'.labeled', 'w+')

        # Store the headers in the output file
        output_netflow_line_to_file(output_file, headerline)

        # ---- Define the columns
        if filetype == 'zeek-json':
            column_idx = define_columns(headerline, filetype='json')
            amount_lines_processed = 0
        elif filetype == 'suricata-json':
            column_idx = define_columns(headerline, filetype='json')
            amount_lines_processed = 0
        elif filetype == 'nfdump-csv':
            column_idx = define_columns(headerline, filetype='csv')
            amount_lines_processed = 0
        elif filetype == 'argus-csv':
            column_idx = define_columns(headerline, filetype='csv')
            amount_lines_processed = process_argus(column_idx, input_file, output_file, labelmachine, filetype='csv')
        elif filetype == 'argus-tab':
            column_idx = define_columns(headerline, filetype='tab')
            amount_lines_processed = process_argus(column_idx, input_file, output_file, labelmachine, filetype='tab')
        elif filetype == 'zeek-tab':
            # Get all the other headers first
            while '#types' not in headerline:
                # Go through all the # headers, but rememeber the #fields one
                if '#fields' in headerline:
                    fields_headerline = headerline
                headerline = input_file.readline()
                # Store the rest of the zeek headers in the output file
                output_netflow_line_to_file(output_file, headerline, filetype='tab')
            # Get the columns indexes
            column_idx = define_columns(fields_headerline, filetype='tab')
            # Process the whole file
            amount_lines_processed = process_zeek(column_idx, input_file, output_file, labelmachine, filetype='tab')
            # Close the netflow file
            input_file.close()
        elif filetype == 'nfdump-tab':
            column_idx = define_columns(headerline, filetype='tab')
            amount_lines_processed = process_nfdump(column_idx, input_file, output_file, headerline, labelmachine)

        # Close the outputfile
        output_file.close()

        print('Amount of lines read: {0}'.format(amount_lines_processed))

    except Exception as inst:
        exception_line = sys.exc_info()[2].tb_lineno
        print(f'Problem in process_netflow() line {exception_line}', 0, 1)
        print(type(inst))     # the exception instance
        print(inst.args)      # arguments stored in .args
        print(inst)           # __str__ allows args to printed directly
        exit(-1)


def loadConditions(labelmachine):
    """
    Load the labelling conditions from a conf file
    """
    conditionsList = []
    try:
        conf = open(args.configFile)
        # try:
        #    if args.verbose > 0:
        #        print('Opening the configuration file \'{0}\''.format(args.configFile))
        #    conf = open(args.configFile)
        # except:
        #    print('The file \'{0}\' couldn\'t be opened.'.format(args.configFile))
        #    exit(1)

        if args.debug > 0:
            print('Loading the conditions from the configuration file ')

        # Read the conf file
        line = conf.readline().strip()
        conditions = {}

        while (line):
            # Ignore comments
            if line.strip().find('#') == 0:
                line = conf.readline().strip()
                continue

            # Read a label
            if line.strip()[0] != '-':
                label = line.split(':')[0]
                # if args.debug > 0:
                #    print 'Label: {}'.format(label)
                conditions[label]=[]

                # Now read all the conditions for this label
                line = conf.readline().strip()
                while (line):
                    if line.strip()[0] == '-':
                        # Condition
                        tempAndConditions = line.strip().split('-')[1]
                        if args.debug > 1:
                            print('Condition: {}'.format(tempAndConditions))
                        andConditions = []
                        for andCond in tempAndConditions.split('&'):
                            tempdict = {}
                            tempdict[andCond.strip().split('=')[0]] = andCond.strip().split('=')[1]
                            andConditions.append(tempdict)

                        conditions[label].append(andConditions)

                        line = conf.readline().strip()
                    else:
                        break
            labelmachine.addCondition(conditions)
            conditions = {}

    except KeyboardInterrupt:
        # CTRL-C pretty handling.
        print("Keyboard Interruption!. Exiting.")
        sys.exit(1)
    except Exception as inst:
        print('Problem in main() function at loadConditions ')
        print(type(inst))     # the exception instance
        print(inst.args)      # arguments stored in .args
        print(inst)           # __str__ allows args to printed directly
        sys.exit(-1)
        return False

if __name__ == '__main__':
    print('NetFlow labeler. Version {}'.format(version))
    print('https://stratosphereips.org')

    # Parse the parameters
    parser = argparse.ArgumentParser(description="Tool to label netflow files", add_help=False)
    parser.add_argument('-c', '--configFile', metavar='<configFile>', action='store', required=True, help='path to labeling rules configuration.')
    parser.add_argument('-v', '--verbose', metavar='<verbose>', action='store', required=False, type=int, default=0, help='amount of verbosity. This shows more info about the results.')
    parser.add_argument('-d', '--debug', action='store', required=False, type=int, default=0, help='amount of debugging. This shows inner information about the program.')
    parser.add_argument('-f', '--netflowFile', metavar='<netflowFile>', action='store', required=True, help='file to label.')
    parser.add_argument("-h", "--help", action="help", help="command line help")
    args = parser.parse_args()

    try:
        # Create an instance of the labeler
        labelmachine = labeler()

        # Load conditions
        loadConditions(labelmachine)

        # Direct process of netflow flows
        process_netflow(labelmachine)
    except KeyboardInterrupt:
        # CTRL-C pretty handling.
        print("Keyboard Interruption!. Exiting.")
        sys.exit(1)

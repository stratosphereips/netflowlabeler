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
import json
import argparse
import os
from os import listdir
from os.path import isfile, join

version = "0.1"


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
        # If line TSV, it can be Argus  or zeek

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
                #print(f'New column bytes = {column_values["bytes"]}')

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
                #print(f'New column pkst = {column_values["pkts"]}')

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
                #print(f'New column ipbytes = {column_values["ipbytes"]}')

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


def process_zeekfolder():
    """
    This function takes the flowFile and parse it. Then it ask for a label and finally it calls a function to store the netflow in a file
    """
    try:
        if args.verbose > 0:
            print('[+] Processing the zeek folder {0}'.format(args.zeekfolder))

        # Open labeled flows file and get the columns
        try:
            input_labeled_file = open(args.labeledfile,'r')
        except Exception as inst:
            print('Some problem opening the input labeled netflow file. In process_netflow()')
            print(type(inst))     # the exception instance
            print(inst.args)      # arguments stored in .args
            print(inst)           # __str__ allows args to printed directly
            exit(-1)

        # Get the first header line to find the type
        headerline = input_labeled_file.readline()

        # If there are no headers, get out. Most start with '#' but Argus starts with 'StartTime' and nfdump with 'Date' 
        if '#' not in headerline[0]:
            print('The labeled file has not headers. Please add them.')
            sys.exit(-1)

        # Define the type of file
        filetype = define_type(headerline)
        if args.verbose > 0:
            print(f'[+] Type of labeled file to label: {filetype}')

        # Define the columns 
        if filetype == 'zeek-json':
            column_idx = define_columns(headerline, filetype='json')
            amount_lines_processed = 0
        elif filetype == 'zeek-tab':
            # Get all the other headers first
            while '#types' not in headerline:
                # Go through all the # headers, but rememeber the #fields one
                if '#fields' in headerline:
                    fields_headerline = headerline
                headerline = input_labeled_file.readline()
            # Get the columns indexes
            input_labeled_file_column_idx = define_columns(fields_headerline, filetype='tab')
            # Set the fields separator
            input_labeled_file_separator = '\t'



        # ----- Work with zeek files in the folder

        # Get the list of files in this folder
        zeekfiles = [f for f in listdir(args.zeekfolder) if isfile(join(args.zeekfolder, f))]

        for zeekfile_name in zeekfiles:

            # Ignore labeled files, summary fle and conn.log file
            if '.labeled' in zeekfile_name or 'summary' in zeekfile_name or 'conn.log' in zeekfile_name:
                continue

            # Ignore empty files
            if os.stat(join(args.zeekfolder, zeekfile_name)).st_size == 0:
                continue

            if args.verbose > 0:
                print(f'[+] Processing zeek file: {zeekfile_name}')

            try:
                zeekfile = open(join(args.zeekfolder, zeekfile_name),'r')
            except Exception as inst:
                print(f'Some problem opening a zeek file {zeekfile_name}. In process_zeekfolder()')
                print(type(inst))     # the exception instance
                print(inst.args)      # arguments stored in .args
                print(inst)           # __str__ allows args to printed directly
                exit(-1)

            # Get the first header line to find the type
            headerline = zeekfile.readline()

            # If there are no headers, get out. Most start with '#' but Argus starts with 'StartTime' and nfdump with 'Date' 
            if '#' not in headerline[0]:
                print('The file has not headers. Please add them.')
                sys.exit(-1)

            # ---- Define the type of file
            filetype = define_type(headerline)
            if args.verbose > 0:
                print(f'[+] Type of flow file to label: {filetype}')

            # Create the output file for all cases
            output_file = open(join(args.zeekfolder, zeekfile_name+'.labeled'),'w')
            if args.debug > 1:
                print(f"[+] Output file created: {join(args.zeekfolder, zeekfile_name+'.labeled')}")

            # Store the first header line in the output file
            output_netflow_line_to_file(output_file, headerline)

            # ---- Define the columns 
            if filetype == 'zeek-json':
                column_idx = define_columns(headerline, filetype='json')
                amount_lines_processed = 0
            elif filetype == 'zeek-tab':
                # Get all the other headers first
                while '#types' not in headerline:
                    # Go through all the # headers, but rememeber the #fields one
                    if '#fields' in headerline:
                        fields_headerline = headerline
                    headerline = zeekfile.readline()
                    # Store the rest of the zeek headers in the output file
                    output_netflow_line_to_file(output_file, headerline, filetype='tab')
                # Get the columns indexes
                column_idx = define_columns(fields_headerline, filetype='tab')

            # ---- Read the lines from the labeled file

            # Read each line of the labeled file and get the zeek uid
            inputline = input_labeled_file.readline()
            while not '#' in inputline:
                inputline = input_labeled_file.readline()

                # Transform the line into an array
                line_values = inputline.split(input_labeled_file_separator)
                # Read column values from the flow line
                labeled_uid = line_values[input_labeled_file_column_idx['uid']]


            #amount_lines_processed = process_zeek(column_idx, zeekfile, output_file, filetype='tab')

        # Close the input file
        input_labeled_file.close()
        zeekfile.close()
        # Close the outputfile
        output_file.close()

        #print('Amount of lines read: {0}'.format(amount_lines_processed))

    except Exception as inst:
        exception_line = sys.exc_info()[2].tb_lineno
        print(f'Problem in process_zeekfolder() line {exception_line}', 0, 1)
        print(type(inst))     # the exception instance
        print(inst.args)      # arguments stored in .args
        print(inst)           # __str__ allows args to printed directly
        exit(-1)


if __name__ == '__main__':
    print('Zeek Files labeler from labeled conn.log.labeled file. Version {}'.format(version))
    print('https://stratosphereips.org')

    # Parse the parameters
    parser = argparse.ArgumentParser(description="Given a conn.log.labeled file, copy those labels to the rest of the Zeek log files", add_help=False)
    parser.add_argument('-l','--labeledfile', metavar='<labelFile>', action='store', required=True, help='path to labeled conn.log file.')
    parser.add_argument('-v', '--verbose',metavar='<verbose>',action='store', required=False, type=int, default=0, help='amount of verbosity. This shows more info about the results.')
    parser.add_argument('-d', '--debug', action='store', required=False, type=int, default=0, help='amount of debugging. This shows inner information about the program.')
    parser.add_argument('-f', '--zeekfolder',metavar='<zeekFolder>', action='store', required=True, help='folder with Zeek files to label.')
    parser.add_argument("-h", "--help", action="help", help="command line help")
    args = parser.parse_args()

    try:
        # Process zeek files in the folder
        process_zeekfolder()

    except KeyboardInterrupt:
        # CTRL-C pretty handling.
        print("Keyboard Interruption!. Exiting.")
        sys.exit(1)



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
"""
Zeek files labeler

A tool that effortlessly adds labels to netflow files. With support for Zeek, Argus, and NFdump
formats in both CSV and TSV.

Authors:
   Sebastian Garcia, sebastian.garcia@agents.fel.cvut.cz, eldraco@gmail.com
   Veronica Valeros, vero.valeros@gmail.com
   Stratosphere Laboratory, Czech Technical University in Prague
"""


import sys
import json
import argparse
import os
from os import listdir
from os.path import isfile, join
import subprocess

VERSION = "0.1"


def output_netflow_line_to_file(outputfile, originalline, filetype='', genericlabel='', detailedlabel=''):
    """
    Store the input line with its labels into the output file. If 'genericlabel' is empty, it means
    the input line is a header line, and requires special processing.
        - Input: outpuffile, originalline, filetype, genericlabel and detailedlabel
        - Output: no output
    """
    try:
        # Configure the field separator
        if 'csv' in filetype:
            separator = ','
        elif 'tab' in filetype:
            separator = '\t'

        # Validate if input line is a header line. Write all header lines back without change,
        # except those Zeek headers that define fields and types.
        if isinstance(originalline, str) and genericlabel == '':
            if '#fields' in originalline:
                outputline = originalline.strip() + separator + 'label' + separator + 'detailedlabel' + '\n'
                outputfile.writelines(outputline)
            elif '#types' in originalline:
                outputline = originalline.strip() + separator + 'string' + separator + 'string' + '\n'
                outputfile.writelines(outputline)
            else:
                outputfile.writelines(originalline)
        # Validate if input line is a netflow line and store along with the new fields
        elif isinstance(originalline,str) and genericlabel != '':
            outputline = originalline.strip() + separator + genericlabel + separator + detailedlabel + '\n'
            outputfile.writelines(outputline)
            if args.debug > 1:
                print(f' [+] Wrote line: {outputline}')
            # do not close the file

    except Exception as inst:
        print('Problem in output_labeled_netflow_file()')
        print(type(inst))     # the exception instance
        print(inst.args)      # arguments stored in .args
        print(inst)           # __str__ allows args to printed directly
        sys.exit(-1)


def define_columns(headerline, filetype):
    """
    Define the columns for Argus and Zeek-tab from the line received
        - Input: headerline, filetype
        - Output: column_idx
    """
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
    column_idx['conn_uids'] = False
    column_idx['local_orig'] = False
    column_idx['local_resp'] = False
    column_idx['missed_bytes'] = False
    column_idx['tunnel_parents'] = False
    column_idx['label'] = False
    column_idx['detailedlabel'] = False
    column_idx['fingerprint'] = False
    column_idx['id'] = False
    column_idx['uids'] = False

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
                elif field.lower() == 'uid':
                    column_idx['uid'] = nline.index(field)
                elif 'conn_uids' in field.lower():
                    column_idx['conn_uids'] = nline.index(field)
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
                elif 'detailedlabel' in field.lower():
                    column_idx['detailedlabel'] = nline.index(field)
                elif 'label' in field.lower():
                    column_idx['label'] = nline.index(field)
                elif 'fingerprint' in field.lower():
                    column_idx['fingerprint'] = nline.index(field)
                elif 'uids' in field.lower():
                    column_idx['uids'] = nline.index(field)
                elif 'id' in field.lower():
                    column_idx['id'] = nline.index(field)
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
                column_idx['conn_uids'] = 'conn_uids'
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
                column_idx['fingerprint'] = 'fingerprint'

        # Some of the fields were not found probably,
        # so just delete them from the index if their value is False.
        # If not we will believe that we have data on them
        # We need a temp dict because we can not change the size of dict while analyzing it
        temp_dict = {}
        for key, value in column_idx.items():
            if isinstance(value,bool) and value is False:
                continue
            temp_dict[key] = value

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
    Using heuristic detection, quickly determine the input type from the following options:
    Zeek file, Suricata JSON, Argus binetflow CSV, or Argus binetflow TSV.
        - Input: The first line after the headers if there were some, as 'data'
        - Outputs types can be can be: zeek-json, suricata, argus-tab, argus-csv, zeek-tab
    If input is JSON, it can be Zeek or Suricata
    If input is CSV, it can be Argus
    If input is TSV, it can be Argus or zeek
    """
    input_type = 'unknown'
    try:
        # Validate if input is JSON
        try:
            json_line = json.loads(data)

            # Determine if logs are Zeek or Suricata
            try:
                # Validate if input are Zeek JSON logs
                _ = json_line['ts']
                input_type = 'zeek-json'
            except KeyError:
                # Validate if input are Suricata JSON logs?
                _ = json_line['timestamp']
                input_type = 'suricata-json'
        # Validate if input is CSV or TSV
        except json.JSONDecodeError:
            # Validate if input is text based
            if isinstance(data,str):
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
            else:
                print("Exception in define_type(): unknown logs type.")
                sys.exit(1)

        # Returned guessed input log type
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

        while line:
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

        return amount_lines_processed
    except Exception as inst:
        exception_line = sys.exc_info()[2].tb_lineno
        print(f'\tProblem in process_zeek() line {exception_line}', 0, 1)
        print(str(type(inst)), 0, 1)
        print(str(inst), 0, 1)
        sys.exit(1)


def cache_labeled_file():
    """
    Read the labeled file and store the uid and labels in a dictionary.
        - Input: global variable 'args.labeledfile'
        - Output: labels_dict
    """
    try:
        if args.verbose > 0:
            print(f'[+] Labeled file to use: {args.labeledfile}')

        # Open labeled flows file and get the columns
        try:
            input_labeled_file = open(args.labeledfile,'r', encoding='utf-8')
        except Exception as inst:
            print('Some problem opening the input labeled netflow file. In cache_labeled_file()')
            print(type(inst))     # the exception instance
            print(inst.args)      # arguments stored in .args
            print(inst)           # __str__ allows args to printed directly
            sys.exit(-1)

        # Get the first header line to find the type
        headerline = input_labeled_file.readline()

        # If there are no headers, get out. Most start with '#' but Argus starts with 'StartTime' and nfdump with 'Date'
        if '#' not in headerline[0]:
            print('The labeled file has not headers. Please add them.')
            sys.exit(-1)

        # Define the type of file
        filetype = define_type(headerline)

        if args.verbose > 3:
            print(f'[+] Type of labeled file to use: {filetype}')

        # Define the columns
        if filetype == 'zeek-json':
            input_labeled_file_column_idx = define_columns(headerline, filetype='json')
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

        # Read and Cache the labeled file
        labels_dict = {}

        inputline = input_labeled_file.readline()
        lines_with_labels_read = 0
        while inputline and '#' not in inputline:
            # Transform the line into an array
            line_values = inputline.split(input_labeled_file_separator)
            if args.debug > 8:
                print(f"[+] Line values: {line_values}")
            # Read column values from the flow line
            try:
                uid = line_values[input_labeled_file_column_idx['uid']]
                generic_label = line_values[input_labeled_file_column_idx['label']].strip()
                detailed_label = line_values[input_labeled_file_column_idx['detailedlabel']].strip()
                # Store the labels for this uid in the dict
                labels_dict[uid] = [generic_label, detailed_label]
                lines_with_labels_read += 1
                if args.debug > 6:
                    print(f"[+] UID: {uid}. Label: {generic_label}. Detailed label: {detailed_label}")
            except IndexError:
                # Some zeek log files can have the headers only and no data.
                # Because we create them sometimes from larger zeek files that were filtered
                continue
            inputline = input_labeled_file.readline()

        if args.verbose > 1:
            print(f"[+] Finished reading labeled file. Read {lines_with_labels_read} lines with labels.\n")
        return labels_dict

    except Exception as inst:
        exception_line = sys.exc_info()[2].tb_lineno
        print(f'\tProblem in cache_labeled_file() line {exception_line}', 0, 1)
        print(str(type(inst)), 0, 1)
        print(str(inst), 0, 1)
        sys.exit(1)


def process_zeekfolder():
    """
    This function takes the labeled conn.log file and parses it.
    Then it asks for a label and finally it calls a function to store the netflow in a file.

    Method:
    1. Read the labeled file once and store the uid and labels in a dictionary
    2. Read each of the files in the zeek folder, read their uid, and assign the label given to that uid in the labeled file
    """
    try:
        # Get and load the dict with uid and labels
        labels_dict = cache_labeled_file()

        if args.verbose > 0:
            print(f"\n[+] Processing the zeek folder {args.zeekfolder} for files to label")


        # ----- Second, open each file in the folder, and label them.
        # Get the list of files in this folder
        zeekfiles = [f for f in listdir(args.zeekfolder) if isfile(join(args.zeekfolder, f))]

        lines_labeled = 0
        uid_without_label = 0

        for zeekfile_name in zeekfiles:

            # Ignore the following files
            ignore_keywords = ['.labeled', 'services', 'summary', 'conn.log', 'capture_loss.log',
            'loaded_scripts.log', 'packet_filter.log', 'stats.log', 'reporter.log']

            if any(keyword in zeekfile_name for keyword in ignore_keywords):
                continue

            # Ignore empty files
            if os.stat(join(args.zeekfolder, zeekfile_name)).st_size == 0:
                continue

            if args.verbose > 0:
                print(f'[+] Processing zeek file: {zeekfile_name}')

            try:
                zeekfile = open(join(args.zeekfolder, zeekfile_name),'r', encoding='utf-8')
            except Exception as inst:
                print(f'Some problem opening a zeek file {zeekfile_name}. In process_zeekfolder()')
                print(type(inst))     # the exception instance
                print(inst.args)      # arguments stored in .args
                print(inst)           # __str__ allows args to printed directly
                sys.exit(-1)

            # Get the first header line to find the type
            headerline = zeekfile.readline()

            # If there are no headers, get out. Most start with '#' but Argus starts with 'StartTime' and nfdump with 'Date'
            if '#' not in headerline[0]:
                print('The file has not headers. Please add them.')
                sys.exit(-1)

            # ---- Define the type of file
            filetype = define_type(headerline)
            if args.verbose > 3:
                print(f'[+] Type of flow file to label: {filetype}')

            # Create the output file for all cases
            output_file = open(join(args.zeekfolder, zeekfile_name+'.labeled'),'w', encoding='utf-8')
            if args.debug > 1:
                print(f"[+] Output file created: {join(args.zeekfolder, zeekfile_name+'.labeled')}")

            # Store the first header line in the output file
            output_netflow_line_to_file(output_file, headerline)

            # ---- Define the columns of this file
            if filetype == 'zeek-json':
                column_idx = define_columns(headerline, filetype='json')
            elif filetype == 'zeek-tab':
                # ---- Get all the headers lines and store them in the output file
                while '#types' not in headerline:
                    # Go through all the # headers, but rememeber the #fields one
                    if '#fields' in headerline:
                        fields_headerline = headerline
                    headerline = zeekfile.readline()
                    # Store the rest of the zeek headers in the output file
                    output_netflow_line_to_file(output_file, headerline, filetype='tab')
                # ---- Get the columns indexes for each colum
                column_idx = define_columns(fields_headerline, filetype='tab')
                zeek_file_file_separator = '\t'

            # ---- For the majority of zeek log files, using the UID from conn.log to find the related flow is ok
            # ---- But it is not for x509.log and files.log.

            if zeekfile_name == 'x509.log':
                line_to_label = zeekfile.readline().strip()
                while line_to_label and '#' not in line_to_label[0]:
                    # Transform the line into an array
                    line_values = line_to_label.split(zeek_file_file_separator)
                    if args.debug > 5:
                        print(f"[+] line values: {line_values}")

                    # Read column values from the line to label
                    try:
                        fingerprint = line_values[column_idx['fingerprint']]
                        if args.debug > 5:
                            print(f"[+] got the fingerprint: {fingerprint}")

                        #if args.verbose > 5:
                            #print(f"[+] Greping {fingerprint} in file {join(args.zeekfolder, zeekfile_name)}")
                        command = 'grep ' + fingerprint + ' ' + join(args.zeekfolder, 'ssl.log')
                        result = subprocess.run(command.split(), stdout=subprocess.PIPE, check=True)
                        result = result.stdout.decode('utf-8')
                        #if args.verbose > 5:
                            #print(f"\t[+] Result {result}")

                        # Using this fingerprint find the uid of the ssl line
                        uid = result.split('\t')[1]

                        # Using this uid, find the label for the conn.log line
                        try:
                            # Get the labels
                            generic_label_to_assign = labels_dict[uid][0]
                            detailed_label_to_assign = labels_dict[uid][1]
                        except KeyError:
                            # There is no label for this uid!
                            generic_label_to_assign = '(empty)'
                            detailed_label_to_assign = '(empty)'
                            uid_without_label += 1
                            if args.debug > 1:
                                print(f"There is no label for this uid: {uid}")

                        if args.debug > 3:
                            print(f"[+] To label UID: {uid}. Label: {generic_label_to_assign}. Detailed label: {detailed_label_to_assign}")
                        # Store the rest of the zeek line in the output file
                        output_netflow_line_to_file(output_file, line_to_label, filetype='tab', genericlabel=generic_label_to_assign, detailedlabel=detailed_label_to_assign)
                        lines_labeled += 1
                    except (IndexError, KeyError):
                        # Some zeek log files can have the headers only and no data.
                        # Because we create them sometimes from larger zeek files that were filtered
                        pass
                    line_to_label = zeekfile.readline().strip()
            if zeekfile_name in ('ocsp.log', 'pe.log'):
                line_to_label = zeekfile.readline().strip()
                while line_to_label and '#' not in line_to_label[0]:
                    # Transform the line into an array
                    line_values = line_to_label.split(zeek_file_file_separator)
                    if args.debug > 5:
                        print(f"[+] line values: {line_values}")

                    # Read column values from the line to label
                    try:
                        file_id = line_values[column_idx['id']]
                        if args.debug > 5:
                            print(f"[+] got the file ID: {file_id}")

                        #if args.verbose > 5:
                            #print(f"[+] Greping {file_id} in file {join(args.zeekfolder, zeekfile_name)}")
                        command = 'grep ' + file_id + ' ' + join(args.zeekfolder, 'files.log')
                        result = subprocess.run(command.split(), stdout=subprocess.PIPE, check=True)
                        result = result.stdout.decode('utf-8')
                        #if args.verbose > 5:
                            #print(f"\t[+] Result {result}")

                        # Using this file_id find the uid of the ssl line
                        uid = result.split('\t')[4]

                        # Using this uid, find the label for the conn.log line
                        try:
                            # Get the labels
                            generic_label_to_assign = labels_dict[uid][0]
                            detailed_label_to_assign = labels_dict[uid][1]
                        except KeyError:
                            # There is no label for this uid!
                            generic_label_to_assign = '(empty)'
                            detailed_label_to_assign = '(empty)'
                            uid_without_label += 1
                            if args.debug > 1:
                                print(f"There is no label for this uid: {uid}")

                        if args.debug > 3:
                            print(f"[+] To label UID: {uid}. Label: {generic_label_to_assign}. Detailed label: {detailed_label_to_assign}")
                        # Store the rest of the zeek line in the output file
                        output_netflow_line_to_file(output_file, line_to_label, filetype='tab', genericlabel=generic_label_to_assign, detailedlabel=detailed_label_to_assign)
                        lines_labeled += 1
                    except (IndexError, KeyError):
                        # Some zeek log files can have the headers only and no data.
                        # Because we create them sometimes from larger zeek files that were filtered
                        pass
                    line_to_label = zeekfile.readline().strip()

            else:
                # ---- Read the lines from the rest of log files to label

                # Read each line of the labeled file and get the zeek uid
                line_to_label = zeekfile.readline().strip()

                while line_to_label and '#' not in line_to_label[0]:
                    # Transform the line into an array
                    line_values = line_to_label.split(zeek_file_file_separator)
                    if args.debug > 5:
                        print(f"[+] Line values: {line_values}")

                    # Read column values from the zeek line
                    try:
                        if zeekfile_name == 'files.log':
                            uid = line_values[column_idx['conn_uids']]
                        elif zeekfile_name == 'dhcp.log':
                            uid = line_values[column_idx['uids']]
                        else:
                            uid = line_values[column_idx['uid']]

                        lines_labeled += 1

                        try:
                            # Get the labels
                            generic_label_to_assign = labels_dict[uid][0]
                            detailed_label_to_assign = labels_dict[uid][1]
                        except KeyError:
                            # There is no label for this uid!
                            generic_label_to_assign = '(empty)'
                            detailed_label_to_assign = '(empty)'
                            uid_without_label += 1
                            if args.debug > 1:
                                print(f"There is no label for this uid: {uid}")

                        if args.debug > 3:
                            print(f"[+] To label UID: {uid}. Label: {generic_label_to_assign}. Detailed label: {detailed_label_to_assign}")
                        # Store the rest of the zeek line in the output file
                        output_netflow_line_to_file(output_file, line_to_label, filetype='tab', genericlabel=generic_label_to_assign, detailedlabel=detailed_label_to_assign)
                    except (IndexError, KeyError):
                        # Some zeek log files can have the headers only and no data.
                        # Because we create them sometimes from larger zeek files that were filtered
                        pass
                    line_to_label = zeekfile.readline().strip()

            # Store the last header back
            if line_to_label and '#' in headerline[0]:
                # Store the rest of the zeek headers in the output file
                output_netflow_line_to_file(output_file, line_to_label, filetype='tab')



        if args.verbose > 0:
            print(f"[+] Read all labeled files. Labeled {lines_labeled} lines in total. UID without label {uid_without_label}")

        # Close the input file
        zeekfile.close()
        # Close the outputfile
        output_file.close()

    except Exception as inst:
        exception_line = sys.exc_info()[2].tb_lineno
        print(f'Problem in process_zeekfolder() line {exception_line}', 0, 1)
        print(type(inst))     # the exception instance
        print(inst.args)      # arguments stored in .args
        print(inst)           # __str__ allows args to printed directly
        sys.exit(-1)


if __name__ == '__main__':
    print(f"Zeek Files labeler from labeled conn.log.labeled file. Version {VERSION}")
    print("https://stratosphereips.org")

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

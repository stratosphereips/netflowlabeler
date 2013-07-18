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
from operator import itemgetter, attrgetter
import os
import pwd
import string
import sys
import getopt
from datetime import datetime
from time import mktime
import copy
import subprocess


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
    print
    sys.exit(1)



class labeler():
    """
    This class handles the adding of new labeling conditions and the return of the lables
    """

    def addCondition(self,condition):
        """
        Add a condition.
        Input: condition is a string?
        """
        try:
            global debug
            global verbose

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

            label = ""

            if debug:
                print 'Netflow line asked: {0}'.format(netflowLine)
                print 'Label returned: {0}'.format(label)

            # Only for testing
            return 'Botnet'


        except Exception as inst:
            print 'Problem in getLabel() in class labeler'
            print type(inst)     # the exception instance
            print inst.args      # arguments stored in .args
            print inst           # __str__ allows args to printed directly
            exit(-1)




def output_netflow_line_to_file(labeledNetflowLine):
    """
    """
    try:
        global debug
        global verbose

        # Open the output file
        # write the line
        # keep it open!

    except Exception as inst:
        print 'Problem in output_labeled_netflow_file()'
        print type(inst)     # the exception instance
        print inst.args      # arguments stored in .args
        print inst           # __str__ allows args to printed directly
        exit(-1)




def process_netflow(netflowFile):
    """
    This function takes the netflowfile and parse it. Then it ask for a label and finally it calls a function to store the netflow in a file
    """
    try:
        global debug
        global verbose

        if debug:
            print 'Processing the netflow file {0}'.format(netflowFile)


        # Read the netflow and parse the input
        try:
            f = open(netflowFile,'r')
        except:
            print 'Some problem opening the input netflow file. In process_netflow()'
            exit(-1)

        line = f.readline()

        # Parse the file into a dictionary. We will use the columns names as dictionary keys
        netflowDict = {}

        # Replace the stupid TABs for spaces, if it has them..., and replace the : in the ports to spaces also, and strip the \n
        temp = line.replace('	',' ').replace(':',' ').strip('\n')
        columnNames = temp.split(' ')

        # Only to separate src ip from dst ip
        firstIpColumn = True
        firstPortColumn = True
        addressType = ''

        if debug:
            print 'Columns names: {0}'.format(columnNames)

        for cN in columnNames:
            # Separate between src ip and dst ip
            if 'Src' in cN:
                addressType = 'src'
            elif 'Dst' in cN:
                addressType = 'dst'
            elif 'IP' in cN:
                netflowDict[addressType+cN] = ""
            # Separate ports
            elif 'Port' in cN:
                netflowDict[addressType+cN] = ""
            elif 'Addr' in cN:
                pass
            else:
                netflowDict[cN] = ""

        if debug:
            print netflowDict

        # Read the second line to start processing
        line = f.readline()
        while (line):
            print line
            line = f.readline()



        



        # Ask for a label
        # Call a function to store the new netflow
        

    except Exception as inst:
        print 'Problem in process_netflow()'
        print type(inst)     # the exception instance
        print inst.args      # arguments stored in .args
        print inst           # __str__ allows args to printed directly
        exit(-1)













def main():
    try:
        global debug
        global verbose

        netflowFile = ""

        opts, args = getopt.getopt(sys.argv[1:], "VvDhf:", ["help","version","verbose","debug","file="])
    except getopt.GetoptError: usage()

    for opt, arg in opts:
        if opt in ("-h", "--help"): usage()
        if opt in ("-V", "--version"): version();exit(-1)
        if opt in ("-v", "--verbose"): verbose = True
        if opt in ("-D", "--debug"): debug = 1
        if opt in ("-f", "--file"): netflowFile = str(arg)
    try:
        try:
            if netflowFile == "":
                usage()
                sys.exit(1)


            # Direct process of netflow flows
            elif netflowFile != "":
                version()
                process_netflow(netflowFile)

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


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





def main():
    try:
        global debug
        global verbose

        file = ""

        opts, args = getopt.getopt(sys.argv[1:], "VvDhf:", ["help","version","verbose","debug","file="])
    except getopt.GetoptError: usage()

    for opt, arg in opts:
        if opt in ("-h", "--help"): usage()
        if opt in ("-V", "--version"): version();exit(-1)
        if opt in ("-v", "--verbose"): verbose=True
        if opt in ("-D", "--debug"): debug=1
        if opt in ("-f", "--file"): file=arg
    try:
        try:
            if file == "":
                usage()
                sys.exit(1)


            # Direct process of netflow flows
            elif file != "":
                version()

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


#:mode=python:
# -*- coding: utf-8 -*-
## Copyright (C) 2001-2005 Red Hat, Inc.
## Copyright (C) 2001-2005 Harald Hoyer <harald@redhat.com>
## Copyright (C) 2009 Jiri Moskovcak <jmoskovc@redhat.com>

## This program is free software; you can redistribute it and/or modify
## it under the terms of the GNU General Public License as published by
## the Free Software Foundation; either version 2 of the License, or
## (at your option) any later version.

## This program is distributed in the hope that it will be useful,
## but WITHOUT ANY WARRANTY; without even the implied warranty of
## MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
## GNU General Public License for more details.

## You should have received a copy of the GNU General Public License
## along with this program; if not, write to the Free Software
## Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.

"""
Module for the ABRT exception handling hook
"""

import sys
import os

def write_dump(tb):
    if sys.argv[0][0] == "/":
        executable = os.path.abspath(sys.argv[0])
    else:
        # We don't know the path.
        # (BTW, we *can't* assume the script is in current directory.)
        executable = sys.argv[0]

    # Open ABRT daemon's socket and write data to it
    try:
        import socket
        s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        s.settimeout(5)
        try:
            s.connect("/var/run" + "/abrt/abrt.socket")
            s.sendall("PUT / HTTP/1.1\r\n\r\n")
            s.sendall("PID=%s\0" % os.getpid())
            s.sendall("EXECUTABLE=%s\0" % executable)
            s.sendall("ANALYZER=Python\0")
            s.sendall("BASENAME=pyhook\0")
            # This handler puts a short(er) crash descr in 1st line of the backtrace.
            # Example:
            # CCMainWindow.py:1:<module>:ZeroDivisionError: integer division or modulo by zero
            s.sendall("REASON=%s\0" % tb.splitlines()[0])
            s.sendall("BACKTRACE=%s\0" % tb)
            s.shutdown(socket.SHUT_WR)


            # Read the response and log if there's anything wrong
            response = ""
            while True:
                buf = s.recv(256)
                if not buf:
                    break
                response += buf
        except socket.timeout, ex:
            import syslog
            syslog.syslog("communication with ABRT daemon failed: %s" % str(ex))

        s.close()
        parts = response.split()
        if (len(parts) < 2
                or (not parts[0].startswith("HTTP/"))
                or (not parts[1].isdigit())
                or (int(parts[1]) >= 400)):
            import syslog
            syslog.syslog("error sending data to ABRT daemon: %s" % response)

    except Exception, ex:
        import syslog
        syslog.syslog("can't communicate with ABRT daemon, is it running? %s" % str(ex))

def conf_enabled(var_name):
    try:
        file = open("/etc/abrt" + "/plugins/python.conf", "r")
    except:
        return -1
    for line in file:
        w = line.split("=", 1)  # split on '=' to 2 parts max
        if len(w) < 2:
            continue
        var = w[0].strip()  # remove whitespace
        if var != var_name:
            continue
        val = w[1].strip()  # remove whitespace
        if val == "yes":
            return 1
        if val == "no":
            return 0
    file.close()
    return -1

def handleMyException((etype, value, tb)):
    """
    The exception handling function.

    progname - the name of the application
    version  - the version of the application
    """

    try:
        # Restore original exception handler
        sys.excepthook = sys.__excepthook__  # pylint: disable-msg=E1101

        import errno

        # Ignore Ctrl-C
        # SystemExit rhbz#636913 -> this exception is not an error
        if etype in [KeyboardInterrupt, SystemExit]:
            return sys.__excepthook__(etype, value, tb)

        # Ignore EPIPE: it happens all the time
        # Testcase: script.py | true, where script.py is:
        ## #!/usr/bin/python
        ## import os
        ## import time
        ## time.sleep(1)
        ## os.write(1, "Hello\n")  # print "Hello" wouldn't be the same
        #
        if etype == IOError or etype == OSError:
            if value.errno == errno.EPIPE:
                return sys.__excepthook__(etype, value, tb)

        import syslog
        syslog.openlog("abrt")

        # Ignore interactive Python and similar
        # Check for first "-" is meant to catch "-c" which appears in this case:
        ## $ python -c 'import sys; print "argv0 is:%s" % sys.argv[0]'
        ## argv0 is:-c
        # Are there other cases when sys.argv[0][0] is "-"?
        if not sys.argv[0] or sys.argv[0][0] == "-":
            syslog.syslog("detected unhandled Python exception")
            raise Exception

        # Ignore scripts with relative path unless "RequireAbsolutePath = no".
        # (In this case we can't reliably determine package)
        syslog.syslog("detected unhandled Python exception in '%s'" % sys.argv[0])
        if sys.argv[0][0] != "/":
            if conf_enabled("RequireAbsolutePath") != 0:
                raise Exception

        import traceback

        elist = traceback.format_exception(etype, value, tb)

        if tb != None and etype != IndentationError:
            tblast = traceback.extract_tb(tb, limit=None)
            if len(tblast):
                tblast = tblast[len(tblast)-1]
            extxt = traceback.format_exception_only(etype, value)
            if tblast and len(tblast) > 3:
                ll = []
                ll.extend(tblast[:3])
                ll[0] = os.path.basename(tblast[0])
                tblast = ll

            ntext = ""
            for t in tblast:
                ntext += str(t) + ":"

            text = ntext
            text += extxt[0]
            text += "\n"
            text += "".join(elist)

            trace = tb
            while trace.tb_next:
                trace = trace.tb_next
            frame = trace.tb_frame
            text += ("\nLocal variables in innermost frame:\n")
            try:
                for (key, val) in frame.f_locals.items():
                    text += "%s: %s\n" % (key, repr(val))
            except:
                pass
        else:
            text = str(value) + "\n"
            text += "\n"
            text += "".join(elist)

        # Send data to the daemon
        write_dump(text)

    except:
        # Silently ignore any error in this hook,
        # to not interfere with other scripts
        pass

    return sys.__excepthook__(etype, value, tb)


def installExceptionHandler():
    """
    Install the exception handling function.
    """
    sys.excepthook = lambda etype, value, tb: handleMyException((etype, value, tb))

# install the exception handler when the abrt_exception_handler
# module is imported
try:
    installExceptionHandler()
except Exception, e:
    # TODO: log errors?
    # OTOH, if abrt is deinstalled uncleanly
    # and this file (sitecustomize.py) exists but
    # abrt_exception_handler module does not exist, we probably
    # don't want to irritate admins...
    pass

if __name__ == '__main__':
    # test exception raised to show the effect
    div0 = 1 / 0 # pylint: disable-msg=W0612
    sys.exit(0)


__author__ = "Harald Hoyer <harald@redhat.com>"

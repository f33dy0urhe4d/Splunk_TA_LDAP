#!/usr/bin/env python
# version 1.3
# __author__ = 'feedy0urhead'

# enable / disable logger debug output
myDebug="no" # debug disabled
#myDebug="yes" # debug enabled

# import only basic modules and do some stuff before we start
import sys, os, logging, logging.handlers, splunk.Intersplunk
from os import path
from sys import modules, path as sys_path, stderr
import json

# get SPLUNK_HOME form OS
SPLUNK_HOME = os.environ['SPLUNK_HOME']

# get myScript name and path
myScript = os.path.basename(__file__)
myPath = os.path.dirname(os.path.realpath(__file__))


# define the logger to write into log file
def setup_logging(n):
    logger = logging.getLogger(n)
    if myDebug == "yes":
        logger.setLevel(logging.DEBUG)
    else:
        logger.setLevel(logging.ERROR)
    LOGGING_DEFAULT_CONFIG_FILE = os.path.join(SPLUNK_HOME, 'etc', 'log.cfg')
    LOGGING_LOCAL_CONFIG_FILE = os.path.join(SPLUNK_HOME, 'etc', 'log-local.cfg')
    LOGGING_STANZA_NAME = 'python'
    LOGGING_FILE_NAME = "%s.log" % myScript
    BASE_LOG_PATH = os.path.join('var', 'log', 'splunk')
    LOGGING_FORMAT = "%(asctime)s %(levelname)-s\t%(module)s:%(lineno)d - %(message)s"
    splunk_log_handler = logging.handlers.RotatingFileHandler(os.path.join(SPLUNK_HOME, BASE_LOG_PATH, LOGGING_FILE_NAME), mode='a')
    splunk_log_handler.setFormatter(logging.Formatter(LOGGING_FORMAT))
    logger.addHandler(splunk_log_handler)
    splunk.setupSplunkLogger(logger, LOGGING_DEFAULT_CONFIG_FILE, LOGGING_LOCAL_CONFIG_FILE, LOGGING_STANZA_NAME)
    return logger


# start the logger for troubleshooting
logger = setup_logging( "Logger started ..." ) # logger
#if myDebug == "yes": logger = setup_logging( "Logger started ..." ) # logger

# set path magic to load costum LDAP module into Splunks python
try: # lets do it
    if 'FOO' not in os.environ: # check for a dummy env setting
        if myDebug == "yes": logger.info( "setting LD path..." ) # logger
        os.environ['LD_LIBRARY_PATH'] = '%s/ldap/ldap;/opt/splunk/lib' % myPath # set LD_LIBRARY_PATH
        os.environ['FOO'] = 'yes' # set dummy env
    if myDebug == "yes": logger.info( "setting modul path..." ) # logger
    sys.path.append( "%s/ldap/ldap" % myPath ) # include modules from a subfolder
    if myDebug == "yes": logger.info( "modul path: %s/ldap" % myPath ) # logger
    if myDebug == "yes": logger.info( "loading ldap modul..." ) # logger
    import ldap # load the module
    from ldap.controls import SimplePagedResultsControl # load ldap paged support

except Exception,e: # get error back
    logger.error( "ERROR: LDAP modul load failed with error %s!" % e ) # logger
    splunk.Intersplunk.generateErrorResults(': LDAP modul load failed!') # print the error into Splunk UI
    sys.exit() # exit on error

# import any other Python Modules
import datetime, getopt, splunk.Intersplunk, csv, re, collections, base64, inspect
from datetime import datetime
from ConfigParser import SafeConfigParser
from optparse import OptionParser

# some other def Fu
def myStart(): # calulate start time of script
    global t1
    t1 = datetime.now();
    return t1;

def myStop(): # calulate stop time of script
    global t2
    t2 = datetime.now();
    return t2;

def myTime(): # calulate duration time of test
    c = t2 - t1;
    itTook = (c.days * 24 * 60 * 60 + c.seconds) * 1000 + c.microseconds / 1000.0;
    return itTook;

# set empty lists
result_set = []
results = []

# starting the main
if myDebug == "yes": logger.info( "Starting the main task ..." ) # logger

# get previous search results from Splunk
try: # lets do it
    if myDebug == "yes": logger.info( "getting previous search results..." ) # logger
    myresults,dummyresults,settings = splunk.Intersplunk.getOrganizedResults() # getting search results form Splunk
    for r in myresults: # loop the results
        for k, v in r.items(): # get key value pairs for each result
            if k == "server": # get key
                section_name = v # set value
            if k == "port": # get key
                port = v # set value
            if k == "scope": # get key
                scope = v # set value
            if k == "ldap_filter": # get key
                ldap_filter = v # set value
            if k == "basedn": # get key
                basedn = v # set value
            if k == "timeout": # get key
                timeout = v # set value
            if k == "sizelimit": # get key
                sizelimit = v # set value
            if k == "attrs": # get key
                attrs = v # set value
            if k == "fetch": # get key
                fetch = v # set value
            if k == "response": # get key
                ldap_response = v # set value

except: # get error back
    if myDebug == "yes": logger.info( "INFO: no previous search results provided using [ldapdefault]!" ) # logger

# or get user provided options in Splunk as keyword, option
try: # lets do it
    if myDebug == "yes": logger.info( "getting Splunk options..." ) # logger
    keywords, options = splunk.Intersplunk.getKeywordsAndOptions() # get key value pairs from user search
    section_name = options.get('server','ldapdefault') # get user option or use a default value
    port = options.get('port','389') # get user option or use a default value
    scope = options.get('scope','sub') # get user option or use a default value
    ldap_filter = options.get('ldap_filter','0') # get user option or use a default value
    basedn = options.get('basedn','basedn') # get user option or use a default value
    timeout = options.get('timeout','30') # get user option or use a default value
    sizelimit = options.get('sizelimit','10') # get user option or use a default value
    attrs = options.get('attrs','all') # get user option or use a default value
    fetch = options.get('fetch','nofetch') # get user option or use a default value
    ldap_response = options.get('response','no') # get user option or use a default value


except: # get error back
    if myDebug == "yes": logger.info( "INFO: no option provided using [ldapdefault]!" ) # logger


# set path to ldap.conf file
try: # lets do it
    if myDebug == "yes": logger.info( "read the ldap.conf..." ) # logger
    configLocalFileName = os.path.join(myPath,'..','default','ldap.conf') # setup path to ldap.conf
    if myDebug == "yes": logger.info( "ldap.conf file: %s" % configLocalFileName ) # logger
    parser = SafeConfigParser() # setup parser to read the ldap.conf
    parser.read(configLocalFileName) # read ldap.conf options
    if not os.path.exists(configLocalFileName): # if empty use settings from [ldapdefault] stanza in ldap.conf
        splunk.Intersplunk.generateErrorResults(': No config found! Check your ldap.conf in local.') # print the error into Splunk UI
        exit(0) # exit on error

except Exception,e: # get error back
    logger.error( "ERROR: No config found! Check your ldap.conf in local." ) # logger
    logger.error( "ERROR: %e" % e ) # logger
    splunk.Intersplunk.generateErrorResults(': No config found! Check your ldap.conf in local.') # print the error into Splunk UI
    sys.exit() # exit on error

# use user provided options or get [ldapdefault] stanza options
try: # lets do it
    if myDebug == "yes": logger.info( "read the default options from ldap.conf..." ) # logger
    if myDebug == "yes": logger.info( "reading server from ldap.conf..." ) # logger
    server = parser.get(section_name, 'server')

    # always check username and password in ldap.conf, never provided by user!
    if myDebug == "yes": logger.info( "reading user/pwd from ldap.conf..." ) # logger
    password = parser.get(section_name, 'password')
    binddn = parser.get(section_name, 'binddn')

    # check for user provided basedn options or use [ldapdefault] stanza
    if myDebug == "yes": logger.info( "reading basedn from ldap.conf..." ) # logger
    if basedn == "basedn":
        basedn = parser.get(section_name, 'basedn')
    else:
        basedn = basedn

    # check for user provided ldap_filter options or use [ldapdefault] stanza
    if myDebug == "yes": logger.info( "reading ldap_filter from ldap.conf..." ) # logger
    if ldap_filter == "0":
        ldap_filter = parser.get(section_name, 'ldap_filter')
    else:
        ldap_filter = ldap_filter

    # check for user provided scope options or use [ldapdefault] stanza
    if myDebug == "yes": logger.info( "reading base from ldap.conf..." ) # logger
    if scope == "base":
        scope = ldap.SCOPE_BASE
    elif scope == "one":
        scope = ldap.SCOPE_ONELEVEL
    else:
        scope = ldap.SCOPE_SUBTREE

    # check for user provided port options or use [ldapdefault] stanza
    if myDebug == "yes": logger.info( "reading port from ldap.conf..." ) # logger
    if port == "389":
        port = parser.get(section_name, 'port')
    else:
        port = port

    # check [ldapdefault] stanza if we need ssl
    if myDebug == "yes": logger.info( "reading usessl from ldap.conf..." ) # logger
    usessl = parser.get(section_name, 'usessl')
    if usessl == "1":
        conn_string = "ldaps://%s:%s" % ( server, port )
    else:
        conn_string = "ldap://%s:%s" % ( server, port )

except Exception,e: # get error back
    logger.error( "ERROR: unable to get default options from ldap.conf" ) # logger
    logger.error( "ERROR: %e" % e ) # logger
    splunk.Intersplunk.generateErrorResults(': unable to get default options from ldap.conf') # print the error into Splunk UI
    sys.exit() # exit on error



# now we initialize the LDAP connection
try: # lets do it
    if myDebug == "yes": logger.info( "initialize the ldap connection..." ) # logger
    l = ldap.initialize( conn_string ) # initialize the connection
    l.protocol_version = 3 # used LDAP version
    l.set_option(ldap.OPT_TIMEOUT,int(timeout)) # setting LDAP connection timeout
    l.set_option(ldap.OPT_NETWORK_TIMEOUT,int(timeout)) # setting LDAP connection timeout second option
    l.set_option(ldap.OPT_REFERRALS, 0) # setting LDAP referrals to 0

except: # get error back
    logger.error( "ERROR: unable to initialize the LDAP connection." ) # logger
    splunk.Intersplunk.generateErrorResults(': unable to initialize the LDAP connection.') # print the error into Splunk UI
    sys.exit() # exit on error



# do we use anonymouse bind or do we use a password?
if password == "0": # no password
    try: # lets do an anonymouse bind
        if myDebug == "yes":
            logger.info( "start anonymous LDAP bind..." ) # logger
            logger.info( "using conn :  %s " % conn_string ) # logger
            logger.info( "using scope :  %s " % scope ) # logger
            logger.info( "using sizelimit :  %s " % sizelimit ) # logger
        myStart(); # get the start time
        l.simple_bind_s(); # do the simple bind
        myStop(); # get the stop time
        ms_bind = myTime(); # get the duration of it
    except: # get error back
        logger.error( "ERROR: anonymous LDAP bind failed." ) # logger
        splunk.Intersplunk.generateErrorResults(': anonymous LDAP bind failed.') # print the error into Splunk UI
        sys.exit() # exit on error

else: # we use a password - much better ;)
    try: # lets do an authenticated bind
        if myDebug == "yes":
            logger.info( "start simple LDAP bind..." ) # logger
            logger.info( "using binddn :  %s " % binddn ) # logger
            logger.info( "using server :  %s " % server ) # logger
            logger.info( "using port :  %s " % port ) # logger
        decoded_pwd = base64.b64decode(password) # get the password and decode it
        myStart(); # get the start time
	l.simple_bind_s( binddn, decoded_pwd ) # do the simple bind
        myStop(); # get the stop time
        ms_bind = myTime(); # get the duration of it
    except Exception,e: # get error back
        logger.error( "ERROR: simple LDAP bind failed." ) # logger
        logger.error( "ERROR: %s" % e) # logger
        splunk.Intersplunk.generateErrorResults(': simple LDAP bind failed.') # print the error into Splunk UI
        sys.exit() # exit on error



# or will we only perform LDAP search response time test
if ldap_response == "yes": # only do a response test
    try: # lets do it
        if myDebug == "yes": logger.info( "start response time LDAP bind..." ) # logger
        lc = SimplePagedResultsControl(ldap.LDAP_CONTROL_PAGE_OID,True,(int(sizelimit),'')) # setup LDAP search page control
        myStart(); # get the start time
        #l.search_s(basedn, scope, ldap_filter, attrlist = attributes)
	l.search_s(basedn, scope, ldap_filter, attrlist = attributes)
        myStop(); # get the stop time
        ms_search = myTime(); # get the duration of it
        myStart(); # get the start time
        l.unbind() # LDAP unbind
        myStop(); # get the stop time
        ms_unbind = myTime(); # get the duration of it
        responses = [] # setup empty list
        response = {} # setup empty list
        response["server"] = server # fill in key value pairs
        response["basedn"] = basedn # fill in key value pairs
        response["ldap_bind"] = ms_bind # fill in key value pairs
        response["ldap_search"] = ms_search # fill in key value pairs
        response["ldap_unbind"] = ms_unbind # fill in key value pairs
        od = collections.OrderedDict(sorted(response.items())) # sort the list
        responses.append(od) # append the ordered results to the list
        splunk.Intersplunk.outputResults( responses ) # print the result into Splunk UI
    except Exception,e: # get error back
        logger.error( "ERROR: response time LDAP bind failed." ) # logger
        logger.error( "ERROR: %s" % e) # logger
        splunk.Intersplunk.generateErrorResults(': response time LDAP bind failed') # print the error into Splunk UI
        sys.exit() # exit on error
    if myDebug == "yes": logger.info( "response time LDAP bind done...leaving the script" ) # logger
    sys.exit() # exit on error


# check what attributes will be returned, default all
try: # lets do it
    if myDebug == "yes": logger.info( "set attribute list and size limit for LDAP search..." ) # logger
    lc = SimplePagedResultsControl(ldap.LDAP_CONTROL_PAGE_OID,True,(int(sizelimit),'')) # setup LDAP search page control
    if myDebug == "yes": logger.info( "set serverctrls to: %s " % lc ) # logger
    if attrs == "all": # we get all attributes
        if myDebug == "yes":
            logger.info( "using all attributes for the query..." ) # logger
            logger.info( "using basedn :  %s " % basedn ) # logger
            logger.info( "using scope :  %s " % scope ) # logger
            logger.info( "using ldap_filter :  %s " % ldap_filter ) # logger
        result_id = l.search( basedn, ldap.SCOPE_SUBTREE, ldap_filter) # set attrlist=['+'] in the LDAP search
    else: # no, we only get certain attributes back
        if myDebug == "yes": logger.info( "using special attributes only for the query..." ) # logger
        x_attrs = [] # Create a list of attribute names of the form ['attr1', 'attrs2', ...]
        myattrs = attrs.split(',') # how to identify a single attribute
        for attr_name in myattrs: # loop throught the attribute list
            if myDebug == "yes": logger.info( "using attr_name: %s " % attr_name ) # logger
            x_attrs.append(attr_name) # append the attribute name to the list
        if myDebug == "yes":
            logger.info( "using attrs: %s " % x_attrs ) # logger
            logger.info( "using basedn :  %s " % basedn ) # logger
            logger.info( "using scope :  %s " % scope ) # logger
            logger.info( "using ldap_filter :  %s " % ldap_filter ) # logger
        result_id = l.search( basedn, ldap.SCOPE_SUBTREE, ldap_filter, attrlist=x_attrs) # set attrlist=x_attrs in the LDAP search
    if fetch == "nofetch": # special option to return all DN attributes
        fetch = "" # set it to be empty
    else:
        scope = ldap.SCOPE_BASE # set the LDAP search scope
        result_id = l.search( fetch, ldap.SCOPE_SUBTREE, ldap_filter, attrlist=['+'], serverctrls=[lc] ) # search the attributes

except: # get error back
    logger.error( "ERROR: unable to set attribute list for LDAP search." ) # logger
    splunk.Intersplunk.generateErrorResults(': unable to set attribute list for LDAP search.') # print the error into Splunk UI
    sys.exit() # exit on error

# get and process the LDAP result
try: # lets do it
    if myDebug == "yes": logger.info( "processing LDAP results..." ) # logger
    while 1: # start the loop
        result_type, result_data = l.result(result_id,0) # get the type and data from the results
        if (result_data == []): # if there is no more result
            break # leave the while loop
        result_set = result_data # append result data to the set
	logger.info(result_set)
        for i in result_set: # do some python Fu magic on the LDAP results
            a = {} # set empty list
            z = {} # set empty list
            key = "dn" # set key to DN to identify the destinguest name
            z.setdefault(key, []) #
            z[key].append(i[0]) #
            for k, v in i[1].items(): #
		if not k == "objectClass": #
                    v = '","'.join(v) #
                    key = k #
                    a.setdefault(key, []) #
                    a[key].append(v) # append keys and value pairs to first list
            z = dict(z.items() + a.items()) # append keys and value pairs to second list
            od = collections.OrderedDict(sorted(z.items())) # lets sort this alphabetical order
            results.append(od) # append ordered list to results

except Exception,e: # get error back
    logger.error( "ERROR: %s" % e) # logger
    splunk.Intersplunk.generateErrorResults(': %s' % e) # print the error into Splunk UI
    sys.exit() # exit on error

# unbind the LDAP connection!
try: # lets do it
    if myDebug == "yes": logger.info( "unbind the LDAP connection..." ) # logger
    l.unbind() # LDAP unbind

except: # get error back
    logger.error( "ERROR: unbind failed!" ) # logger
    splunk.Intersplunk.generateErrorResults(': LDAP unbind failed!') # print the error into Splunk UI
    sys.exit() # exit on error

# print result into Splunk
if myDebug == "yes": logger.info( "printing to Splunk> ..." ) # logger
splunk.Intersplunk.outputResults(results) # print the result into Splunk UI


import csv
import gzip
import json
import logging
import logging.handlers
import sys
import re
import time
import base64
import datetime
import urllib
import urllib2
from datetime import datetime
from datetime import timedelta


#CORE SPLUNK IMPORTS
import splunk
import splunk.search as splunkSearch
from splunk.rest import simpleRequest
import splunk.version as ver
from time import strftime
from time import localtime
import splunk.clilib.cli_common
import splunk.auth, splunk.search
import splunk.Intersplunk as si

try:
    from splunk.clilib.bundle_paths import make_splunkhome_path
except ImportError:
    from splunk.appserver.mrsparkle.lib.util import make_splunkhome_path

sys.path.append(make_splunkhome_path(["etc", "apps", "Splunk_SA_CIM", "lib"]))
sys.path.append(make_splunkhome_path(["etc", "apps", "SA-Utils", "lib"]))
sys.path.append(make_splunkhome_path(["etc", "apps", "DA-ESS-Checkphish", "lib"]))

from cim_actions import ModularAction

from phish_results import PhishResult

# set the maximum allowable CSV field size
#
# The default of the csv module is 128KB; upping to 10MB. See SPL-12117 for
# the background on issues surrounding field sizes.
# (this method is new in python 2.5)
csv.field_size_limit(10485760)


##
## Debugging : index=_internal (source=*_modalert.log* OR source=*_modworkflow.log*)


## Setup the logger
def setup_logger():
   """
   Setup a logger for the REST handler.
   """

   logger = logging.getLogger('checkphish_modaction')
   logger.setLevel(logging.INFO)

   file_handler = logging.handlers.RotatingFileHandler(
     make_splunkhome_path(['var', 'log', 'splunk', 'checkphish_modalert.log']),
     maxBytes=25000000, backupCount=5)
   formatter = logging.Formatter('%(asctime)s %(lineno)d %(levelname)s %(message)s')
   file_handler.setFormatter(formatter)

   logger.addHandler(file_handler)

   return logger

logger = setup_logger()

## ModularAction wrapper
class CheckphishModularAction(ModularAction):

    def __init__(self, settings, logger, action_name=None):
        super(CheckphishModularAction, self).__init__(settings, logger, action_name)

        self.urltocheck = self.configuration.get('site', '')
        self.baseurl= self.configuration.get('baseurl', '')
        self.checkurl= self.configuration.get('checkurl', '')
        self.apikey = self.configuration.get('apikey', '')

        self.logger.info("Suspect URL = %s", self.urltocheck)
        self.logger.info("baseurl  = %s", self.baseurl)
        self.logger.info("checkurl = %s", self.checkurl)
        self.logger.info("apikey = %s", self.apikey)

    # Send SMS alert
    def sendSMSAlert(self, url):
        '''
        Run search with sendalert to invoke twilio mod alert 
        '''

        msg = " This URL is phish! : " + url + ". ES Adaptive Response rocks!!"
        sms_search = "| stats count | sendalert twilio param.message=\"" + msg + "\"" 

        logger.critical("Triggered search : " + sms_search )

        my_job = splunk.search.dispatch( sms_search, sessionKey=self.session_key)

        jobDone = my_job.isDone
        while jobDone == False :
            time.sleep(1)
            jobDone = my_job.isDone

        events = [ sms_search ]

        # Create Splunk events for status
        self.addevent(events)

        return my_job.eventCount

    ## Create splunk events for action updates
    def addevent(self, events):
        if modaction.makeevents(  events, index='main', source='check', sourcetype='phish'):
            logger.info("Created splunk event for CheckphishModularAction.")
        else:
            logger.critical("Faild creating splunk event for CheckphishModularAction.")
        return
         

    def dowork(self, result):

        # Extract URL that needs to be checked against phistank DB
        self.urls = result['site']
        self.logger.info("About to check for Suspect URL = %s", self.urls)

        urlencoded = base64.encodestring(self.urls)

        # Create payload for the Phishtank API
        #   reference: https://www.phishtank.com/api_info.php
        post_data = urllib.urlencode(
            {'url': urlencoded,
             'format': 'json',
             'app_key': self.apikey,
            })

        self.logger.info( "Post data: %s" , post_data)

        # Callout to phishtank 
        response = urllib2.urlopen( self.baseurl + self.checkurl, post_data)
        headers = response.info()
        rdata = response.read().decode('utf-8')
        data = json.loads(rdata)

        self.logger.info( "Date : %s" , headers['date'])
        self.logger.info( "Data: %s" , data)

        # Parse phishtank results
        phish_res = PhishResult(data['results'])

        # Create status message 
        if phish_res.in_database:
            if phish_res.valid:
                url_status = "{url} is a phish!".format(url=phish_res.url) 
                # Send SMS alert 
                self.sendSMSAlert(phish_res.url)
            else:
                url_status = "{url} is NOT a phish!".format(url=phish_res.url) 
        else:
            url_status = "{url} not in PT database.".format(url=phish_res.url) 

        events = [ url_status ]

        # Add splunk events for status
        self.addevent(events)

        # Track the final state
        self.logger.info(modaction.message(self.urls, 'success'))


if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] != "--execute":
        print >> sys.stderr, "FATAL Unsupported execution mode (expected --execute flag)"
        sys.exit(1)

    try:
        modaction = CheckphishModularAction(sys.stdin.read(), logger, 'checkphish')
        session_key = modaction.session_key
        if logger.isEnabledFor(logging.DEBUG):
            logger.debug('%s', json.dumps(modaction.settings, sort_keys=True,
                indent=4, separators=(',', ': ')))

        ## process results
        with gzip.open(modaction.results_file, 'rb') as fh:
            for num, result in enumerate(csv.DictReader(fh)):
                ## set rid to row # (0->n) if unset
                result.setdefault('rid', num)
                modaction.update(result)
                modaction.invoke()
                modaction.dowork(result)

    except Exception as e:
        ## adding additional logging since adhoc search invocations do not write to stderr
        try:
            logger.critical(modaction.message(e, 'failure'))
        except:
            logger.critical(e)
        print >> sys.stderr, "ERROR Unexpected error: %s" % e
        sys.exit(3)

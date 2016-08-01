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


## Helper class for Phishtank API and processing 
# 
# Copyright (c) 2010, Steve 'Ashcrow' Milner
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions
# are met:
#
#    * Redistributions of source code must retain the above copyright
#      notice, this list of conditions and the following disclaimer.
#    * Redistributions in binary form must reproduce the above
#      copyright notice, this list of conditions and the following
#      disclaimer in the documentation and/or other materials
#      provided with the distribution.
#    * Neither the name of the project nor the names of its
#      contributors may be used to endorse or promote products
#      derived from this software without specific prior written
#      permission.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
# "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
# LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
# FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
# COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT,
# INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
# (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
# SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
# HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
# STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
# ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
# OF THE POSSIBILITY OF SUCH DAMAGE.

class PhishResult():
    """
    Result sent back from PhishTank.
    """

    def __init__(self, response):
        """
        Initialize Result object.
        :Parameters:
           - `response`: actual json response from the service
        """
        
        self.url = response.get('url', None)
        self.in_database = response.get('in_database', None)
        self.phish_id = response.get('phish_id', None)
        self.phish_detail_page = response.get('phish_detail_page', None)
        self.verified = response.get('verified', None)
        self.verified_at = response.get('verified_at', None)
        if self.verified_at:
            self.verified_at = self.__format_date(self.verified_at)
        self.valid = response.get('valid', None)
        self.submitted_at = response.get('submitted_at', None)
        if self.submitted_at:
            self.submitted_at = self.__format_date(self.submitted_at)

    def __format_date(self, date_str):
        """
        Format a date string into a datetime object.
        :Parameters:
           - `date_str`: the date string in %Y-%m-%dT%H:%M:%S+00:00 format.
        """
        return datetime.strptime(date_str, '%Y-%m-%dT%H:%M:%S+00:00')

    def __phish(self):
        """
        Returns True if the URL checked is known to be a phish, False if not.
        """
        if self.valid:
            return True
        return False

    def __repr__(self):
        """
        Representation of Result object.
        """
        return "<Result: url=%s, phish=%s>" % (self.url, self.__phish())

    def __eq__(self, other):
        """
        Checks to see if this instance is the same as another.
        :Parameters:
           - `other`: The other instance to look at.
        """
        for key in self.__slots__:
            try:
                if getattr(self, key) != getattr(other, key):
                    raise KeyError()
            except:
                return False
        return True

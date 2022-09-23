#!/usr/bin/python
# -*- coding:utf-8 -*-

#############################################
# Any Firewall
# - Code by Jioh L. Jung (ziozzang@gmail.com)
#############################################

import os
import io
import clamd
import time

import requests
from flask import Flask, Blueprint, request, Response

app = Flask(__name__)


####################################################################################

def get_osenv(env_name, default_value=""):
    if env_name in os.environ.keys():
        if len(os.environ[env_name]) > 0:
            return os.environ[env_name]
    return default_value


TMP_BASE_PATH = get_osenv('TMP_BASE_PATH', "/tmp")
UPSTREAM_URL = get_osenv('UPSTREAM_URL', 'https://mirror.kakao.com')
LISTEN_PORT = int(get_osenv('LISTEN_PORT', 8888))
DEBUG_FLAG = bool(int(get_osenv('DEBUG_FLAG', '1')))
ENABLE_CLAMAV_SCAN = bool(int(get_osenv('ENABLE_CLAMAV_SCAN', '1')))

CLAMAV_PORT = int(get_osenv('CLAMAV_PORT', '3310'))
CLAMAV_HOST = get_osenv('CLAMAV_HOST', 'home.jioh.net')


####################################################################################

def is_clamav_passed(contents, print_func=app.logger.info):
    if ENABLE_CLAMAV_SCAN == False:
        return True
    vsc_time = time.time()
    message = ''
    
    cd = clamd.ClamdNetworkSocket()
    cd.__init__(host=CLAMAV_HOST, port=CLAMAV_PORT, timeout=None)
    scan_result = cd.instream(io.BytesIO(contents))
    
    if (scan_result['stream'][0] == 'OK'): #file has no virus
        print_func("> Virus Scan - Passed / %ssec" % (time.time() - vsc_time))
        return True, ''
    elif (scan_result['stream'][0] == 'FOUND'):
        print_func("> Virus Scan - Failed(Virus Found) / %ssec" % (time.time() - vsc_time))
        #print(scan_result['stream'])
        message = 'Virus Scan - Failed(Virus Found)'
        return False, message
    else:
        print_func("> Virus Scan - Failed(Other Issue) / %ssec" % (time.time() - vsc_time))
        message = 'Virus Scan - Failed(Other Issue)'
        return False, message


####################################################################################

proxy = Blueprint('proxy', __name__)


@proxy.route('/', methods=["GET"])
@proxy.route('/<path:url_files>', methods=["GET"])
def path_request(url_files=""):
    req_time = time.time()
    app.logger.info(">> F: '%s'" % (url_files))

    request_headers = {}
    for h in ["Cookie", "Referer", "X-Csrf-Token"]:
        if h in request.headers:
            request_headers[h] = request.headers[h]

    if request.query_string:
        path = "%s?%s" % (url_files, request.query_string)
    else:
        path = url_files

    headers = {}
    headers['location'] = UPSTREAM_URL + '/' + path

    app.logger.debug('>> Downloading....')
    resp = requests.get(UPSTREAM_URL + '/' + path)
    app.logger.info('>> SIZE: %d' % (len(resp.content),))
    d = {}
    for key in resp.headers.keys():
        value = resp.headers[key]
        # print ("HEADER: '%s':'%s'" % (key, value))
        d[key.lower()] = value

    resp_hdr = {}
    if resp.ok:
        resp_hdr['content-length'] = len(resp.content)
        resp_hdr['content-type'] = d['content-type']

        res, message = is_clamav_passed(resp.content)
        if res:
            flask_response = Response(response=resp.content, headers=resp_hdr)
        else:
            flask_response = Response(response=message,
                                      status=404)
    else:
        app.logger.info('>> Download Error. Failed')
        flask_response = Response(status=404)

    return flask_response


####################################################################################

app.register_blueprint(proxy)
app.run(debug=DEBUG_FLAG, host='0.0.0.0', port=LISTEN_PORT, threaded=True)

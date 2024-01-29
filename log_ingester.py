import base64
import gzip
import hashlib
import hmac
import json
import logging
import operator
import time
from functools import reduce

import requests

import constants as const
import helper as hp
import msgspec_okta_event

logger = logging.getLogger()
logger.setLevel(logging.INFO)

metadata_deep_path = None
company = hp.get_required_attr_from_env(const.COMPANY_NAME)
lm_access_id = hp.get_attr_from_env(const.LM_ACCESS_ID)
lm_access_key = hp.get_attr_from_env(const.LM_ACCESS_KEY)
lm_bearer_token =hp.get_attr_from_env(const.LM_BEARER_TOKEN)
lm_resource_id = hp.get_attr_as_json_from_env(const.LM_RESOURCE_ID)
        #set_metadata_deep_path()
include_metadata_keys = hp.get_required_attr_from_env(const.INCLUDE_METADATA_KEYS)
service_name = hp.get_attr_from_env(const.LM_SERVICE_NAME_KEY)
use_lmv1_for_auth = True if (lm_access_id and lm_access_key) else False

        
def set_metadata_deep_path():
        try:
            # metadata_deep_path = []
            include_metadata_keys = hp.get_attr_from_env(const.INCLUDE_METADATA_KEYS).replace(' ', '')  # remove spaces
            metadata_deep_path = include_metadata_keys.split(',')
            # for k in include_metadata_keys.split(','):
            #     metadata_deep_path.append(k.split('.'))
            metadata_deep_path = metadata_deep_path
        except Exception as e:
            logger.warning(e, exc_info=True)
            metadata_deep_path = None

def get_company_name():
        return company

def ingest_to_lm_logs(raw_json_resp):
        if len(raw_json_resp) < 1:
            return
        # split
        logger.info("number of logs in response = %s", str(len(raw_json_resp)))
        payload = []
        for event in raw_json_resp:
            payload.append(prepare_lm_log_event(event))
        report_logs_in_chunks(payload)

def report_logs_in_chunks(payload):
        payload_size = len(json.dumps(payload).encode(const.ENCODING))
        if payload_size < const.MAX_ALLOWED_PAYLOAD_SIZE and len(payload) > 0:
            # ingest as it is
            logger.info("payload size while ingestion =" + str(payload_size))
            report_logs(payload)
        else:
            # this is an extremely rare scenario where size of 1000 logs is larger than 8 mbs
            # generally size of 1000 logs is around 3 MBs
            # but if the ever occurs, split data equally and report logs
            logger.info("splitting payload due to payload size limit exceeded.")
            split_len = len(payload) // 2
            report_logs_in_chunks(payload[:split_len])
            report_logs_in_chunks(payload[split_len:])

def prepare_lm_log_event(event):
        lm_log_event = {"message": msgspec_okta_event.dumps(event).decode(), "timestamp": event.published,
                        "_lm.logsource_type": "lm-logs-okta"}

        if service_name:
            lm_log_event[const.LM_KEY_SERVICE] = service_name
        if lm_resource_id:
            lm_log_event["_lm.resourceId"] = lm_resource_id

        if metadata_deep_path:
            for path in metadata_deep_path:
                try:
                    lm_log_event[path] = msgspec_okta_event.r_getattr(event, path)
                    # lm_log_event['.'.join(path)] = reduce(operator.getitem, path, event)
                except Exception as e:
                    logger.warning("Failed to add metadata {0} to lm-log event. Error = {1}".format(path, str(e)))

        return lm_log_event

def generate_auth(data):
        if not use_lmv1_for_auth and not lm_bearer_token:
            raise ValueError("Either LMAccessId, LMAccessKey both or BearerToken should be configured for authentication with Logicmonitor.")
        if use_lmv1_for_auth:
            http_verb = 'POST'
            epoch = str(int(time.time() * 1000))
            request_vars = http_verb + epoch + data + const.LOG_INGESTION_RESOURCE_PATH
            signature = base64.b64encode(hmac.new(lm_access_key.encode(const.ENCODING),
                                                msg=request_vars.encode(const.ENCODING),
                                                digestmod=hashlib.sha256).hexdigest().encode(const.ENCODING))
            return 'LMv1 ' + lm_access_id + ':' + signature.decode() + ':' + epoch
        else:
            return "Bearer " + lm_bearer_token

def report_logs(payload):
        data = json.dumps(payload)
        url = "https://" + company + ".logicmonitor.com/rest" + const.LOG_INGESTION_RESOURCE_PATH
        logging.debug("Payload to ingest =%s", data)

        auth = generate_auth(data)

        headers = {'Content-Encoding': 'gzip', 'Content-Type': 'application/json', 'Authorization': auth,
                   'User-Agent': 'Okta-log-lambda-function'}
        logger.debug("making post request.")
        response = requests.post(url, data=gzip.compress(data.encode(const.ENCODING)), headers=headers)
        if response.status_code == 202:
            logger.info("Successfully ingested events to log-ingest. x-request-id=%s response=%s",
                        response.headers['x-request-id'], response.json())
        elif response.status_code == 207:
            logger.debug("Partial events accepted by log-ingest. x-request-id=%s, response=%s",
                         response.headers['x-request-id'], response.json())
        else:
            logger.error("Log ingestion failed. error=%s", response.json())
            raise Exception("Error while ingesting logs. Stopping log-ingestion. Will attempt back-filling in "
                            "next lambda function execution..")

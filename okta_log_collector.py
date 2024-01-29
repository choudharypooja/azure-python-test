
import logging
import requests
from datetime import datetime, timedelta, timezone
import helper as hp
import log_ingester
import msgspec_okta_event
import storage_account
import validators
import json
logger = logging.getLogger()
logger.setLevel(logging.INFO)


OKTA_LOGS_ENDPOINT = "/api/v1/logs"
HTTP_PROTOCOL = "https://"
OKTA_EVENT_FILTER = "OKTA_EVENT_FILTER"
OKTA_EVENT_KEYWORD = "OKTA_EVENT_KEYWORD"
OKTA_NEXT_LINK = "okta_next_link"
RETRIES = "next_link_retries"
MAX_RETRIES = 3
BACK_FILL_DURATION_MINUTES = 2
domain = hp.get_attr_from_env("OKTA_DOMAIN")#"logicmonitorpreview.oktapreview.com"#hp.get_attr_from_env(const.OKTA_DOMAIN)
api_key = "00c2SamWJ6AiRS9TByggjjrcPtlDDTO3JCakkvPT_W"#hp.get_required_attr_from_env(const.OKTA_API_KEY)
        #log_ingester = log_ingester.LogIngester()
back_fill_dur_min = BACK_FILL_DURATION_MINUTES
retry_attempt = 0

def get_domain():
        return domain
    
def get_last_report_time():
        return datetime.now(timezone.utc) - timedelta(minutes=back_fill_dur_min)


def get_next_link_s3_obj_key():
        return "nextLinkForOktaLogs-" + log_ingester.get_company_name() + "-" + domain

def get_url_to_query():
        if url_data_json := storage_account.getOktaUrl(get_next_link_s3_obj_key()):

            try:
                logger.info("url_data_json read from s3 = %s", url_data_json)
                link = url_data_json[OKTA_NEXT_LINK]
                if validators.url(link) and int(url_data_json[RETRIES]) < MAX_RETRIES:
                    logger.info("valid link read from s3 with valid retries = %s", url_data_json[RETRIES])
                    retry_attempt = int(url_data_json[RETRIES])
                    return link
                else:
                    logger.info("Invalid URL or Max retries exceeded. Will attempt to back-fill now. URL=%s, "
                                "Retries=%s, Max-Retries allowed = %s",
                                link, url_data_json[RETRIES], MAX_RETRIES)
                    return build_log_fetching_url()
            except Exception as e:
                logger.error("Unable to read persisted url from S3. Error = %s", str(e))
                raise e
        else:
            return build_log_fetching_url()

def build_log_fetching_url():
        base_url = HTTP_PROTOCOL + domain + OKTA_LOGS_ENDPOINT
        last_report_time = get_last_report_time().isoformat().replace("+00:00", 'Z')
        logger.info("LastReportTimeStamp being used as since = %s ", last_report_time)
        query_param = "?since=" + last_report_time + "&sortOrder=ASCENDING" + "&limit=1000"
        final_url = base_url + query_param
        logger.info("Fetching URL built from scratch = %s", final_url)
        return final_url
    
def update_next_url_to_query( url, retry):
        if validators.url(url) and retry >= 0:
            link_data = {OKTA_NEXT_LINK: url, RETRIES: retry}
            logger.info("Updating s3 with data = %s", json.dumps(link_data))
            storage_account.updateOktaUrl(get_next_link_s3_obj_key(), json.dumps(link_data))
        else:
            logger.warning("Invalid URL or negative retry count. Not updating in s3. url = %s, retry = %s", url, retry)

def collect_logs():
    url_for_fetching = get_url_to_query()
    logger.info("Using url to query logs at execution : %s", url_for_fetching)
    url_to_persist = url_for_fetching
    report_date = get_last_report_time()
    logging.info("report_date "+report_date)
    print("API_KEY OKTA "+ api_key)
    headers = {
            'Accept': 'application/json',
            'Content-Type': 'application/json',
            'Authorization': 'SSWS {}'.format(api_key)
    }
    try:
        response = requests.request("GET", url_for_fetching, headers=headers)
        response.raise_for_status()
        logger.info("helper integrated")
        log_ingester.ingest_to_lm_logs(msgspec_okta_event.loads(response.text))
        while response.links["next"]["url"]:
                next_url = response.links["next"]["url"]
                url_to_persist = next_url
                # persist url to s3 as soon as ingestion is successful
                logger.info("Updating next url to s3 after last successful ingestion : %s ", next_url)
                update_next_url_to_query(url_to_persist, 0)

                url_for_fetching = url_to_persist
                retry_attempt = 0
                response = requests.request("GET", response.links["next"]["url"], headers=headers)
                response.raise_for_status()
                if len(msgspec_okta_event.loads(response.text)) < 1:
                    logger.info("Reached last next link as no logs found this time. Stopping log collection.. ")
                    break
                else:
                    log_ingester.ingest_to_lm_logs(msgspec_okta_event.loads(response.text))

        logger.info("URL for fetching first : %s, url to persist at the ending : %s", url_for_fetching,
                        url_to_persist)
        url_to_persist = response.links[""]["url"]

    except Exception as e:

         if url_to_persist == url_for_fetching:
            logger.error("Exception encountered. incrementing retry attempt. Error = %s", str(e))
            retry_attempt += 1
            # raise Exception('Error occurred during execution')
    finally:
            if url_to_persist == url_for_fetching:
                if retry_attempt > 0:
                    logger.warning("Retrying attempt found. Incrementing retry count for same url = %s, "
                                   "retry_attempt to persist = %s", url_to_persist, str(retry_attempt))
                    update_next_url_to_query(url_to_persist, retry_attempt)
                else:
                    logger.info("URL unchanged. Skipping update in s3.")
            else:
                logger.info("Updating next url in s3 to %s", url_to_persist)
                update_next_url_to_query(url_to_persist, 0)
            logger.info("Okta log collection completed ... ")

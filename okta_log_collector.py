
import logging
import requests
from datetime import datetime, timedelta, timezone
import helper as hp
import log_ingester
import msgspec_okta_event
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
        #self.log_ingester = log_ingester.LogIngester()
back_fill_dur_min = BACK_FILL_DURATION_MINUTES
retry_attempt = 0

def get_last_report_time():
        return "test"#datetime.now(timezone.utc) - timedelta(minutes=back_fill_dur_min)
  

def collect_logs():
    url_for_fetching = "https://logicmonitorpreview.oktapreview.com/api/v1/logs"
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
            # while response.links["next"]["url"]:
            #     next_url = response.links["next"]["url"]
            #     url_to_persist = next_url
            #     # persist url to s3 as soon as ingestion is successful
            #     logger.info("Updating next url to s3 after last successful ingestion : %s ", next_url)
            #     self.update_next_url_to_query(url_to_persist, 0)

            #     url_for_fetching = url_to_persist
            #     self.retry_attempt = 0
            #     response = requests.request("GET", response.links["next"]["url"], headers=headers)
            #     response.raise_for_status()
            #     if len(msgspec_okta_event.loads(response.text)) < 1:
            #         logger.info("Reached last next link as no logs found this time. Stopping log collection.. ")
            #         break
            #     else:
            #         self.log_ingester.ingest_to_lm_logs(msgspec_okta_event.loads(response.text))

            # logger.info("URL for fetching first : %s, url to persist at the ending : %s", url_for_fetching,
            #             url_to_persist)
            # url_to_persist = response.links["self"]["url"]

    except Exception as e:

         if url_to_persist == url_for_fetching:
            logger.error("Exception encountered. incrementing retry attempt. Error = %s", str(e))
            retry_attempt += 1
            # raise Exception('Error occurred during execution')
    finally:
            # if url_to_persist == url_for_fetching:
            #     if self.retry_attempt > 0:
            #         logger.warning("Retrying attempt found. Incrementing retry count for same url = %s, "
            #                        "retry_attempt to persist = %s", url_to_persist, str(self.retry_attempt))
            #         self.update_next_url_to_query(url_to_persist, self.retry_attempt)
            #     else:
            #         logger.info("URL unchanged. Skipping update in s3.")
            # else:
            #     logger.info("Updating next url in s3 to %s", url_to_persist)
            #     self.update_next_url_to_query(url_to_persist, 0)
        logger.info("Okta log collection completed ... ")

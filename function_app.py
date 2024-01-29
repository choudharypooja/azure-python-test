import azure.functions as func

# import constants as const
# import helper as hp
#from .okta_log_collector import OktaLogCollector
# import storage_account as acc
import logging
import helper_function
#import storage_account
#import constants as const
#import helper as hp
#from log_ingester import LogIngester
#import msgspec_okta_event

# logger = logging.getLogger()
# logger.setLevel(logging.INFO)

# domain = "logicmonitorpreview.oktapreview.com"#hp.get_attr_from_env(const.OKTA_DOMAIN)
# api_key = "00c2SamWJ6AiRS9TByggjjrcPtlDDTO3JCakkvPT_W"#hp.get_required_attr_from_env(const.OKTA_API_KEY)
#         #self.log_ingester = LogIngester()
# back_fill_dur_min = BACK_FILL_DURATION_MINUTES
# retry_attempt = 0
# # dir_path = os.path.dirname(os.path.realpath(__file__))
# # sys.path.insert(0, dir_path)

app = func.FunctionApp()
#oktaLog = helper_function.OktaLogCollector()
@app.schedule(schedule="*/30 * * * * *", arg_name="myTimerTest", run_on_startup=True,
              use_monitor=False) 
def MyTimerTrigger1(myTimerTest: func.TimerRequest) -> None:
    logging.info('Python timer trigger function executing uploaded using zip.')
    if myTimerTest.past_due:
        logging.info('The timer is past due!')
    
    try:
        #helper_function.init1()
        helper_function.collect_logs()
    except Exception as e:
                logging.error("error %s", str(e))
    logging.info('Python timer trigger function executed.')



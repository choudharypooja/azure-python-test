import azure.functions as func

# import constants as const
# import helper as hp
#from .okta_log_collector import OktaLogCollector
# import storage_account as acc
import logging
import okta_log_collector

app = func.FunctionApp()
#oktaLog = helper_function.OktaLogCollector()
@app.schedule(schedule="*/30 * * * * *", arg_name="myTimerTest", run_on_startup=True,
              use_monitor=False) 
def MyTimerTrigger1(myTimerTest: func.TimerRequest) -> None:
    logging.info('Python timer trigger function executing uploaded using zip.')
    if myTimerTest.past_due:
        logging.info('The timer is past due!')
    
    try:
        okta_log_collector.collect_logs()
    except Exception as e:
                logging.error("error %s", str(e))
    logging.info('Python timer trigger function executed.')



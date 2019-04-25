import os
import logging as logger
from datetime import datetime
import json
import time
import itertools
import sys
from splunk.appserver.mrsparkle.lib.util import make_splunkhome_path

from ModularInput import ModularInput
from RESTClient import RESTClient
from Utilities import Utilities, KennyLoggins

__author__ = 'njeanselme'

_MI_APP_NAME = 'Infoblox ActiveTrust Cloud Modular Input'
_APP_NAME = 'IA-infoblox-atc'
_SPLUNK_HOME = make_splunkhome_path([""])

kl = KennyLoggins()
log = kl.get_logger(_APP_NAME, "modularinput", logger.INFO)


class infoblox(ModularInput):
    def _validate_arguments(self, val_data):
        """
        :param val_data: The data that requires validation.
        :return:
        RAISE an error if the arguments do not validate correctly. The default is just "True".
        """
        event_type_list = 'event,categories'

        if "proxy_name" in val_data:
            if len(val_data["proxy_name"]) > 255:
                raise Exception("Proxy name cannot be longer than 255 characters.")

        if t1 - t0 > 86400:
            raise Exception("Max interval between t0 & t1 is 24h. Recommended value is 30 minutes")

        return True


class infoblox_client(RESTClient):
    def _build_url(self, endpoint):
        return "https://{}/api/threats/v1/{}".format(self._hostname, endpoint)

    def _call(self, **kwargs):
        payload = "t0={}&t1={}".format(kwargs["t0"], kwargs["t1"])
        fullUrl = "{}?{}".format(self._build_url(kwargs["type"]), payload)
        log.debug("fullURL : {}".format(fullUrl))
        return self._read(fullUrl, payload=None)

    def get_events(self, **kwargs):
        log.debug("binder=pagination_start data_type={}".format(kwargs))
        log.debug("I have KWARGS: {}".format(kwargs))
        kwargs["type"] == "dns_event"

        log.debug("calling for events")
        # partial_events = self._call(t0=kwargs["t0"], t1=kwargs["t1"], endpoint=kwargs["endpoint"])
        partial_events = self._call(**kwargs)
        partial_events_length = 0
        log.debug("Returned results: {}".format(partial_events))
        log.debug("partial_events[result] len is {}".format(len(partial_events["result"])))
        if partial_events["result"] is not None and int(partial_events["status_code"]) == 200:
            log.debug("partial_events is Not None")
            partial_events_length = len(partial_events["result"])
        else:
            log.debug("partial_events is None")
            return partial_events

        total_events = {"status_code": int(partial_events["status_code"]), "result": []}
        total_events["result"].extend(partial_events["result"])

        log.debug("total event length = {}".format(len(total_events["result"])))
        return total_events


MI = infoblox(_APP_NAME, {
    "title": "Infoblox",
    "description": "Modular Input for events from Infoblox ActiveTrust Cloud",
    "args": [
        {"name": "tenanturl",
         "description": "The Infoblox ActiveTrust Cloud URL. For produdction csp.infoblox.com",
         "title": "Tenant URL",
         "required": True
         },
        {"name": "token",
         "description": "The authorization Token generated by Infolox",
         "title": "Token"
         },
        {"name": "t0",
         "description": "The start unix timestamp",
         "title": "t0"
         },
        {"name": "t1",
         "description": "The end unix timestamp. Max interval with t0 is 24h. Recommended value is 30 minute",
         "title": "t1"
         },
        {"name": "proxy_name",
         "description": "The stanza name for a configured proxy.",
         "title": "Proxy Name"
         },
        {"name": "use_mi_kvstore",
         "description": "Should the checkpoint use KVStore? ADVANCED NEED ONLY",
         "title": "Use KVStore for Checkpoints"}
    ]
})


def KVToString(eventDict):
    ev_dict = eventDict
    kv_pairs = ", ".join("{}={}".format(k, json.dumps(v)) for k, v in ev_dict.items())
    return kv_pairs


def run():
    MI.start()
    try:
        MI.config()
        use_proxy = False
        proxy_name = MI.get_config("proxy_name")

        log.info("setting proxy to: {}".format(proxy_name))

        if proxy_name is not None:
            if len(proxy_name) > 0 and proxy_name != "not_configured":
                use_proxy = True
        else:
            log.info("action=variable_check use_proxy={} skipping test")
        log.info("action=variable_check use_proxy={}".format(use_proxy))

        utils = Utilities(app_name=_APP_NAME, session_key=MI.get_config("session_key"))

        MI.host(MI.get_config("tenanturl"))
        MI.source(MI.get_config("name"))

        args_dict = {}
        args_event_type_dict = {}

        args_dict["token"] = utils.get_credential(_APP_NAME, MI.get_config("token"))
        args_dict["interval"] = MI.get_config("interval")
        args_dict["tenanturl"] = MI.get_config("tenanturl")
        args_dict["t0"] = int(MI.get_config("t0"))
        args_dict["t1"] = int(MI.get_config("t1"))
        args_event_type_dict["event_type"] = MI.get_config("event_type")

        log.debug("action=variable_check args_dict='{}'".format(args_dict))

        RESTConfig = {
            "auth":
                {"type": "token",
                 "token": args_dict["token"],
                 "authorization_string": "Token %s"
                 },
            "hostname": MI.get_config("tenanturl"),
            "headers": {'User-Agent': 'Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/46.0.2490.80 Safari/537.36',
						'Cache-Control': "no-cache"
                 },
            "verify_certificate": False
        }

        if use_proxy:
            RESTConfig["proxy"] = utils.get_proxy_configuration(MI.get_config("proxy_name"))

        RC = infoblox_client(_APP_NAME, RESTConfig)

        log.info("configuration=event_type value={}".format(args_event_type_dict["event_type"]))
        evts = [args_event_type_dict["event_type"]]
        if "," in args_event_type_dict["event_type"]:
            evts = args_event_type_dict["event_type"].split(",")

        for evt_type in evts:
            args_dict["event_type"] = evt_type.strip()
            args_dict["type"] = args_dict["event_type"]
            my_key = '{}:{}'.format(args_dict["tenanturl"], args_dict["event_type"])
            my_sourcetype = "infoblox:{}".format(args_dict["event_type"])
            MI.sourcetype(my_sourcetype)
            MI.checkpoint_default_lookback(86400)

            chk = MI._get_checkpoint(my_key)
            if chk is None:
                chk = {}
            MI.debug("returned from get_checkpoint TYPE: {0}".format(type(chk)))
            if type(chk) == float or type(chk) == int:
                oldchk = chk
                MI.debug("resetting the checkpoint to an object")
                chk = {}
                chk["last_time"] = oldchk
            if "last_time" not in chk:
                MI.debug("setting starting time to 0")
                chk["last_time"] = 0

            chk["checkpoint_name"] = my_key
            chk["modular_input"] = _APP_NAME
            MI.debug("Current checkpoint TYPE: {0}".format(type(chk)))

            atc_ga = int(datetime(2016, 12, 24, 0, 0).strftime("%s"))  # ATC 1.0 GA
            if int(chk["last_time"]) < atc_ga:
                MI.debug("setting starting time to t0")
                starttime = args_dict["t0"]
            else:
                MI.debug("setting starting time to chk last_time")
                starttime = int(chk["last_time"])
            
            endtime = starttime + (30 * 60)  # 30 minutes
            now = int((datetime.utcnow() - datetime.utcfromtimestamp(0)).total_seconds())
            if endtime + 90 > now:  # to deal with 90s, maximum delay to API
                endtime = now - 90

            log.debug("Start time: %s. End time: %s" % (starttime, endtime))

            args_dict["t0"] = starttime
            args_dict["t1"] = endtime

            log.debug("args:{}".format(args_dict))

            log.info(
                "t0_timestamp=%s,  t0_human=%s, t1_timestamp=%s, t1_human=%s, now_timestamp=%s  now_human=%s" % (
                args_dict["t0"], datetime.utcfromtimestamp(args_dict["t0"]).isoformat(), args_dict["t1"],
                datetime.utcfromtimestamp(args_dict["t1"]).isoformat(), now,
                datetime.utcfromtimestamp(now).isoformat()))

            result = None

            log.debug("Get events")

            try:
                result = RC.get_events(starttime=starttime, endtime=endtime, **args_dict)

            except Exception as e:
                exc_type, exc_obj, exc_tb = sys.exc_info()
                fname = os.path.split(exc_tb.tb_frame.f_code.co_filename)[1]
                jsondump = {"message": str((e)),
                            "exception_type": "%s" % type(e).__name__,
                            "exception_arguments": "%s" % e,
                            "filename": fname,
                            "line": exc_tb.tb_lineno,
                            "input": MI.get_config("name")
                            }
                log.error("Error occured making REST API call : {}".format(e, jsondump))
                MI.print_error(json.dumps(jsondump))

            # Need to make sure that result is actually something
            if result is not None:
                log.debug("The result length is {}".format(len(result)))

            events_not_found = []
            ids_added = []

            if result is not None:
                if not result["status_code"] == 200:
                    if result["status_detail"]:
                        raise Exception(json.dumps(result["status_detail"]))
                    else:
                        raise Exception(json.dumps(result))

                MI.sourcetype("infoblox:{}".format(evt_type))
                MI.print_multiple_events(result["result"])

            new_checkpoint=endtime
            chk["last_time"] = int(new_checkpoint)

            if new_checkpoint != 0:
                log.debug("New checkpoint will be %s" % new_checkpoint)
                MI._set_checkpoint(my_key, object=chk)

            # Output a summary event

            summary_dict = {}

            summary_dict["modular_input_consumption_time"] = new_checkpoint
            summary_dict["timestamp"] = new_checkpoint
            summary_dict["total_events"] = len(result["result"])
            summary_dict["infoblox_event_type"] = args_dict["event_type"]
            summary_dict["modular_input_name"] = MI.get_config("name")


            my_sourcetype = "infoblox:api"
            MI.sourcetype(my_sourcetype)
            MI.print_event(json.dumps(summary_dict))

    except Exception, e:
        exc_type, exc_obj, exc_tb = sys.exc_info()
        fname = os.path.split(exc_tb.tb_frame.f_code.co_filename)[1]
        jsondump = {"message": str(e),
                    "exception_type": "%s" % type(e).__name__,
                    "exception_arguments": "%s" % e,
                    "filename": fname,
                    "line": exc_tb.tb_lineno,
                    "input": MI.get_config("name")
                    }
        log.error("Error occured making REST API call : {} {}".format(e, jsondump))
        MI.print_error(json.dumps(jsondump))
    MI.info("Completed Modular Input Run")
    MI.stop()


if __name__ == '__main__':
    if len(sys.argv) > 1:
        if sys.argv[1] == "--scheme":
            MI.scheme()
        elif sys.argv[1] == "--validate-arguments":
            MI.validate_arguments()
        elif sys.argv[1] == "--test":
            print 'No tests for the scheme present'
        else:
            print 'You giveth weird arguments'
    else:
        run()

    sys.exit(0)

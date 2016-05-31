
import ness6rest as nessrest
import os
import re
import sys
import time
import datetime


class Scan(object):
    '''
    Scan interface
    '''

    def __init__(self,name,
                      scanner=None,
                      url="",
                      login="",
                      password="",
                      insecure="",
                      template=""):
        if scanner:
            self.scanner = scanner
        else:
            self.scanner = nessrest.Scanner(url=url,
                                            login=login,
                                            password=password,
                                            insecure=insecure)
        self.name = name
        self.scan_id = ""
        self.scanner_id = "1"
        self.folder_id = ""
        self.uuid = ""
        self.category = ""
        self.settings = {"launch":"ONETIME",
                         "enabled":False,
                         "launch_now":True,
                         "text_targets":"",
                         "file_targets":""}
        self.audits = {}
        self.creds = {}
        self.uploads = []
        self.categories = {}

        self._cache = {}

        if template:
            set_scan_template(template)

        if self.scanner.scan_exists(name):
            self.get_scan_settings(self.scanner.scan_id)

    def submit(self):
        self.settings["name"] = self.name
        self.settings["scanner_id"] = self.scanner_id
        self.settings["folder_id"] = self.folder_id
        extra = {"uuid":self.uuid,
                 "settings":self.settings}
        if self.audits:
            extra.update({"audits":self.audits})
        if self.creds:
            extra.update({"credentials":self.creds})
        for filename in self.uploads:
            self.scanner.upload(filename)

        if self.scan_id:
            self.scanner.action(action="scans/"+str(self.scan_id),
                                method="put",
                                extra=extra)
            if "error" in self.scanner.res:
                self._error(self.scanner.res["error"])
            self.scanner.action(action="scans/"+str(self.scan_id)+
                                "/launch",
                                method="post")
            if "error" in self.scanner.res:
                self._error(self.scanner.res["error"])
            self.get_scan_settings(self.scan_id)
        else:
            self.scanner.action(action="scans",
                                method="post",
                                extra=extra)
            if "error" in self.scanner.res:
                self._error(self.scanner.res["error"])
            self.scan_id = self.scanner.res["scan"]["id"]
            self.get_scan_settings(self.scan_id)

    def is_running(self):
        self.get_scan_info()
        return self.info["status"] == "running"

    def is_completed(self):
        self.get_scan_info()
        return self.info["status"] == "completed"

    def get_scan_info(self,scan_id=""):
        if scan_id:
            self.scan_id = scan_id
        self.scanner.action("scans/"+str(self.scan_id),
                            method="get")
        if "info" in self.scanner.res:
            self.info = self.scanner.res["info"]

    def get_scan_settings(self,scan_id=""):
        if scan_id:
            self.scan_id = scan_id
        self.scanner.action(action="editor/scan/"+str(scan_id),
                            method="get")
        self._cache["scan"] = self.scanner.res
        self.uuid = self._cache["scan"]["uuid"]

    def set_scan_template(self,name):
        self.scanner.action(action="editor/scan/templates", method="get")
        for template in self.scanner.res["templates"]:
            for key in template:
                if template[key] == name:
                    self.uuid = template["uuid"]
        if self.uuid:
            self.scanner.action(action="editor/scan/templates/"+
                                self.uuid,
                                method="get")
            self.settings.update(self._find_inputs(self.scanner.res))
            self._cache["template"] = self.scanner.res

    def get_scan_template_names(self):
        results = {}
        self.scanner.action(action="editor/scan/templates", method="get")
        for template in self.scan.res["templates"]:
            results[template["name"]] = template["title"]
        return results

    def set_compliance_category(self, name):
        categories = self.get_compliance_categories()

        # Try full word match first
        for category in categories.keys():
            if re.search("^"+name.lower()+"$", category.lower()):
                self.category = category
                return

        # Try contains match
        for category in categories.keys():
            if re.search(name.lower(), category.lower()):
                self.category = category
                return

    def get_compliance_categories(self):
        if self.categories:
            return self.categories
        if not "template" in self._cache:
            self._error("Template must be set before categories.")
        for item in self._cache["template"]["compliance"]["data"]:
            self.categories[item["name"]] = None
            if "offline_allowed" in item.keys() and item["offline_allowed"]:
                inputs = self._find_inputs(item)
                for key in inputs.keys():
                    self.categories[item["name"]] = key
        return self.categories

    def set_targets(self,targets):
        if type(targets) == list:
            self.settings["text_targets"] = ",".join(targets)
        else:
            self.settings["text_targets"] = targets

    def add_audit_file(self,filename):
        if not self.category:
            self._error("Plugin must be set before adding audit file.")
        self._verify_custom_audit_action("add")
        self.audits["custom"]["add"].append({"category":self.category,
                                     "file":os.path.basename(filename)
                                     })
        self.uploads.append(filename)

    def remove_all_audit_files(self):
        if not "scan" in self._cache or not "compliance" in self._cache["scan"]:
            return
        self._verify_custom_audit_action("delete")
        for record in self._cache["scan"]["compliance"]["data"]:
            for audit in record["audits"]:
                if audit["type"] == "custom" and "id" in audit:
                    self.audits["custom"]["delete"].append(audit["id"])

    def add_config_file(self,filename):
        if not self.category:
            self._error("Plugin must be set before adding config file.")
        if self.categories[self.category]:
            self.settings[self.categories[self.category]] = filename
            self.uploads.append(filename)

    def _verify_custom_audit_action(self,action="add"):
        if not self.audits:
            self.audits = {"custom":{action:[]}}
        if "custom" not in self.audits:
            self.audits["custom"] = {action:[]}
        if action not in self.audits["custom"]:
            self.audits["custom"][action] = []

    def add_credential(self,cred):
        self._verify_credential_action("add",cred.category,cred.name)
        self.creds["add"][cred.category][cred.name].append(cred.__dict__)

    def remove_all_credentials(self):
        if not "scan" in self._cache or not "credentials" in self._cache["scan"]:
            return
        self._verify_credential_action("delete")
        for record in self._cache["scan"]["credentials"]["data"]:
            for item in record["types"]:
                for instance in item["instances"]:
                    self.creds["delete"].append(instance["id"])

    def _verify_credential_action(self,action="add",category="",name=""):
        if action == "delete" and not self.creds:
            self.creds = {action:[]}
        else:
            if not self.creds:
                self.creds = {action:{category:{name:[]}}}
            if action not in self.creds:
                self.creds[action] = {category:{name:[]}}
            if category not in self.creds[action]:
                self.creds[action][category] = {name:[]}
            if name not in self.creds[action][category]:
                self.creds[action][category][name] = []

    def set_folder(self,name):
        # Find folder by name
        self.scanner.action(action="folders", method="get")
        for folder in self.scanner.res["folders"]:
            if folder["name"] == name:
                self.folder_id = folder["id"]
                break

        # Create if does not exist
        if not self.folder_id:
            self.scanner.action("folders",
                                method="post",
                                extra={"name": name})
            self.folder_id = self.scanner.res["id"]

    def _export_in_progress(self,file_id):
        url = "scans/"+str(self.scan_id)+"/export/"+str(file_id)+"/status"
        self.scanner.action(url,method="get")
        return self.scanner.res["status"] != "ready"

    def _find_inputs(self,obj):
        result = {}
        if type(obj) is dict:
            if "inputs" in obj and obj["inputs"]:
                result.update(self._extract_inputs(obj["inputs"]))
            for key in obj:
                result.update(self._find_inputs(obj[key]))
        elif type(obj) is list:
            for item in obj:
                result.update(self._find_inputs(item))
        return result
    
    def _extract_inputs(self,inputs):
        result = {}
        for item in inputs:
            key = ""
            kind = ""
            value = ""
            if "id" in item:
                key = item["id"]
            if "type" in item:
                kind = item["type"]
            if "default" in item:
                value = item["default"]
            if key and not kind == "entry" and not value == None:
                result[key] = value
        return result

    def status_info(self):
        self.get_scan_info()
        duration = self.info["scan_end"]-self.info["scan_start"]

        return "%s\nStatus:   %s\nStart:    %s\nEnd:      %s\nDuration: %s" % (
                                  str(self.info["name"]),
                                  str(self.info["status"]),
                                  datetime.datetime.fromtimestamp(self.info["scan_start"]).strftime("%Y/%m/%d %H:%M:%S"),
                                  datetime.datetime.fromtimestamp(self.info["scan_end"]).strftime("%Y/%m/%d %H:%M:%S"),
                                  "%d:%02d" % (int(duration/60),int(duration%60)))

    def _error(self,message):
        print(message)
        sys.exit()

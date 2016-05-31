__author__ = 'Patrizio Tufarolo'
__email__ = 'patrizio.tufarolo@studenti.unimi.it'

from testagent.probe import Probe

import os, sys
sys.path.append(os.path.join(os.path.dirname(__file__), "Search-Scan/"))
print("PROXY:" , os.getenv("http_proxy"));
_searchscan = __import__('Search-scan', globals(), locals(), [], -1); ''' add every class u want to import to the list in the fourth argument, then call it by asking for _searchscan.* '''

globals().update(vars(_searchscan));

class SearchScanPublicInterface(_searchscan.PublicInterface):
    def __init__(self, testinstances):
        self.time = testinstances["parameters"]["Time"]
        self.category = testinstances["parameters"]["Category"]
        print("CATEGORY", self.category)
        self.cvss = float(testinstances["parameters"]["CVSS"])
        self.mongoHost = testinstances["mongo"]["host"]
        self.mongoPort = int(testinstances["mongo"]["port"])
        self.nessusHost = testinstances["nessus"]["host"]
        self.nessusLogin = testinstances["nessus"]["login"]
        self.nessusPassword = testinstances["nessus"]["password"]
        self.nessusPolicyName = 'Test_Policy_%s' % self.category
        self.nessusScanName = 'Scan_%s' % self.category
        self.nessusTarget = testinstances["nessus"]["Target"]
        self.sshUser = testinstances["credentials"]["ssh_user"]
        self.sshPassword = testinstances["credentials"]["ssh_pass"]
        self.file = testinstances["credentials"]["PrivateKeyPath"]
        self.certUser = testinstances["credentials"]["certUser"]
        self.certPass = testinstances["credentials"]["certPass"]
        self.mongoUser = testinstances["credentials"]["MongoDB_user"]
        self.mongoPassword = testinstances["credentials"]["MongoDB_pass"]
        self.mongoDB = testinstances["credentials"]["MongoDB"]
        self.mysqlUser= testinstances["credentials"]["MySQL_user"]
        self.mysqlPassword = testinstances["credentials"]["MySQL_pass"]
        self.checkRequirements()
        self.final_status = False
        Engine(self)

    def outputs(self, Scan):
        Scan.scan_results()
        self.myScanResults = Scan.download_scan(export_format='nessus');        

    def certification(self):
        if not self.myScanResults:
            raise Exception("No scan results yet")
        rpt = dotnessus_parser.Report()
        rpt.parse(self.myScanResults, True)
        if len(rpt.targets) is not 0:
            for t in rpt.targets:
                for v in t.vulns:
                    if v.get('risk_factor') != 'None':
                        print("Certification not possible: plugin %s return a positive match!"
                              %v.get('plugin_name'))
                        self.final_status = False
                        return False
                    else:
                        print("No vulnerability found on the target, certification ok!")
                        self.final_status = True
                        return True
        else:
            print('Error, no target found in report!')
            self.final_status = False
            return False
    def returnFinalStatus(self):
        print self.final_status
        return self.final_status


class SearchScanProbe(Probe): #ricordati di ereditare da Probe poi
    def main(self, inputs):
        print(self.testinstances)
        return SearchScanPublicInterface(self.testinstances).returnFinalStatus()
 
    def nullRollback (self, inputs):
        return

    def appendAtomics(self):
        self.appendAtomic(self.main, self.nullRollback)
probe = SearchScanProbe 

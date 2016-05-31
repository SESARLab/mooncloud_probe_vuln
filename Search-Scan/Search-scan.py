'''
Welcome in Search-Scan
'''

__author__ = 'Lorenzo Comi'
__email__ = 'lorenzo.comi@studenti.unimi.it'

from pymongo import MongoClient
import time
import requests
import sys
from bs4 import BeautifulSoup
import re
from nessrest import ness6rest, credentials
from multiprocessing.pool import ThreadPool as Pool
import datetime
import configparser
import argparse
import dotnessus_parser

def onlinePluginSearch(cveList):
        '''
        Interroga il database dei plugin di Nessus per cercare gli id correlati alle vulnerabilita' e aggiorna la cache
        Search in Nessus's plugin database and return the plugin-id's correlated to the vulnerabilities, so update cache
        '''

        pluglist = []
        payload = {'data': cveList, 'what': 'cve'}

        try:
            r = requests.post(url='http://www.tenable.com/plugins/index.php?view=search', data=payload)
        except requests.Timeout:
            raise MyError("Timeout error")

        if r.status_code != 200:
            raise MyError('HTTP request error' + str(r.status_code))

        soup = BeautifulSoup(r.text,"lxml")

        for id in soup.find_all(href=re.compile("\d+")):
            string = str(id)
            match = re.search('>\d{5}<', string)
            if match:
                stringa = re.findall('\d{5}', match.string)[0]
                pluglist.append(stringa)
                print("ADDED" , stringa)
        print("OK DONE")
        return cveList, pluglist

class Tee(object):
    '''
    Semplice classe per lo switch tra standard output e output su file
    Switch output from stdout to file
    '''

    def __init__(self, *files):
        self.files = files

    def write(self, obj):
        for f in self.files:
            f.write(obj)

    def flush(self):
        pass

class PublicInterface(object):

    def __init__(self, configFile):
        Config = configparser.ConfigParser()
        Config.read(configFile)
        self.time = Config.get(section='parameters', option='Time')
        self.category = Config.get(section='parameters', option='Category')
        self.cvss = Config.getfloat(section='parameters', option='CVSS')
        self.mongoHost = Config.get(section='mongo', option='host')
        self.mongoPort = Config.getint(section='mongo', option='port')
        self.nessusHost = Config.get(section='nessus', option='host')
        self.nessusLogin = Config.get(section='nessus', option='login')
        self.nessusPassword = Config.get(section='nessus', option='password')
        self.nessusPolicyName = 'Test_Policy_%s' % self.category
        self.nessusScanName = 'Scan_%s' % self.category
        self.nessusTarget = Config.get(section='nessus', option='Target')
        self.sshUser = Config.get(section='credentials', option='ssh_user')
        self.sshPassword = Config.get(section='credentials', option='ssh_pass')
        self.file = Config.get(section='credentials', option='PrivateKeyPath')
        self.certUser = Config.get(section='credentials', option='certUser')
        self.certPass = Config.get(section='credentials', option='certPass')
        self.mongoUser = Config.get(section='credentials', option='MongoDB_user')
        self.mongoPassword = Config.get(section='credentials', option='MongoDB_pass')
        self.mongoDB = Config.get(section='credentials', option='MongoDB')
        self.mysqlUser= Config.get(section='credentials', option='MySQL_user')
        self.mysqlPassword = Config.get(section='credentials', option='MySQL_pass')
        self.checkRequirements()
        Engine(self)

    def checkRequirements(self):

        if self.category == '':
            raise MyError('No category provided, exiting')

        if self.time == '':
            raise MyError('No time provided, exiting')

        if self.cvss == None:
            raise MyError('No cvss provided, exiting')

        if self.mongoHost == '':
            raise MyError("No vulnerability database's url provided, exiting")

        if self.mongoPort == None:
            raise MyError("No vunerability database's port provided, exiting")

        if self.nessusTarget == '':
            raise MyError('No target provided, exiting')

        if self.nessusHost == '':
            raise MyError("No scanner's url provided, exiting")

        if self.nessusLogin == None:
            raise MyError("No scanner's user provided, exiting")

        if self.nessusPassword == None:
            raise MyError("No scanner's password provided, exiting")

        return True

    def outputs(self, Scan):
        '''
        Metodo che si occupa della gestione degli outputs
        Outputs managment method
        '''

        file = open('Outputs/Report%s_%s.txt' % (self.category, self.nessusTarget), 'w')
        original = sys.stdout
        sys.stdout = Tee(sys.stdout, file)
        Scan.scan_results()
        file.close()
        sys.stdout = original
        content = open('Outputs/scan%s_%s.nessus' % (self.category, self.nessusTarget), 'w')
        content.write(Scan.download_scan(export_format='nessus'))
        content.close()

    def certification(self):
        '''
        Metodo che valuta se il criterio di certificazione e' soddisfatto o meno
        Evaluation of the correct certification requirements method
        '''

        nessusfile = 'Outputs/scan%s_%s.nessus' % (self.category, self.nessusTarget)
        rpt = dotnessus_parser.Report()
        rpt.parse(nessusfile)
        if len(rpt.targets) is not 0:
            for t in rpt.targets:
                for v in t.vulns:
                    if v.get('risk_factor') != 'None':
                        print("Certification not possible: plugin %s return a positive match!"
                              %v.get('plugin_name'))
                        return True
                    else:
                        print("No vulnerability found on the target, certification ok!")
                        return False
        else:
            print('Error, no target found in report!')
            return False

class MyError(Exception):
    pass

class DbInterface(object):

    def __init__(self, url, port, category):
        self.client = MongoClient(url, port)
        self.db = self.client.cvedb
        self.cveCollection = self.db.cves
        self.plugCollection = self.db.cveplug
        self.category = category
        self.cvelist = []

    #ritorna una lista
    def getCve(self, time, cvss):
        '''
        Cerco all'interno del mio db i cve-id
        Search for CVE-ID in the database
        '''

        print("Starting vulnerability research...")

        if self.category[0] == 'A':
            cwe = self.owaspConverter(self.category)

        if self.category == 'Openstack':
            cwe = 'Openstack'
            num_vuln_trovate = self.db.cves.find({ "$text": { "$search": "Openstack"}}, {"id": 1, "_id": 0}).count()


        elif cwe =='CWE-77, CWE-74, CWE-89, CWE-94':  #A1
            num_vuln_trovate = self.db.cves.find({ "$or": [{"cwe": "CWE-77"}, {"cwe": "CWE-74"}, {"cwe": "CWE-89"},
                                    {"cwe": "CWE-94"}], "Published": {"$gte": time}, "cvss": {"$gte": cvss}}).count()

        elif cwe =='CWE-287, CWE-255':  #A2
            num_vuln_trovate = self.db.cves.find({ "$or": [{"cwe": "CWE-287"}, {"cwe": "CWE-255"}],
                                              "Published": {"$gte": time}, "cvss": {"$gte": cvss}}).count()

        elif cwe =='CWE-22, CWE-21, CWE-59':  #A4
            num_vuln_trovate = self.db.cves.find({ "$or": [{"cwe": "CWE-22"}, {"cwe": "CWE-21"}, {"cwe": "CWE-59"}],
                                              "Published": {"$gte": time}, "cvss": {"$gte": cvss}}).count()

        elif cwe =='CWE-254, CWE-16':  #A5
            num_vuln_trovate = self.db.cves.find({ "$or": [{"cwe": "CWE-254"}, {"cwe": "CWE-16"}],
                                              "Published": {"$gte": time}, "cvss": {"$gte": cvss}}).count()

        elif cwe =='CWE-310, CWE-200':  #A6
            num_vuln_trovate = self.db.cves.find({ "$or": [{"cwe": "CWE-310"}, {"cwe": "CWE-200"}],
                                              "Published": {"$gte": time}, "cvss": {"$gte": cvss}}).count()

        else:  #A3, A7, A8
            num_vuln_trovate = self.db.cves.find({ "cwe": cwe, "Published" : {"$gte": time},
                                                   "cvss": {"$gte": cvss}}).count()

        print("Number of vulnerability found: %s " % num_vuln_trovate)

        if num_vuln_trovate != 0:

            if cwe == 'Openstack':
                for item in self.db.cves.find({ "$text": { "$search": "Openstack"}},{"id": 1, "_id": 0}):
                    self.cvelist.append(item['id'])

            elif cwe =='CWE-77, CWE-74, CWE-89, CWE-94':  #A1
                for item in self.db.cves.find({"$or": [{ "cwe": "CWE-77"}, {"cwe":"CWE-74"}, {"cwe":"CWE-89"} ,
                     {"cwe": "CWE-94"}], "Published" : {"$gte": time}, "cvss": {"$gte": cvss}}, {"id": 1, "_id": 0}):
                    self.cvelist.append(item['id'])

            elif cwe =='CWE-287, CWE-255':  #A2
                for item in self.db.cves.find({"$or": [{ "cwe": "CWE-287"}, {"cwe":"CWE-255"}],"Published" :
                                                        {"$gte": time}, "cvss": {"$gte": cvss}}, {"id": 1, "_id": 0}):
                    self.cvelist.append(item['id'])

            elif cwe =='CWE-22, CWE-21, CWE-59':  #A4
                for item in self.db.cves.find({"$or": [{ "cwe": "CWE-22"}, {"cwe": "CWE-21"}, {"cwe":"CWE-59"}],
                                          "Published" : {"$gte": time}, "cvss": {"$gte": cvss}}, {"id": 1, "_id": 0}):
                    self.cvelist.append(item['id'])

            elif cwe =='CWE-254, CWE-16':  #A5
                for item in self.db.cves.find({"$or": [{ "cwe": "CWE-254"}, {"cwe": "CWE-16"}], "Published":
                                                {"$gte": time}, "cvss": {"$gte": cvss}}, {"id": 1, "_id": 0}):
                    self.cvelist.append(item['id'])

            elif cwe =='CWE-310, CWE-200':  #A6
                for item in self.db.cves.find({"$or": [{ "cwe": "CWE-310"}, {"cwe": "CWE-200"}], "Published":
                                                {"$gte": time}, "cvss": {"$gte": cvss}}, {"id": 1, "_id": 0}):
                    self.cvelist.append(item['id'])

            else:  #A3, A7, A8
                for item in self.db.cves.find({"cwe": cwe, "Published": {"$gte": time}, "cvss": {"$gte": cvss}},
                                                {"id": 1, "_id": 0}):
                    self.cvelist.append(item['id'])

            return self.cvelist

        else:
            raise MyError("No vulnerability found")

    def owaspConverter(self, category):
        '''
        Metodo che converte la category OWASP nei corrispettivi CWE_id
        Convert the OWASP category into the right CWE category
        '''

        if category == 'A1':
            return "CWE-77, CWE-74, CWE-89, CWE-94"
        if category == 'A2':
            return "CWE-287, CWE-255"
        if category == 'A3':
            return "CWE-79"
        if category == 'A4':
            return "CWE-22, CWE-21, CWE-59"
        if category == 'A5':
            return "CWE-254, CWE-16"
        if category == 'A6':
            return "CWE-310, CWE-200"
        if category == 'A7':
            return "CWE-284"
        if category == 'A8':
            return "CWE-352"

        raise MyError("Categoria OWASP inesistente, specificarne una tra A1 e A8")

    def getPlugin(self, DB, cveList):
        '''
        In base allo stato della cache cerca i plugin online o in locale
        Based on cache status choose between the online-search or the local one
        '''

        if self.plugCollection.find_one({"Category": self.category}) == None:
            print("Empty collection 'cveplug' or no category elements found, starting online plugin research...")
            plist = self.worker(DB, cveList)
            self.copertura(cveList)
            return plist

        else:
            print ("Starting plugin cache research...")
            plist = self.cacheSearch(cveList)
            self.copertura(cveList)
            return plist

    def copertura(self, cve):
        counter = 0
        numbers = int(len(cve))
        for item in cve:
            for cveplug in self.db.cveplug.distinct("CVE"):
                if item == cveplug:
                    #print("PluginCVE" + cveplug + "CVE"+item)
                    counter=counter+1

        percent = (counter/numbers)*100
        #print("Vulnerabilita' trovate: ", numbers)
        #print("N. of univoke plugin: ", counter)
        print("Ratio between N. of vulnerability and N. of unique plugin: %.2f" % percent + "%")


    def updateCache(self, cve, pluginid):
        '''
        Inserisce all'interno del DatabaseMongo i dati relativi ai plugin-nessus (GESTIONE DELLA CACHE)
        Cache managment
        '''

        post = {"CVE": cve,
                "PluginID": pluginid,
                "Category": self.category,
                "Date": datetime.datetime.utcnow()
                }

        self.plugCollection.ensure_index("Date")
        #setto il TTL a 5 giorni, devi fare il drop se vuoi cambiarlo

        self.plugCollection.insert_one(post).inserted_id

    def worker(self, db, lista):
        '''
        Metodo per eseguire il processo di ricerca dei plugin in multithread
        Multithread method for online search
        '''

        # Make the Pool of workers
        processes = 5 
        #WARNING: con la fibra posso arrivare a 20 senza errori, con adsl massimo 4 worker!
        pool = Pool(processes)

        # Open the urls in their own threads and return the results
        pluglist = pool.map(onlinePluginSearch, lista)

        #close the pool and wait for the work to finish
        pool.close()
        pool.join()

        #parsa il risultato (lista con tuple) e metti tutto in una stringa (result) e aggiorna cache
        result = ''
        for item in pluglist:
            if item[1] !=[]:
                for plug in item[1]:
                    db.updateCache(item[0], plug)
                    result = result + str(plug) + ','

        numbers = result.count(',') + 1
        print("Number of available pflugins: %s" % numbers)
        print("Adding to policy plugins: 19506,10287,12634 for credential checks and ping target.")
        result = result + "19506,10287,12634"
        #aggiungo sempre questi 3 plug-in per verificare se il target e' alive

        return result

    def cacheSearch(self, cveList):
        '''
        Cerca i plugin id all'interno della cache
        Loacal Plugin search
        '''

        list=[]
        pluglist = []

        current = 0
        if len(cveList) > 0:
            while current < len(cveList):
                for item in self.plugCollection.find({"CVE": cveList[current]}):
                    pluglist.append(item['PluginID'])
                    list.append(cveList[current])
                current = current + 1
        else:
            raise MyError("Empty vulnerability list!")

        print("Number of available plugins: %s" % len(pluglist))
        result = ','.join(pluglist)
        #trasformo la lista di plug-in data in input in una stringa

        print("Adding to policy plugins: 19506,10287,12634 for credential checks and ping target")
        result = result + ",19506,10287,12634"
        #aggiungo sempre questi 3 plug-in per verificare se il target e' alive

        return result

class ScannerInterface(ness6rest.Scanner):

    def buildCredential(self, Public):
        creds = []
        if Public.sshUser != '' and Public.sshPassword != '':
            creds = [
                credentials.SshPassword(username=Public.sshUser, password=Public.sshPassword)# \
                    #.sudo("password"),
                ]
        if Public.mongoUser != '' and Public.mongoPassword != '':
            creds.append(credentials.MongoDB(username=Public.mongoUser, password=Public.mongoPassword,
                                             database=Public.mongoDB, port=27017))

        if Public.mysqlUser != '' and Public.mysqlPassword != '':
            creds.append(credentials.MySQL(username='root', password='password', port=3306))

        if Public.file != '':
            creds.append(credentials.SshPublicKey(username=Public.certUser, private_key_filename=Public.file,
                                                  private_key_passphrase=Public.certPass))
        if len(creds)==0:
            print('Warning: no credentials provided, '
                  'test will be launched anyway but local security checks will be disabled')

        return creds

    def plugins_info(self, plugins):
        '''
        Gather information on plugins for reporting. This also ensures that the
        plugin exists, and exits if it does not.
        '''
        for plugin in plugins.split(','):
            self.action(action="plugins/plugin/" + str(plugin), method="GET")

            if self.res:
                for attrib in self.res["attributes"]:
                    if attrib["attribute_name"] == "fname":
                        self.plugins.update({str(plugin):
                                             {"fname":
                                              attrib["attribute_value"],
                                              "name": self.res["name"]}})
            else:
                # We don't want to scan with plugins that don't exist.
                #print("Il Plugin con ID %s non e' stato trovato nella tua versione di Nessus, quindi non
                        # verra' incuso nella policy." % plugin)
                print("Plugin %s not found in your Nessus version so it will be excluded from policy." % plugin)
                #sys.exit(1)

    def _policy_set_settings(self):
        '''
        Current settings include: safe_checks, scan_webapps, report_paranoia,
        provided_creds_only, thorough_tests, report_verbosity,
        silent_dependencies
        '''
        settings = {"settings": {}}

        # Default to safe checks
        # Values: yes, no
        if not self.set_safe_checks:
            self.set_safe_checks = "yes"

        # Default to not scanning webapps
        # Values: yes, no
        if not self.pref_cgi:
            self.pref_cgi = "yes"

        # Default to normal paranoia levels
        # Values: Avoid false alarms, Normal, Paranoid
        if not self.pref_paranoid:
            self.pref_paranoid = "Normal"

        # Default to allow scans to check for default credentials
        # Values: yes, no
        if not self.pref_supplied:
            self.pref_supplied = "yes"

        # Default to not use thorough tests
        # Values: yes, no
        if not self.pref_thorough:
            self.pref_thorough = "no"

        # Default to normal verbosity.
        # Values: Quiet, Normal, Verbose
        if not self.pref_verbose:
            self.pref_verbose = "Verbose"

        # Default to normal reporting of dependencies
        # Values: yes, no
        if not self.pref_silent_dependencies:
            self.pref_silent_dependencies = "yes"

        settings["settings"].update({"safe_checks": self.set_safe_checks})
        settings["settings"].update({"scan_webapps": self.pref_cgi})
        settings["settings"].update({"report_paranoia": self.pref_paranoid})
        settings["settings"].update({"provided_creds_only": self.pref_supplied})
        settings["settings"].update({"thorough_tests": self.pref_thorough})
        settings["settings"].update({"report_verbosity": self.pref_verbose})
        settings["settings"].update({"silent_dependencies": self.pref_silent_dependencies})
        settings["settings"].update({"cisco_offline_configs":
                                     self.cisco_offline_configs})

        self.action(action="policies/" + str(self.policy_id), method="put",
                    extra=settings)

    def download_scan(self, export_format="nessus"):
        running = True
        #counter = 0

        self.action("scans/" + str(self.scan_id), method="get")
        data = {'format': export_format}
        self.action("scans/" + str(self.scan_id) + "/export",
                                        method="post",
                                        extra=data)

        file_id = self.res['file']
        print('Download for file id '+str(self.res['file'])+'.')

        while running:
            time.sleep(2)
            #counter += 2
            self.action("scans/" + str(self.scan_id) + "/export/" + str(file_id) + "/status", method="get")
            running = self.res['status'] != 'ready'
            '''
            sys.stdout.write(".")
            sys.stdout.flush()
            if counter % 60 == 0:
                print("")
            '''
        print("")

        content = self.action("scans/" + str(self.scan_id) + "/export/"
                              + str(file_id) + "/download",
                              method="get",
                              download=True)
        return content

    def _scan_status(self):
        '''
        Check on the scan every 2 seconds.
        '''
        running = True
        counter = 0

        while running:
            self.action(action="scans?folder_id=" + str(self.tag_id),
                        method="get")

            for scan in self.res["scans"]:
                if (scan["uuid"] == self.scan_uuid and scan['status'] == "running"):

                    #sys.stdout.write(".")
                    #sys.stdout.flush()
                    time.sleep(2)
                    counter += 2

                    #if counter % 60 == 0:
                    #    print('')

                if (scan["uuid"] == self.scan_uuid and scan['status'] != "running"):

                    running = False

                    # Yes, there are timestamps that we can use to compute the
                    # actual running time, however this is just a rough metric
                    # that's more to get a feel of how long something is taking,
                    # it's not meant for precision.
                    print("\nComplete! Run time: %d seconds." % counter)
        return 'completed'

    def scan_results(self):
        '''
        Get the list of hosts, then iterate over them and extract results
        '''
        counter6 = 0
        counter5 = 0
        counter4 = 0
        counter3 = 0
        counter2 = 0
        counter1 = 0
        setplugin = []
        safeplugin = []
        osplugin = []
        missplugin = []
        negplugin = []
        okplugin = []
        # Check the status, we will be in a "wait" until the scan completes
        self._scan_status()

        # Query the completed scan and parse results
        self.action("scans/" + str(self.scan_id), method="get")

        for host in self.res["hosts"]:
            if self.format_start:
                print(self.format_start)

            print("----------------------------------------")
            print("Target    : %s" % host["hostname"])
            print("----------------------------------------\n")

            for plugin in self.plugins.keys():
                self.action("scans/" + str(self.scan_id) + "/hosts/" +
                            str(host["host_id"]) + "/plugins/" + str(plugin),
                            method="get")

                # If not defined, the plugin did not fire for the host
                if self.res["outputs"]:

                    print("Plugin Name   : " + self.plugins[plugin]["name"])
                    print("Plugin File   : " + self.plugins[plugin]["fname"])
                    print("Plugin ID     : %s" % plugin)
                    print("Plugin Output :")

                    for output in self.res["outputs"]:
                        if 'plugin_output' in output:
                            print(output["plugin_output"])
                            counter2 = counter2+1
                            okplugin.append(plugin)

                        else:
                            print("Success")
                            print()

                # The 6.x Audit Trail has less information than previous
                # versions(no plugin name). This information could be captured
                # during the call to "_enable_plugins", and stored, but is
                # somewhat limited in utility.
                self.action("scans/" + str(self.scan_id) +
                            "/trails/?plugin_id=" + str(plugin) + "&hostname=" +
                            host["hostname"], method="get")

                # If there is audit trail, the self.res is 'null'
                if self.res:
                    for output in self.res:
                        if self.res['trails'] is not None:
                            #print(self.res)
                            #print(output)
                            print("Plugin Name   : " +
                                  self.plugins[plugin]["name"])
                            print("Plugin File   : " +
                                  self.plugins[plugin]["fname"])
                            print("Plugin ID     : %s" % plugin)

                            print("Audit trail   : " + self.res[output][0]["output"])#["output"])
                            print()

                            if re.findall("[a-zA-Z-_0-9. /]+ is missing", self.res[output][0]["output"]):
                                counter1 = counter1+1
                                missplugin.append(plugin)

                            elif re.findall("The remote host is not affected.", self.res[output][0]["output"]):
                                counter3 = counter3+1
                                negplugin.append(plugin)

                            elif re.findall("was not launched because safe checks are enabled", self.res[output][0]["output"]):
                                counter4 = counter4+1
                                safeplugin.append(plugin)

                            elif re.findall("The remote host's OS is not", self.res[output][0]["output"]):
                                counter5 = counter5+1
                                osplugin.append(plugin)

                            elif re.findall("item is not set.", self.res[output][0]["output"]):
                                counter6 = counter6+1
                                setplugin.append(plugin)

            if self.format_end:
                print(self.format_end)
        print('----------------------------------------')
        print("Plugin not launched because no application found: %s\n" % counter1, missplugin)
        print("Plugin with positive result: %s\n" % counter2, okplugin)
        print("Plugin with negative result: %s\n" % counter3, negplugin)
        print("Plugin not launched for safe check: %s\n" % counter4, safeplugin)
            #http://www.tenable.com/blog/understanding-the-nessus-safe-checks-option
        print("Plugin with OS incompatibility (the target is not affected by vulnerability): %s\n" % counter5, osplugin)
        print("Plugin not launched because item is not set: %s\n" % counter6, setplugin)

        '''
        if self.res['comphosts'] is not []:

            for host in self.res['comphosts']:
                print("----------------------------------------")
                print("Target    : %s" % host["hostname"])
                print("----------------------------------------\n")

                for plugin in self.res["compliance"]:
                    self.action("scans/" + str(self.scan_id) + "/hosts/" +
                                str(host["host_id"]) + "/compliance/" +
                                str(plugin['plugin_id']), method="get")
                    self.pretty_print()
        '''

class Engine(object):

    def __init__(self, publicInterface):
        #print('Welcome in Search & Scan Software, by Lorenzo Comi')
        Public = publicInterface
        DB = DbInterface(url=Public.mongoHost, port=Public.mongoPort, category=Public.category)
        cveList = DB.getCve(time=Public.time, cvss=Public.cvss)
        plugin = DB.getPlugin(DB, cveList) #plugin e' una stringa
        Scanner = ScannerInterface(Public.nessusHost, Public.nessusLogin, Public.nessusPassword, insecure=True)
        if Public.file != '':
            Scanner.upload(upload_file=Public.file, file_contents="")
        print("Building Policy, please wait...")
        Scanner.policy_add(name=Public.nessusPolicyName, plugins=plugin,
                                credentials=Scanner.buildCredential(Public), template='advanced' )
        Scanner.scan_add(targets=Public.nessusTarget, name=Public.nessusScanName)
        Scanner.scan_run()
        Public.outputs(Scanner)
        Public.certification()



if __name__ == '__main__':
    try:
        parser = argparse.ArgumentParser(description='This is a program by Lorenzo Comi, type -i and insert .conf file')
        parser.add_argument('-i', '--input', help='Input file name', required=True)
        args = parser.parse_args()
        Public = PublicInterface(args.input)
    except MyError as e:
        print(e.args)



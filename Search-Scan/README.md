# Search-Scan
This software Search trough the NVD (National Vulnerability Database) the vulnerability CVE's based on the OWASP top ten category or the CWE and the CVSS score. With the vulnerbabilities CVE-id, the software try to test them on a target using the Nessus Software.
Thesis project by Comi Lorenzo 

Requirements
------------

* Python3.2 or later
* MongoDB 2.2 or later
* Nessus Vulnerability scanner (http://www.tenable.com)
* Pip3  
* cve-search (https://github.com/adulau/cve-search) or cve-search-light
* Pymongo
* Beautiful Soup


Installation of Nessus
----------------------

You can install the latest version of Nessus vulnerability scanner by http://www.tenable.com/products/nessus/select-your-operating-system for my deploy i used the free version of the software wich means that you have to give Tenable your email for a free activation code... but you can also use a premiun version!

Installation of MongoDB
-----------------------

First, you'll need to have a Python 3 installation (3.2 or 3.3 preferred).
Then you need to install MongoDB (2.2) from source (this should also work
with any standard packages from your favorite distribution). Don't forget
to install the headers for development while installing MongoDB.
You can go to http://docs.mongodb.org/manual/installation/ for to get the
packages for your distribution, or http://www.mongodb.org/downloads for
the source code.


Populating the database
-----------------------

For the initial run, you need to populate the CVE database by running the cve-search scripts, located in the /sbin folder of the project. For this procedure you can download the latest cve-search script by the project page or you can use the "light" version of the package presents in this repo:

    ./db_mgmt.py -p
    ./db_mgmt_cpe_dictionary.py
    ./db_updater.py -c
    ./python3.3 db_fulltext.py

It will fetch all the existing XML files from the Common Vulnerabilities
and Exposures database and the Common Platform Enumeration.
Indexing all the database with fulltext.py is necessary if you want search for "openstack" or other text-based vulnerability name. 

Databases and collections
-------------------------

The MongoDB database is called cvedb and there are 10 collections:

* cves (Common Vulnerabilities and Exposure items) - source NVD NIST
* cpe (Common Platform Enumeration items) - source NVD NIST
* vendor (Official Vendor Statements on CVE Vulnerabilities) - source NVD NIST
* cwe (Common Weakness Enumeration items) - source NVD NIST
* capec (Common Attack Pattern Enumeration and Classification) - source NVD NIST
* ranking (ranking rules per group) - local cve-search
* d2sec (Exploitation reference from D2 Elliot Web Exploitation Framework) - source d2sec.com
* [vFeed](https://github.com/toolswatch/vFeed) (cross-references to CVE ids (e.g. OVAL, OpenVAS, ...)) - source [vFeed](https://github.com/toolswatch/vFeed)
* Microsoft Bulletin (Security Vulnerabilities and Bulletin) - source [Microsoft](http://www.microsoft.com/en-us/download/details.aspx?id=36982)
* info (metadata of each collection like last-modified) - local cve-search

Updating the database
---------------------

An updater script helps to start the db_mgmt_*  

    ./db_updater.py -v

You can run it in a crontab, logging is done in syslog by default.

Repopulating the database
-------------------------

To easily drop and re-populate all the databases

    ./db_updater.py -v -f

This will drop all the existing external sources and reimport everything. This operation can take some time
and it's usually only required when new attributes parsing are added in cve-search.

Usage
-----

1. Fill the configuration file with your parameters:
    * Nessus connection parameters (mandatory)
    * target ip (mandatory)
    * credentials (optional)
    * vulnerability parameters (mandatory)
    * mongo connection parameters (mandatory)

2. Use the following command to launch the script:

    $ python3 Search-scan.py -i configurazione.conf

The Outputs will be saved in the "Outputs" folder

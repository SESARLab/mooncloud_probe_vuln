#!/bin/bash

echo -e "MOON Cloud\n\n******** Installing Search Scan"
wget "http://downloads.nessus.org/nessus3dl.php?file=Nessus-6.7.0-es7.x86_64.rpm&licence_accept=yes&t=99f53edd2eebd0bf74fd3673862c3d4f" -O nessus.rpm
rpm -i nessus.rpm
systemctl start nessusd.service
echo -e "\n\nInsert you nessus activation code >>  "
read NESSUSLICENSE
yum -y install python34
yum -y install wget
curl https://bootstrap.pypa.io/get-pip.py | python3.4
yum -y install python34-devel
pip3 install python-dateutil
pip3 install pymongo
pip3 install redis
pip3 install request
pip3 install flask-login
pip3 install lxml
pip3 install xlrd
pip2 install pymongo
pip2 install configparser
cat mongo.repo > /etc/yum.repos.d/mongodb-org-3.2.repo
yum -y install mongodb-org
systemctl stop mongod.service
sed -i 's/SELINUX=enforcing/SELINUX=disabled/g' /etc/selinux/config
setenforce 0
systemctl start mongod.service
git clone https://github.com/cve-search/cve-search.git
pip3 install -r cve-search/requirements.txt
cve-search/sbin/db_mgmt.py -p
cve-search/sbin/db_mgmt_cpe_dictionary.py
cve-search/sbin/db_updater.py -c
cve-search/sbin/db_fulltext.py
echo -e "\n\nNessus admin setup\n"
/opt/nessus/sbin/nessuscli adduser admin
/opt/nessus/sbin/nessuscli fetch --register $NESSUSLICENSE
cp -r SearchScan /usr/lib/python2.7/site-packages/testagent-0.1.0-py2.7.egg/testagent/probes/
cp probe_searchscan.py /usr/lib/python2.7/site-packages/testagent-0.1.0-py2.7.egg/testagent/probes/

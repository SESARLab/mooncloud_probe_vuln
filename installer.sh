#!/bin/bash

echo -e "MOON Cloud\n\n******** Installing Search Scan"
wget "http://downloads.nessus.org/nessus3dl.php?file=Nessus-6.7.0-es7.x86_64.rpm&licence_accept=yes&t=99f53edd2eebd0bf74fd3673862c3d4f" -O nessus.rpm
rpm -i nessus.rpm
systemctl start nessusd.service
echo -e "\n\nDo you have a Nessus Activation Code?\n\n"
read NESSUSLICENSE
yum -y install python34
yum -y install wget
curl https://bootstrap.pypa.io/get-pip.py | python3.4
yum install python-devel
pip3 install python-dateutil
pip3 install pymongo
pip3 install redis
pip3 install request
pip3 install flask-login
pip3 install lxml
pip3 install xlrd
cat mongo.repo > /etc/yum.repos.d/mongodb-org-3.2.repo
yum -y install mongodb-org
systemctl stop mongod.service
sed -i 's/SELINUX=enforcing/SELINUX=disabled/g' /etc/selinux/config
systemctl start mongod.service
/opt/nessus/sbin/nessuscli adduser admin
/opt/nessus/sbin/nessuscli fetch --register $NESSUSLICENSE
cp probe_searchscan.py /usr/lib/python2.7/site-packages/testagent-0.1.0-py2.7.egg/testagent/probes/

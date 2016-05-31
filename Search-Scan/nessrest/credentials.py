class WindowsPassword(object):
    '''
    Username and password for a Windows target.
    '''
    category = "Host"
    name = "Windows"

    def __init__(self, username, password, domain="", auth_method="Password"):
        self.username = username
        self.password = password
        self.domain = domain
        self.auth_method = auth_method


class Ssh(object):
    '''
    Does not provide complete credential information on its own. Create one of
    its subclasses instead. The privilege escalation functions can be used on
    any subclass.
    '''
    category = "Host"
    name = "SSH"

    def __init__(self):
        self.elevate_privileges_with = "Nothing"

    def cisco_enable(self, enable_password):
        self.elevate_privileges_with = "Cisco 'enable'"
        self.escalation_password = enable_password
        return self

    def sudo(self, password, username="root"):
        self.elevate_privileges_with = "sudo"
        self.escalation_account = username
        self.escalation_password = password
        return self


class SshPassword(Ssh):
    '''
    Username and password for an SSH login.
    '''
    def __init__(self, username, password):
        super(SshPassword, self).__init__()
        self.auth_method = "password"
        self.username = username
        self.password = password


class SshPublicKey(Ssh):
    '''
    SSH certificate login. The private key must have been uploaded already.
    '''
    def __init__(self, username, private_key_filename, private_key_passphrase):
        super(SshPublicKey, self).__init__()
        self.auth_method = "public key"
        self.username = username
        self.private_key = private_key_filename
        self.private_key_passphrase = private_key_passphrase


class SshUserCert(SshPublicKey):
    '''
    SSH client certificate login. The private key and user cert must have been
    uploaded already.
    '''
    def __init__(self, username, user_cert_filename, private_key_filename,
                 private_key_passphrase):
        self.user_cert = user_cert_filename
        super(SshUserCert, self) \
            .__init__(username=username,
                      private_key_filename=private_key_filename,
                      private_key_passphrase=private_key_passphrase)


class AmazonAWS(object):
    '''
    Access ID and Secret for Amazon AWS
    '''
    category = "Cloud Services"
    name = "Amazon AWS"

    def __init__(self, access_key_id, secret_key):
        self.access_key_id = access_key_id
        self.secret_key = secret_key


class Salesforce(object):
    '''
    Username and password for Salesforce.com.
    '''
    category = "Cloud Services"
    name = "Salesforce.com"

    def __init__(self, username, password):
        self.username = username
        self.password = password


class PaloAltoPANOS(object):
    '''
    Username and password for a Palo Alto PAN-OS device through the web API.
    '''
    category = "Miscellaneous"
    name = "Palo Alto Networks PAN-OS"

    def __init__(self, username, password, port="443", verify_ssl=True):
        self.username = username
        self.password = password
        self.port = port
        self.verify_ssl = verify_ssl

class RHEV(object):
    '''
    Username and password for a Red Hat Enterprise Virtualization
    '''
    category = "Miscellaneous"
    name = "RHEV"

    def __init__(self, username, password, port="443", verify_ssl=True):
        self.username = username
        self.password = password
        self.port = port
        self.verify_ssl = verify_ssl


class IBMiSeries(object):
    '''
    Username and password for a IBM iSeries
    '''
    category = "Miscellaneous"
    name = "IBM iSeries"

    def __init__(self, username, password):
        self.username = username
        self.password = password


class VMwareVCenter(object):
    '''
    Username and password for a VMware vCenter
    '''
    category = "Miscellaneous"
    name = "VMware vCenter SOAP API"

    def __init__(self, username, password, host, https=True, port="443", verify_ssl=True):
        self.username = username
        self.password = password
        self.host = host
        self.port = port
        self.https = https
        self.verify_ssl = verify_ssl


class VMwareESX(object):
    '''
    Username and password for VMware ESX
    '''
    category = "Miscellaneous"
    name = "VMware ESX SOAP API"

    def __init__(self, username, password, dont_verify_ssl=False):
        self.username = username
        self.password = password
        self.dont_verify_ssl = dont_verify_ssl


class Database(object):
    '''
    Does not provide complete credential information on its own. Create one of
    its subclasses instead. The privilege escalation functions can be used on
    any subclass.
    '''
    category = "Database"
    name = "Database"

    def __init__(self, username, password, port, type):
        self.type = type
        self.username = username
        self.password = password
        self.port = port


class DB2(Database):
    '''
    Username and password for Database DB2
    '''
    def __init__(self, username, password, db_sid, port=50000):
        super(DB2, self).__init__(username, password, port, "DB2")
        self.db_sid = db_sid      # dbname


class Oracle(Database):
    '''
    Username and password for Database Oracle
    '''
    def __init__(self, username, password, oracle_sid, port=1521, oracle_auth_type="SYSDBA"):
        super(Oracle, self).__init__(username, password, port, "Oracle")
        self.oracle_sid = oracle_sid      # sid
        self.oracle_auth_type = oracle_auth_type      # SYSDBA, SYSOPER, NORMAL


class MySQL(Database):
    '''
    Username and password for Database MySQL
    '''
    def __init__(self, username, password, port=3306):
        super(MySQL, self).__init__(username, password, port, "MySQL")


class PostgreSQL(Database):
    '''
    Username and password for Database PostgreSQL
    '''
    def __init__(self, username, password, port=5432):
        super(PostgresSQL, self).__init__(username, password, port, "PostgresSQL")


class SQLServer(Database):
    '''
    Username and password for Database SQL Server
    '''
    def __init__(self, username, password, db_sid="", port=1433, auth_type="SQL"):
        super(SQLServer, self).__init__(username, password, port, "SQL Server")
        self.db_sid = db_sid      # instance
        self.sql_server_auth_type = auth_type      # SQL, Windows


class MongoDB(object):
    '''
    Username and password for MongoDB
    '''
    category = "Database"
    name = "MongoDB"

    def __init__(self, username, password, database="admin", port=27017):
        self.username = username
        self.password = password
        self.port = port
        self.database = database      # admin

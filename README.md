# README #

Enhanced implementation of LDAP connector for Splunk.

### What is this repository for? ###

* Execute LDAP queries from Splunk search bar
* Version: 1.3

### How do I get set up? ###

* Install or copy the whole folder under $SPLUNK_HOME/etc/apps

### Involved Files ###

*

### Usage ###
This is an Add-on for Splunk to execute LDAP queries right from Splunk searchbar.

You can either specify options from search:


```
| ldap server="mydomain"
```

```
| ldap server="mydomain" ldap_filter="(objectclass=*)"
```

```
| ldap server="mydomain" ldap_filter="(objectclass=*)" attrs="cn,mail,sn" 
```

```
| ldap server="mydomain" basedn="dc=thisismydomain,dc=us" ldap_filter="(objectclass=*)" attrs="cn,mail,sn" 
```


or use any stanza from ldap.conf. All options that can be used:

* **_server="STANZA"_**: specify LDAP server to be used, defaults to [default]
* **_port="PORT"_**: specify LDAP port to be used, defaults to port in [default]
* **_scope="SCOPE"_**: specify LDAP scope to be used in the search, defaults to sub
* **_ldap_filter="LDAP_FILTER"_**: specify LDAP filter to be used in the search
* **_basedn="BASEDN"_**: specify LDAP basedn to be used in the search, defaults to basedn in [default]
* **_timelimit="TIMEOUT"_**: specify LDAP search timeout to be used, defaults to 30 seconds
* **_sizelimit="LIMIT"_**: specify LDAP size limit to be used in the search, defaults to 5000 entries
* **_attrs="ATTRS"_**: provide comma separated LDAP attributes to be returned, defaults to all
* **_fetch="dc=example,dc=us"_**: provide DN to get all attributes from use all default stanza settings and return LDAP search response times in milliseconds

### Installation ###
1. Copy the whole Splunk_TA_LDAP under $SPLUNK_HOME/etc/apps directory
2. Make sure to have ldap.conf in  Splunk_TA_LDAP/**default** folder
3. Add your own stanza in Splunk_TA_LDAP/**default**/ldap.conf and modify ldap.conf as needed

### Log Files ###

* $SPLUNK_HOME/var/log/splunk/myldap.py.log

### Who do I talk to? ###

* 

### Reference ###
[https://github.com/f33dy0urhe4d/Splunk_TA_LDAP](https://github.com/f33dy0urhe4d/Splunk_TA_LDAP)
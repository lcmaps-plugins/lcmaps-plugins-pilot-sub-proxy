# lcmaps-plugins-pilot-sub-proxy
Non-standard LCMAPS plugin to handle pilot sub-proxies containing the username.

### Background
This plugin is intended to be used for a very specific gLExec-on-the-workernode
scenario, where the payload user has no certificate, but the pilot has reliable
information about this payload user. It should then be possible to transfer this
information into the gLExec tool to allow a user-switch to an account used
exclusively by this payload user.
This scenario is similar to the [EGI per-user sub-proxy
scenario](https://wiki.egi.eu/wiki/Fedcloud-tf:WorkGroups:Federated_AAI:per-user_sub-proxy).

### Usage
The pilot should create a (it's a hack) limited proxy-delegation, where the real
user identity is somehow encoded into the new proxy CN= field. This is again
very similar to the EGI per-user sub-proxy scenario, where the user identity is
encoded in the _first_ proxy delegation created by a robot certificate on a
portal.
A simple shell script which can be used for this, ```create_pilot_sub_proxy.sh```,
is provided in the ```tools``` directory.

It should set this new proxy as the _GLEXEC_CLIENT_CERT_. In order to prevent
the payload user from getting access to the pilot proxy, the pilot should
normally also specify the environment variable
> export GLEXEC_TARGET_PROXY=/dev/null

This plugin will verify (in this order) that:
* that the pilot proxy contains its private key,
* that both pilot and payload proxy are
[RFC3820](http://tools.ietf.org/html/rfc3820) compliant,
* it optionally (default) will check that both pilot and payload proxy are
Limited,
* it optionally can verify that at least one of the FQANs matches a pre-defined
pattern,
* the payload proxy (i.e. that pointed to by _GLEXEC_CLIENT_CERT_) is signed by
the proxy pointed to by the _X509_USER_PROXY_ variable,
* the effective proxy pathlength contraint for the payload proxy does not exceed
the maximum (default 0),
* the value of the extra proxy commonName RDN does not start with a slash (/).

When all checks succeed the plugin will register the value of the extra
commonName RDN of the payload (i.e. that of the extra proxy delegation) into the
LCMAPS framework. It can optionally (default) also store the FQANs of the proxy
into the LCMAPS framework.

It is important to run this plugin after the ```lcmaps-plugins-verify-proxy```,
to ensure that the entire proxy chain (incl. the pilot-sub-proxy) has been fully
validated.

The newly obtained DN and FQANs can be sent to e.g. a GUMS server using the
```lcmaps-plugins-scas-client``` version 0.5.5 or higher. The GUMS server should
subsequently check that the pilot user was entitle to use these type of proxies
and subsequently map the username to an actual account.

### Security considerations
There are certainly a number of issues with this scenario, and it has to be used
very carefully.
+ Note that anyone with a valid proxy can create a limited proxy delegation with
a 'hacked' CN field. It is therefore necessary to do an external independent
check of whether the pilot user is entitled to using such a proxy to start
payload jobs.
+ As mentioned above, it is necessary to prevent the payload user from getting
access to a valid pilot proxy, hence gLExec needs to be instructed not to copy
the proxy into the payload account.
+ It is necessary to validate the entire proxy chain, hence the verify proxy
plugin must run.
+ misusing the information in the proxy CN= field is really a hack: a proxy CN
is considered to be opaque and software should not (mis)use it.
+ The trust obviously comes fully from the pilot.
+ Having the possibility of fully separating the actual users gives a much better traceability than only separating the payload account from the pilot account since any misuse can be traced to individual users.


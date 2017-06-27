How to setup the Apache2 auth_openidc module

See also: https://github.com/pingidentity/mod_auth_openidc

# Prerequisites

* Vagrant (https://www.vagrantup.com/downloads.html)
* Virtualbox (https://www.virtualbox.org/wiki/Downloads)

# Setup

From the git repo dir (oidc-primer):

```
cd oidc-apache2-rp
vagrant up
```

To complete the exercises, get a terminal on the vagrant machine 
(Linux Debian Jessie):

```
cd oidc-apache2-rp
vagrant ssh
```

then become root:

```
sudo su -
```

# Exercises Instructions

For every exercise you have to:
* Edit the file `/etc/apache2/sites-enabled/oidc-rp.conf-EDIT_ME`
* Link the file to `oidc-rp.conf` (JUST ONCE):
 ```
 ln -s /etc/apache2/sites-enabled/oidc-rp.conf-EDIT_ME /etc/apache2/sites-enabled/oidc-rp.conf
 ```
* restart the apache2 service:
 ```
 service apache2 restart
 ```
* follow what's going on on the apache2 error.log:
 ```
 tail -f /var/log/apache2/error.log
 ```
 
## Enable a dynamically registered Relying Party

Edit the file `/etc/apache2/sites-enabled/oidc-rp.conf-EDIT_ME`: follow the
instructions under the `##TODO: Dynamic Registration` comment.

READ AGAIN `Exercises Instructions`

Open a browser on your host:
- go to http://localhost:8090
- press the `Test authentication` button
- when asked for your OIDC Provider insert `https://mitreid.org`
- authenticate
- authorize the client on the OIDC Provider
- if everything works you'll land on the `RP Auth Success` page

## Enable an already registered Relying Party

Edit the file `/etc/apache2/sites-enabled/oidc-rp.conf-EDIT_ME`: follow the
instructions under the `##TODO: Already Registered` comment.

READ AGAIN `Exercises Instructions`

Link the file to `oidc-rp.conf` (IF NOT ALREDY LINKED):

```
ln -s /etc/apache2/sites-enabled/oidc-rp.conf-EDIT_ME /etc/apache2/sites-enabled/oidc-rp.conf
```

Open a browser on your host:
- go to http://localhost:8090
- follow the `Test authentication` link
- authenticate
- authorize the client on the OIDC Provider
- if everything works you'll land on the `RP Auth Success` page

# MCollective x509 Security Plugin #

This security plugin provides authentication using keys and
certificates issued by an X509 CA. The callerid used in authorisation
and audit is derived from the sender's certificate distinguished name.

Encryption of the message payload is not provided.

# Installation #

For MCollective 1.2.x, install mco-1.2.x/security/x509.rb in your
local plugins directory, typically /etc/mcollective/site_plugins. 

For MCollective 2.x, you can still install in site_plugins, but it's
also possible to create a native package from this repository using
"mco plugin package". From the root of this repository, run:

    mcollective-security-x509$ mco plugin package mco-2.x
    Created RPM and SRPM packages for mcollective-x509-security

which should produce mcollective-x509-security-1.0-1.{noarch,src}.rpm.  

# Configuration #

For the server:

    securityprovider = x509

    plugin.x509_serializer = yaml
    plugin.x509_cacert = /etc/mcollective/server_cacert.pem
    plugin.x509_server_key = /etc/mcollective/server_key.pem
    plugin.x509_server_cert = /etc/mcollective/server_cert.pem

For the client:

    securityprovider = x509

    plugin.x509_serializer = yaml
    plugin.x509_cacert = /etc/mcollective/client_cacert.pem
    plugin.x509_client_key = /etc/mcollective/client_key.pem
    plugin.x509_client_cert = /etc/mcollective/client_cert.pem

# Certificate Management #

This plugin typically requires a server and client key and certificate
for each host, plus client certificates for management clients. If
you're running Chef, you might want to consider using the "x509"
cookbook, which automates deployment of a set of keys and
certificates:

    http://community.opscode.com/cookbooks/x509

# Licence and copyright #

Copyright 2012 Venda Ltd, All Rights Reserved.

Licensed under the Apache License, Version 2.0 (the "License"); you
may not use this file except in compliance with the License.  You may
obtain a copy of the License at

  http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
implied.  See the License for the specific language governing
permissions and limitations under the License.

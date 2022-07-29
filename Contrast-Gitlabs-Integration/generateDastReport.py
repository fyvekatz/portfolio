# Header stuff and other non-glorious bookkeeping

import json         # JSON handling
import requests     # Web request handling
import os           # Access to environment variables
import re           # Regular expressions

from datetime import datetime
from datetime import timedelta

# Expected environment variables
CONTRAST_AUTHORIZATION_HEADER   = os.environ.get('CONTRAST_AUTHORIZATION_HEADER')
CONTRAST_API_KEY                = os.environ.get('CONTRAST_API_KEY')
CONTRAST_WEBSITE_URL            = os.environ.get('CONTRAST_WEBSITE_URL')

CONTRAST_SERVER_NAME            = os.environ.get('CONTRAST_SERVER_NAME')
CONTRAST_ORG_ID                 = os.environ.get('CONTRAST_ORG_ID')
CONTRAST_APP_ID                 = os.environ.get('CONTRAST_APP_ID')
CONTRAST_DEBUG                  = os.environ.get('CONTRAST_DEBUG', "0")


# For the time being, embed CWE -> WASC mapping directly in this script.
#
# Referenced:
# - http://projects.webappsec.org/w/page/13246974/Threat%20Classification%20Reference%20Grid
CWEID_TO_WASCID = {

    '20':             {
                "wascid":         '20',
                "name":           "Improper Input Validation",
                "risk":           "INFO",
                "confidence":     "LOW",
                "description":    "",
                "solution":       "",
                "reference":      "",
                "cveUrl":         "http://cwe.mitre.org/data/definitions/20.html",
                "wascUrl":        "http://projects.webappsec.org/w/page/13246933/Improper%20Input%20Handling"
    },

    '22':             {
                "wascid":         '33',
                "name":           "Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal')",
                "risk":           "INFO",
                "confidence":     "LOW",
                "description":    "The software uses external input to construct a pathname that is intended to identify a file or directory that is located underneath a restricted parent directory, but the software does not properly neutralize special elements within the pathname that can cause the pathname to resolve to a location that is outside of the restricted directory.",
                "solution":       "",
                "reference":      "",
                "cveUrl":         "http://cwe.mitre.org/data/definitions/22.html",
                "wascUrl":        "http://projects.webappsec.org/w/page/13246952/Path%20Traversal"
    },

    '78':             {
                "wascid":         '31',
                "name":           "Improper Neutralization of Special Elements used in an OS Command ('OS Command Injection')",
                "risk":           "HIGH",
                "confidence":     "HIGH",
                "description":    "The software constructs all or part of an OS command using externally-influenced input from an upstream component, but it does not neutralize or incorrectly neutralizes special elements that could modify the intended OS command when it is sent to a downstream component.",
                "solution":       "",
                "reference":      "",
                "cveUrl":         "http://cwe.mitre.org/data/definitions/78.html",
                "wascUrl":        "http://projects.webappsec.org/w/page/13246950/OS%20Commanding"
    },

    '79':             {
                "wascid":         '8',
                "name":           "Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')",
                "risk":           "HIGH",
                "confidence":     "HIGH",
                "description":    "The software does not neutralize or incorrectly neutralizes user-controllable input before it is placed in output that is used as a web page that is served to other users.",
                "solution":       "",
                "reference":      "http://cwe.mitre.org/data/definitions/79.html",
                "cveUrl":         "http://cwe.mitre.org/data/definitions/99.html",
                "wascUrl":        "http://projects.webappsec.org/w/page/13246920/Cross%20Site%20Scripting"
    },

    '89':             {
                "wascid":         '19',
                "name":           "SQL Injection",
                "risk":           "HIGH",
                "confidence":     "HIGH",
                "description":    "SQL Injection is an attack technique used to exploit applications that construct SQL statements from user-supplied input. When successful, the attacker is able to change the logic of SQL statements executed against the database.",
                "solution":       "",
                "reference":      "http://cwe.mitre.org/data/definitions/89.html",
                "cveUrl":         "http://cwe.mitre.org/data/definitions/89.html",
                "wascUrl":        "http://projects.webappsec.org/w/page/13246963/SQL%20Injection"
    },

    '93':             {
                "wascid":         '24',
                "name":           "Improper Neutralization of CRLF Sequences ('CRLF Injection')",
                "risk":           "MEDIUM",
                "confidence":     "MEDIUM",
                "description":    "The software uses CRLF (carriage return line feeds) as a special element, e.g. to separate lines or records, but it does not neutralize or incorrectly neutralizes CRLF sequences from inputs.",
                "solution":       "",
                "reference":      "http://cwe.mitre.org/data/definitions/93.html",
                "cveUrl":         "http://cwe.mitre.org/data/definitions/93.html",
                "wascUrl":        "http://projects.webappsec.org/w/page/13246929/HTTP%20Request%20Splitting"
    },

    '200':             {
                "wascid":         '13',
                "name":           "Exposure of Sensitive Information to an Unauthorized Actor",
                "risk":           "LOW",
                "confidence":     "MEDIUM",
                "description":    "The product exposes sensitive information to an actor that is not explicitly authorized to have access to that information.",
                "solution":       "",
                "reference":      "",
                "cveUrl":         "http://cwe.mitre.org/data/definitions/200.html",
                "wascUrl":        "http://projects.webappsec.org/w/page/13246936/Information%20Leakage"
    },

    '209':             {
                "wascid":         '13',
                "name":           "Application Error Disclosure via WebSockets (script)",
                "risk":           "MEDIUM",
                "confidence":     "MEDIUM",
                "description":    "This payload contains an error/warning message that\
 may disclose sensitive information like the location of the file\
 that produced the unhandled exception. This information can be used\
 to launch further attacks against the web application.",
                "solution":       "Review the error payloads which are piped directly to WebSockets.\
 Handle the related exceptions.\
 Consider implementing a mechanism to provide a unique\
 error reference/identifier to the client (browser) while logging the\
 details on the server side and not exposing them to the user.",
                "reference":      "",
                "cveUrl":         "http://cwe.mitre.org/data/definitions/209.html",
                "wascUrl":        "http://projects.webappsec.org/w/page/13246936/Information%20Leakage"
    },

    '235':             {
                "wascid":         '20',
                "name":           "Improper Handling of Extra Parameters",
                "risk":           "LOW",
                "confidence":     "MEDIUM",
                "description":    "The software does not handle or incorrectly handles when the number of parameters, fields, or arguments with the same name exceeds the expected amount.",
                "solution":       "",
                "reference":      "",
                "cveUrl":         "http://cwe.mitre.org/data/definitions/235.html",
                "wascUrl":        "http://projects.webappsec.org/w/page/13246933/Improper%20Input%20Handling"
    },

    '284':             {
                "wascid":         '2',
                "name":           "Username Hash Found in WebSocket message (script)",
                "risk":           "INFO",
                "confidence":     "HIGH",
                "description":    "",
                "solution":       "Use per user or session indirect object references (create a temporary mapping at time of use). Or, ensure that each use of a direct object reference is tied to an authorization check to ensure the user is authorized for the requested object.",
                "reference":      "https://www.owasp.org/index.php/Top_10_2013-A4-Insecure_Direct_Object_References\nhttps://www.owasp.org/index.php/Testing_for_Insecure_Direct_Object_References_(OTG-AUTHZ-004)",
                "cveUrl":         "http://cwe.mitre.org/data/definitions/284.html",
                "wascUrl":        ""
    },

    '0':             {
                "wascid":         '0',
                "name":           "Name of the alert",
                "risk":           "INFO",
                "confidence":     "INFO",
                "description":    "Description of the Alert.",
                "solution":       "Solution of the Alert.",
                "reference":      "Reference of the Alert.",
                "cveUrl":         "",
                "wascUrl":        ""
    },

    '319':             {
                "wascid":         '0',
                "name":           "Cleartext Transmission of Sensitive Information",
                "risk":           "MEDIUM",
                "confidence":     "MEDIUM",
                "description":    "The software transmits sensitive or security-critical data in cleartext in a communication channel that can be sniffed by unauthorized actors.",
                "solution":       "",
                "reference":      "",
                "cveUrl":         "http://cwe.mitre.org/data/definitions/319.html",
                "wascUrl":        ""
    },

    '328':             {
                "wascid":         '0',
                "name":           "Reversible One-Way Hash",
                "risk":           "MEDIUM",
                "confidence":     "MEDIUM",
                "description":    "The response contains Personally Identifiable Information, such as CC number. Credit Card type detected: ",
                "solution":       "",
                "reference":      "",
                "cveUrl":         "http://cwe.mitre.org/data/definitions/328.html",
                "wascUrl":        ""
    },

    '359':             {
                "wascid":         '13',
                "name":           "Personally Identifiable Information via WebSocket (script)",
                "risk":           "HIGH",
                "confidence":     "HIGH",
                "description":    "The response contains Personally Identifiable Information, such as CC number. Credit Card type detected: ",
                "solution":       "",
                "reference":      "",
                "cveUrl":         "http://cwe.mitre.org/data/definitions/359.html",
                "wascUrl":        "http://projects.webappsec.org/w/page/13246936/Information%20Leakage"
    },

    '525':             {
                "wascid":         '13',
                "name":           "Incomplete or No Cache-control and Pragma HTTP Header Set",
                "risk":           "INFO",
                "confidence":     "MEDIUM",
                "description":    "The cache-control and pragma HTTP header have not been set properly or are missing allowing the browser and proxies to cache content.",
                "solution":       "Whenever possible ensure the cache-control HTTP header is set with no-cache, no-store, must-revalidate; and that the pragma HTTP header is set with no-cache.",
                "reference":      "https://www.owasp.org/index.php/Session_Management_Cheat_Sheet#Web_Content_Caching",
                "cveUrl":         "http://cwe.mitre.org/data/definitions/525.html",
                "wascUrl":        "http://projects.webappsec.org/w/page/13246936/Information%20Leakage"
    },

    '601':             {
                "wascid":         '38',
                "name":           "URL Redirection to Untrusted Site ('Open Redirect')",
                "risk":           "MEDIUM",
                "confidence":     "MEDIUM",
                "description":    "A web application accepts a user-controlled input that specifies a link to an external site, and uses that link in a Redirect. This simplifies phishing attacks.",
                "solution":       "",
                "reference":      "",
                "cveUrl":         "http://cwe.mitre.org/data/definitions/601.html",
                "wascUrl":        "http://projects.webappsec.org/w/page/13246981/URL%20Redirector%20Abuse"
    },

    '602':             {
                "wascid":         '0',
                "name":           "Client-Side Enforcement of Server-Side Security",
                "risk":           "MEDIUM",
                "confidence":     "MEDIUM",
                "description":    "The software is composed of a server that relies on the client to implement a mechanism that is intended to protect the server.",
                "solution":       "",
                "reference":      "",
                "cveUrl":         "http://cwe.mitre.org/data/definitions/602.html",
                "wascUrl":        ""
    },

    '611':             {
                "wascid":         '43',
                "name":           "Improper Restriction of XML External Entity Reference",
                "risk":           "MEDIUM",
                "confidence":     "MEDIUM",
                "description":    "The software processes an XML document that can contain XML entities with URIs that resolve to documents outside of the intended sphere of control, causing the product to embed incorrect documents into its output.",
                "solution":       "",
                "reference":      "",
                "cveUrl":         "http://cwe.mitre.org/data/definitions/611.html",
                "wascUrl":        "http://projects.webappsec.org/w/page/13247003/XML%20External%20Entities"
    },

    '259':             {
                "wascid":         '15',
                "name":           "Application Misconfiguration",
                "risk":           "HIGH",
                "confidence":     "HIGH",
                "description":    "The use of a hard-coded password increases the possibility of password guessing tremendously.",
                "solution":       "Remove hard-coded passwords.",
                "reference":      "https://owasp.org/www-community/vulnerabilities/Use_of_hard-coded_password",
                "cveUrl":         "http://cwe.mitre.org/data/definitions/259.html",
                "wascUrl":        "http://projects.webappsec.org/w/page/13246914/Application%20Misconfiguration"
    },

    '219':             {
                # TODO
                "wascid":         '13',
                "name":           "Storage of File with Sensitive Data Under Web Root",
                "risk":           "MEDIUM",
                "confidence":     "MEDIUM",
                "description":    "The application stores sensitive data under the web document root with insufficient access control, which might make it accessible to untrusted parties.",
                "solution":       "",
                "reference":      "http://cwe.mitre.org/data/definitions/219.html",
                "cveUrl":         "http://cwe.mitre.org/data/definitions/219.html",
                "wascUrl":        "http://projects.webappsec.org/w/page/13246936/Information%20Leakage"
    },

    '613':             {
                "wascid":         '47',
                "name":           "Insufficient Session Expiration",
                "risk":           "MEDIUM",
                "confidence":     "MEDIUM",
                "description":    "According to WASC, \"Insufficient Session Expiration is when a web site permits an attacker to reuse old session credentials or session IDs for authorization.\"",
                "solution":       "",
                "reference":      "http://cwe.mitre.org/data/definitions/613.html",
                "cveUrl":         "http://cwe.mitre.org/data/definitions/613.html",
                "wascUrl":        "http://projects.webappsec.org/Insufficient-Session-Expiration"
    },

    '693':             {
                "wascid":         '40',
                "name":           "Protection Mechanism Failure",
                "risk":           "MEDIUM",
                "confidence":     "MEDIUM",
                "description":    "The product does not use or incorrectly uses a protection mechanism that provides sufficient defense against directed attacks against the product.",
                "solution":       "",
                "reference":      "http://cwe.mitre.org/data/definitions/693.html",
                "cveUrl":         "http://cwe.mitre.org/data/definitions/693.html",
                "wascUrl":        "http://projects.webappsec.org/Insufficient-Process-Validation"
    },

    '384':             {
                "wascid":         '37',
                "name":           "Session Fixation",
                "risk":           "MEDIUM",
                "confidence":     "MEDIUM",
                "description":    "Authenticating a user, or otherwise establishing a new user session, without invalidating any existing session identifier gives an attacker the opportunity to steal authenticated sessions.",
                "solution":       "",
                "reference":      "http://cwe.mitre.org/data/definitions/384.html",
                "cveUrl":         "http://cwe.mitre.org/data/definitions/384.html",
                "wascUrl":        "http://projects.webappsec.org/Session-Fixation"
    },

    '614':             {
                "wascid":         '4',
                "name":           "Insufficient Transport Layer Protection",
                "risk":           "MEDIUM",
                "confidence":     "MEDIUM",
                "description":    "The Secure attribute for sensitive cookies in HTTPS sessions is not set, which could cause the user agent to send those cookies in plaintext over an HTTP session.",
                "solution":       "",
                "reference":      "http://cwe.mitre.org/data/definitions/614.html",
                "cveUrl":         "http://cwe.mitre.org/data/definitions/614.html",
                "wascUrl":        "http://projects.webappsec.org/Insufficient-Transport-Layer-Protection"
    }
}


# Other Constants
SCANNER_INFORMATION = {
    "id":       "contrast_security",
    "name":     "Contrast Security",
    "url":      "https://www.contrastsecurity.com",
    "version":  "unversioned",
    "vendor": {
        "name": "Contrast Security"
    }
}

# CURL Headers
HEADERS = {
    'Authorization':    CONTRAST_AUTHORIZATION_HEADER,
    'API-Key':          CONTRAST_API_KEY,
    'Accept':           'application/json',
}

CURRENT_TIME        = datetime.now()
END_TIME            = CURRENT_TIME
START_TIME          = CURRENT_TIME - timedelta(minutes=30000)
# END: Rest API Prep

routeCoverageResponse = requests.get('https://' + CONTRAST_SERVER_NAME + '/Contrast/api/ng/' + CONTRAST_ORG_ID + '/applications/' + CONTRAST_APP_ID + '/route?expand=observations',
                                     # + "?START_TIME=" + str(int(datetime.timestamp(START_TIME))) + "&"
                                        #"END_TIME=" + str(int(datetime.timestamp(CURRENT_TIME))),
                                    headers=HEADERS)

if(CONTRAST_DEBUG == "1"):
    print ("Route Coverage\n")
    print (str(routeCoverageResponse.json()))
    print ("\n\n")

vulnerabilitiesResponse = requests.get('https://' + CONTRAST_SERVER_NAME + '/Contrast/api/ng/' + CONTRAST_ORG_ID + '/traces/' + CONTRAST_APP_ID + '/filter',
                                     headers=HEADERS)

if(CONTRAST_DEBUG == "1"):
    print ("Vulnerabilities\n")
    print (str(vulnerabilitiesResponse.json()))
    print ("\n\n")

rulesResponse = requests.get('https://' + CONTRAST_SERVER_NAME + '/Contrast/api/ng/' + CONTRAST_ORG_ID + '/rules?expand=references,customization,skip_links&sort=title',
                                     headers=HEADERS)

rulesHash = {}

for rule in rulesResponse.json()['rules']:
    rule['cweUrl']              = rule['cwe']
    rule['cwe']                 = re.findall(r'/(\d+).html$', rule['cwe'])[0]

    rulesHash[rule['title']]    = rule

if(CONTRAST_DEBUG == "1"):
    #print ("Rules Response\n")
    #print (str(rulesResponse.json()))
    print ("\n\n")
    print ("Rules List\n")

    print("{")
    for key in rulesHash.keys():
        print ("'" + key + "':\t" + str(rulesHash[key]) + "\n")
    print("}")
    #print (rulesHash)
    print ("\n\n")


# site->alerts
#
# I've not yet found a way to query vulns by page/route. For the time being, I'm using
# /Contrast/api/ng/<orgID>/traces/<appID>/trace/<UUID>/routes'. Doesn't list vulns for
# SAST-style vulns so we'll need to find a better solution. Also means that
# root->site->alerts will have different information than root->vulnerabilities

# <UUID> -> [ <site1>, <site2>, <site3>]
observationsByVuln = {}

for vuln in vulnerabilitiesResponse.json()['traces']:

    uuid = vuln['uuid']

    routesByVulnResponse = requests.get('https://' + CONTRAST_SERVER_NAME + '/Contrast/api/ng/' + CONTRAST_ORG_ID + '/traces/' + CONTRAST_APP_ID + '/trace/' + vuln['uuid'] +'/routes',
                                     headers=HEADERS)

    if(CONTRAST_DEBUG == "1"):
        print("Routes By Vuln:\t" + vuln['uuid'] + "\n")
        print(routesByVulnResponse.json())
        print("\n\n")

    for route in routesByVulnResponse.json()['routes']:

        for observation in route['observations']:

            if uuid in observationsByVuln.keys():
                observationsByVuln[uuid].append(observation)
            else:
                observationsByVuln[uuid] = [observation]

if(CONTRAST_DEBUG == "1"):
    print("Observations By Vuln\n")

    for vulnUuid in observationsByVuln.keys():
        print("Vuln:\t" + vulnUuid + "\n")
        print(observationsByVuln[vulnUuid])
        print("\n\n")

# Now actually create the alerts json
alertsList = []
for vuln in vulnerabilitiesResponse.json()['traces']:

    alert                       = {}
    cweid_to_wascid             = CWEID_TO_WASCID[rulesHash[vuln['rule_title']]['cwe']]

    instances                   = []
    vulnConfidence              = "Info" if vuln['confidence_label'] == "Note" else vuln['confidence_label']
    vulnSeverity                = "Info" if vuln['severity_label'] == "Note" else vuln['severity_label']

    sanitizedTitle              = str(vuln['rule_title']).replace("''", "`").replace("'", "`")

    alert['alert']              = sanitizedTitle
    alert['confidence']         = str(1 if vulnConfidence == "Low" else 2 if vulnConfidence == "Medium" else 3)
    alert['count']              = str(vuln['total_traces_received'])
    alert['cweid']              = rulesHash[vuln['rule_title']]['cwe']
    alert['desc']               = str(vuln['title']).replace("'", "`").replace("\"", "`") + "\n\n" + str(vuln['evidence'])

    if vuln['uuid'] in observationsByVuln.keys():
        for observation in observationsByVuln[vuln['uuid']]:

            instance = {
                'attack':       '',
                'evidence':     '',
                'method':       observation['verb'],
                'param':        '',
                'url':          CONTRAST_WEBSITE_URL + observation['url']
            }

            instances.append(instance)


    alert['instances']          = instances
    alert['name']               = sanitizedTitle
    alert['otherinfo']          = 'TODO otherinfo'
    alert['pluginid']           = vuln['uuid']
    alert['reference']          = 'https://' + CONTRAST_SERVER_NAME + '/Contrast/static/ng/index.html#' + CONTRAST_ORG_ID + '/applications/' + CONTRAST_APP_ID + '/vulns/' + vuln['uuid']

    alert['riskcode']           = str(3 if vulnSeverity == "High" else 2 if vulnSeverity == "Medium" else 1 if vulnSeverity == "Low" else 0)

    alert['riskdesc']           = vulnSeverity
    alert['solution']           = cweid_to_wascid ['solution']

    # TODO: sourceid
    alert['sourceid']           = '0'
    alert['wascid']             = cweid_to_wascid ['wascid']

    alertsList.append(alert)


# SCANNED RESOURCE
scannedResources = []

for route in routeCoverageResponse.json()['routes']:
    for observation in route['observations']:

        item = {}
        item['method']  = observation['verb']
        item['type']    = 'url'
        item['url']     = observation['url']

        scannedResources.append(item)


# SITE
# [scheme://]host[:port]

urlTokens   = re.split("://", CONTRAST_WEBSITE_URL)
hostTokens  = re.split(":", urlTokens[-1])

site          = {}
site['@host'] = hostTokens[0]
site['@name'] = CONTRAST_WEBSITE_URL

# host:port
if len(hostTokens) == 2:
    site['@port'] = hostTokens[1]

# host
elif len(urlTokens) == 1:
    site['@port'] = ''

# https://host
elif urlTokens[0] == "https":
    site['@port'] = '443'

# http://host
else:
    site['@port'] = '80'

if ((len(hostTokens) == 2 and hostTokens[1] == 443) or
    (len(urlTokens) == 2 and urlTokens[0] == "https")):
    site['@ssl'] = "true"
else:
    site['@ssl'] = "false"

site['alerts'] = alertsList


# Create urlsInScope JSON

urlsInScope = []

urlsInScope.append({
    "method":                       "GET",
    "processed":                    "true",
    "resourceNotProcessed":         "",
    "statusCode":                   "200",
    "statusReason":                 "OK",
    "url":                          CONTRAST_WEBSITE_URL
})

for scannedResource in scannedResources:

    urlItem = {
        "method":                       scannedResource['method'],
        "processed":                    "true",
        "resourceNotProcessed":         "",
        "statusCode":                   "200",
        "statusReason":                 "OK",
        "url":                          scannedResource['url']
    }

    urlsInScope.append(urlItem)

# END: Create urlsInScope JSON


# Create vulnerabilites JSON

vulnerabilitiesList = []

for vuln in vulnerabilitiesResponse.json()['traces']:

        rule                                       = rulesHash[vuln['rule_title']]
        cweid_to_wasidEntry                        = CWEID_TO_WASCID[rule['cwe']]

        vulnerabilityJson = {}

        vulnerabilityJson['category']              = "dast"
        vulnerabilityJson['confidence']            = "Info" if vuln['confidence_label'] == "Note" else vuln['confidence_label']
        vulnerabilityJson['cve']                   = "TODO cve"
        vulnerabilityJson['description']           = str(vuln['title']).replace("'", "`").replace("\"", "`") + "\n\n" + str(vuln['evidence'])
        vulnerabilityJson['discovered_at']         = datetime.fromtimestamp(vuln['discovered']/1000).strftime("%Y-%m-%-dT%-H:%M:%S")

        # Out "evidence" usually isn't present and when it is, it doesn't map to theres.
        # Investigate this at another time
        vulnerabilityJson['evidence']              = {}
        vulnerabilityJson['id']                    = vuln['uuid']

        sanitizedTitle                             = str(vuln['rule_title']).replace("''", "`").replace("'", "`")

        vulnerabilityJson['identifiers']           = [
            {
                "name":             sanitizedTitle ,
                "type":             "Contrast Security UUID",
                "url":              'https://' + CONTRAST_SERVER_NAME + '/Contrast/static/ng/index.html#' + CONTRAST_ORG_ID + '/applications/' + CONTRAST_APP_ID + '/vulns/' + vuln['uuid'],
                "value":            vuln['uuid']
            },
            {
                "name":             "CWE-" + rule['cwe'],
                "type":             "CWE",
                "url":              rule['cweUrl'],
                "value":            rule['cwe']
            },
            {
                "name":             "WASC-" + cweid_to_wasidEntry['wascid'],
                "type":             "WASC",
                "url":              cweid_to_wasidEntry['wascUrl'],
                "value":            cweid_to_wasidEntry['wascid']
            }
        ]

        vulnerabilityJson['links']                  = [ {

                "url": 'https://' + CONTRAST_SERVER_NAME + '/Contrast/static/ng/index.html#' + CONTRAST_ORG_ID + '/applications/' + CONTRAST_APP_ID + '/vulns/' + vuln['uuid']
                }
            ]

        if vuln['uuid'] in observationsByVuln.keys():
            # A product of pidgeon-holing IAST results into a DAST report. There's usually a 1-to-1
            # mapping between vulnerabilities and routes in DAST world. Not the case with SAST;
            # however, DAST "location" results are not a list. Workaround is to just show the first
            # route here since there should be at least 1 by definition.
            vulnerabilityJson['location']              = {

                "hostname":         CONTRAST_WEBSITE_URL,
                "method":           observationsByVuln[vuln['uuid']][0]['verb'],
                "param":            "",
                "path":             observationsByVuln[vuln['uuid']][0]['url']
            }
        else:
            vulnerabilityJson['location']               = {}

        vulnerabilityJson['message']                    = sanitizedTitle
        vulnerabilityJson['scanner']                    = {
                "id":               SCANNER_INFORMATION['id'],
                "name":             SCANNER_INFORMATION['name']
        }

        vulnerabilityJson['severity']                   = "Info" if vuln['severity_label'] == "Note" else vuln['severity_label']
        vulnerabilityJson['solution']                   = ''

        vulnerabilitiesList.append(vulnerabilityJson)


# END: Create vulnerabilites JSON

jsonOutput = {
    "@generated": CURRENT_TIME.strftime("%a, %-d %b %Y %-H:%M:%S"),
#    "@version": "D-2020-06-30",
    "@version": SCANNER_INFORMATION['version'],
    "remediations": [],
    "scan": {
        # Continuous scan. Doesn't apply. Too difficult (?) to figure out last vuln found for a given tag.
        # Use datetime.now()
        "end_time":             CURRENT_TIME.strftime("%Y-%m-%-dT%-H:%M:%S"),
        "messages":             vulnerabilitiesResponse.json()['messages'],
        "scanned_resources":    scannedResources
    },
    "scanner":          SCANNER_INFORMATION,
    "start_time":       CURRENT_TIME.strftime("%Y-%m-%-dT%-H:%M:%S"),

    # IAST does continuous analysis rather than successive scans so status is always "success"
    "status":           "success",

    # Gitlab Security Dashboard does not yet support IAST specifically.
    "type":             "dast",
    "site":             [ site ],

    "spider": {

        # We continuously scan. Always 100%
        "progress":     "100",

        "result": {

        #   "urlsInScope": [
        #     {
        #       "method": "GET",
        #       "processed": "true",
        #       "reasonNotProcessed": "",
        #       "statusCode": "302",
        #       "statusReason": "Found",
        #       "url": "https://webgoat-net.azurewebsites.net/"
        #     },
        #
        #   Until we can get a reliable list of all URLS, the goal here is just to list the following:
        #
        #   1. Root URL
        #   2. Each URL from "scannedResources" (i.e., a URL for each route observation that was detected)
        #
        #   Hardcode success status since we'll have not detected the route unless if completed successfully.

            "urlsInScope":          urlsInScope,
            "urlsIoError":          [],
            "urlsOutOfScope":       []
        },
        "state":                    "FINISHED"
    },
    "version":                      SCANNER_INFORMATION['version'],
    "vulnerabilities":              vulnerabilitiesList
}

jsonOutputStr = str(jsonOutput).replace("'", "\"")

if(CONTRAST_DEBUG == "1"):
    print ('Final Output:\n')
    print (jsonOutputStr)

f = open("gl-dast-report.json", "w")
f.write(jsonOutputStr)
f.close()

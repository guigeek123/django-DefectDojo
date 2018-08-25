from __future__ import with_statement

import json

from dojo.models import Finding

__author__ = "Guigeek"


class ClairJSONParser(object):
    def __init__(self, json_output, test):
        self.target = None
        self.port = "80"
        self.host = None

        tree = self.parse_json(json_output)
        if tree:
            self.items = self.get_items(tree, test)
            #self.items = [data for data in self.get_items(tree, test)]
        else:
            self.items = []

    def parse_json(self, json_output):
        try:
            tree = json.load(json_output)
        except:
            raise Exception("Invalid format")

        return tree

    def get_items(self, tree, test):

        items = {}

        if "Features" in tree['Layer']:

            # - Get list of components
            features = tree['Layer']['Features']

            for node in features:
                # - For each components find vulnerabilities if any
                if "Vulnerabilities" in node:
                    item = get_item(node, test)
                    items[item.title] = item

        return items.values()

def get_item(item_node, test):
    severitys= ["Unknown","Negligible","Low", "Medium", "High", "Critical", "Defcon1"]
    vuln_data = []

    # - List vulnerabilites in a dict in order to order them later
    for v in item_node['Vulnerabilities']:
        vd = dict (
            namespace_name = v['NamespaceName'],
            cve_severity = v['Severity'],
            cve_name = v['Name'],
            cve_link = v['Link'],
        )
        if 'FixedBy' in v:
            vd['cve_fixed_version'] = v['FixedBy']
        else:
            vd['cve_fixed_version'] = "N/A"
        if 'Description' in v:
            vd['cve_desc'] = v['Description']
        else:
            vd['cve_desc'] = "N/A"

        for i in range(0, len(severitys)):
            if severitys[i] == vd['cve_severity']:
                vd['cve_severity_nr'] = i

        #Rename severities to be compliant with defectDojo
        tempseverity = vd['cve_severity']

        if tempseverity == "Unknown":
            tempseverity = "Low"

        if tempseverity == "Negligible":
            tempseverity = "Info"

        #TODO : check what really means Defcon1 from Clair
        if tempseverity == "Defcon1":
            tempseverity = "Critical"

        vd['cve_severity'] = tempseverity

        vuln_data.append(vd)

    # Order vulns by criticity (more critical in first)
    vuln_data.sort(key=lambda vuln: vuln['cve_severity_nr'], reverse=True)

    # Set the finding criticity to the level of the most critical vuln
    severity = vuln_data[0]['cve_severity']

    # Describe all vuln for the given components
    remediation =""
    references = ""
    background = ""
    cwe=""

    for vuln in vuln_data:
        #TODO : Design a tab for better reading ?
        background += "Namespace : " + vuln['namespace_name'] + "\n"
        background += "CVE : " + vuln['cve_name'] + "\n"
        background += "Severity : " + vuln['cve_severity'] + "\n"
        background += "Link : " + vuln['cve_link'] + "\n"
        background += "Fixed By : " + vuln['cve_fixed_version'] + "\n"
        background += "Description : " + vuln['cve_desc'] + "\n"
        background += "\n\n"

        #No meanings to set one CVE only : this is a group of CVE for the given component
        cwe=None


    finding = Finding(title=item_node['Name'] + " (Version :" + item_node['Version'] + ")",
                      url="N/A",
                      test=test,
                      severity=severity,
                      description=background + "\n\n",
                      mitigation=remediation,
                      references=references,
                      active=False,
                      verified=False,
                      false_p=False,
                      duplicate=False,
                      out_of_scope=False,
                      mitigated=None,
                      impact="No impact provided",
                      numerical_severity=Finding.get_numerical_severity(severity),
                      cwe=cwe)
    #finding.unsaved_endpoints = endpoints
    #finding.unsaved_req_resp = unsaved_req_resp
    #finding.unsaved_tags = tags


    return finding
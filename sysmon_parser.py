import json
import xmltodict
import sys
import hashlib


with open(sys.argv[1]) as xml_file:
    print(f"Opening {sys.argv[1]}")
    data_dict = xmltodict.parse(xml_file.read())
    print(f"Read in {sys.argv[1]}")

export_dict = {}


# Iterate through the rule groups to get to each event type
for rulegroup in data_dict["Sysmon"]["EventFiltering"]["RuleGroup"]:
    # While there should be only one event type per rule group for exclusions you must iterate regardless
    for event_type in rulegroup:
        # Take reach rule parame
        for rule_parameters in rulegroup:
            element_type = {}
            # Do not pull multi-part exceptions
            if rule_parameters != "@groupRelation":
                if "Rule" in rulegroup[rule_parameters]:
                    for element in rulegroup[rule_parameters]:
                        # iterate through the non multi-part rules
                        if (
                            type(rulegroup[rule_parameters][element]) == list
                            and element != "Rule"
                        ):
                            rule_list = []
                            for individual_rule in rulegroup[rule_parameters][element]:
                                if (
                                    type(individual_rule) == dict
                                    and individual_rule["@condition"] == "image"
                                ):
                                    individual_rule["@condition"] = "is"
                                # Uncomment if your version of Elasticsearch is greater than or equal to 8.11 as this version introduces wildcarding on file.path.text and multimatching
                                # Please understand this is currently untested but please make changes as necessary
                                # https://www.elastic.co/guide/en/security/current/event-filters.html
                                """   
                                if type(individual_rule) == dict and individual_rule["@condition"] == "contains all":
                                    individual_rule["#text"] = individual_rule["#text"].replace(";","*")
                                if type(individual_rule) == dict and individual_rule["@condition"] == "begin with":
                                    if individual_rule["#text"][-1] == "*":
                                        pass
                                    else: individual_rule["#text"] += "*"
                                if type(individual_rule) == dict and (individual_rule["@condition"] == "contains" or individual_rule["@condition"] == "end with"):
                                    if individual_rule["#text"][0] == "*" and individual_rule["#text"][-1] == "*":
                                        pass
                                    else:
                                        individual_rule["#text"] = "*"+individual_rule["#text"]+"*"
                                """
                                # this sha256 hash will be the name of the exclusion in elastic
                                if (
                                    type(individual_rule) == dict
                                    and individual_rule["@condition"] == "is"
                                ):
                                    rule_list.append(
                                        {
                                            hashlib.sha256(
                                                bytes(
                                                    str(
                                                        rule_parameters
                                                        + str(individual_rule)
                                                    ).encode()
                                                )
                                            ).hexdigest(): individual_rule
                                        }
                                    )
                                    element_type.update({element: rule_list})
                export_dict.update({rule_parameters: element_type})

print(f"Removing non-compliant event types")
for event_type in export_dict.copy():
    # remove any event_types that do not contain any excluions
    if len(export_dict[event_type]) == 0:
        del export_dict[event_type]
    # remove any event types that do not have analogs to elastic datasets
    if (
        event_type == "PipeEvent"
        or event_type == "ProcessAccess"
        or event_type == "ProcessTampering"
        or event_type == "CreateRemoteThread"
    ):
        del export_dict[event_type]

print("Forming ndjson filters")
# Form the json objects that will be passed to elastic as event filters
filter_list = []
for event_type in export_dict:
    print(event_type)
    for conditional_field in export_dict[event_type]:
        print(conditional_field)
        for rule in export_dict[event_type][conditional_field]:
            #print(rule)
            for rule_name in rule:
                # start making associations betweeen sysmon event_types and Elastic dataset names and fields
                if conditional_field == "Image":
                    TARGETFIELD = "process.executable.caseless"
                elif conditional_field == "ParentImage":
                    TARGETFIELD = "process.parent.executable.caseless"
                elif conditional_field == "CommandLine":
                    TARGETFIELD = "process.command_line.caseless"
                elif conditional_field == "ParentCommandLine":
                    TARGETFIELD = "process.parent.command_line.caseless"
                elif conditional_field == "QueryName":
                    TARGETFIELD = "dns.question.name"
                elif conditional_field == "TargetObject":
                    TARGETFIELD = "registry.path"

                if event_type == "ProcessCreate":
                    DATASET = "endpoint.events.process"
                elif event_type == "NetworkConnect":
                    DATASET = "endpoint.events.network"
                elif event_type == "FileCreate":
                    DATASET = "endpoint.events.file"
                elif event_type == "RegistryEvent":
                    DATASET = "endpoint.events.registry"
                elif event_type == "DnsQuery":
                    DATASET = "endpoint.events.network"

                PATTERN = rule[rule_name]["#text"]
                NAME = rule_name
                #fill the json object with the collected and matched data
                print(
                    {
                        "comments": [],
                        "entries": [
                            {
                                "field": TARGETFIELD,
                                "operator": "included",
                                "type": "match",
                                "value": PATTERN,
                            },
                            {
                                "field": "event.dataset",
                                "operator": "included",
                                "type": "match",
                                "value": DATASET,
                            },
                        ],
                        "list_id": "endpoint_event_filters",
                        "name": NAME + " " + DATASET,
                        "description": f"Automated Filtering of {PATTERN} for dataset {DATASET}",
                        "namespace_type": "agnostic",
                        "tags": ["policy:all"],
                        "type": "simple",
                        "os_types": ["windows"],
                    }
                )
                filter_list.append(
                    {
                        "comments": [],
                        "entries": [
                            {
                                "field": TARGETFIELD,
                                "operator": "included",
                                "type": "match",
                                "value": PATTERN,
                            },
                            {
                                "field": "event.dataset",
                                "operator": "included",
                                "type": "match",
                                "value": DATASET,
                            },
                        ],
                        "list_id": "endpoint_event_filters",
                        "name": NAME + " " + DATASET,
                        "description": f"Automated Filtering of {PATTERN} for dataset {DATASET}",
                        "namespace_type": "agnostic",
                        "tags": ["policy:all"],
                        "type": "simple",
                        "os_types": ["windows"],
                    }
                )
# Because event filters need to be passed as ndjson, we will write a string variable filled with our mached and process event filters
write_string = ""
for i in filter_list:
    write_string += f"{json.dumps(i)}\n"

open("event_filter.ndjson", "w").write(write_string)
print("Export complete")

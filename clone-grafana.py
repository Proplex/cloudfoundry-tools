#!/usr/bin/env python3

# Specific foundations to copy can be specified as arguments (i.e. ./grafanaNewClone.py us-east-prod)

# AUTHOR: David Lohle (david.lohle@broadcom.com).
# You can set this script's verbosity by setting "GRAFANA_CLONE_LOG_LEVEL" to "DEBUG"
# I'm sorry you're reading this. Feel free to shoot me an email if something went wrong
# But, please watch this first: https://www.youtube.com/watch?v=GtRuQqqVLZE (if you email me, this will be the two of us)

import urllib.parse
import json, urllib.request as request, subprocess, logging, os, base64, sys, urllib
log = logging.getLogger("grafana-clone-tool")

## START CONFIGURATION, EDIT THIS AS NEEDED AS TIME GOES ON

grafanaApiKeysPathInVault = "platform/main/grafana-admin-api-keys"
pcfTicketingApiAuthPathInVault = "platform/main/pcf-ticketing-api-pcf-basic-auth"

grafanaDashboardsToCopy = [
    "Platform Certs", 
    "Platform Monitor",
    "Application CPU Entitlement",
    "Key Capacity Scaling Indicators",
    "App Logging Rate Limits",
    "Low App Instances",
    "Unresponsive Agents"
]

sourceGrafanaInstallation = {
    "name": "us-east-preprod",
    "url": "https://grafana.use.cf.company.com",
    "token": None
}

listOfGrafanaInstallations = [
    {
        "name": "us-east-sandbox",
        "url": "https://grafana.use.cf.company.com",
        "token": None,
        "category": "sandbox"
    },
    {
        "name": "us-east-prod",
        "url": "https://grafana.use.cf.company.com",
        "token": None,
        "category": "prod"
    },
]


## END CONFIGURATION. THIS SCRIPT IS PERFECT, WHY DO YOU NEED TO KEEP SCROLLING???

def main(specificFoundationsToCopy=[]):
    logging.basicConfig(level=os.environ.get("GRAFANA_CLONE_LOG_LEVEL", "INFO"),
                        format='%(asctime)s [%(levelname)-8s] %(message)s')
    log.info("Grafana clone tool running")
    
    log.info("Grabbing the tokens to all Grafana installations.")
    getGrafanaTokens()

    foundationCopyList = []

    if specificFoundationsToCopy:
        log.info(f"Only copying specific foundations: {specificFoundationsToCopy}")
        for foundation in specificFoundationsToCopy:
            foundationCopyList.append(getFoundationInfo(foundation))
    else:
        foundationCopyList = listOfGrafanaInstallations


    # The order of copying data over is important, as certain objects require previous objects.
    for targetGrafanaInstall in foundationCopyList:
        log.info(f"Copying folders from {sourceGrafanaInstallation['name']} to {targetGrafanaInstall['name']}")
        cloneFolders(sourceGrafanaInstallation, targetGrafanaInstall)
        log.info(f"Copying alert rules from {sourceGrafanaInstallation['name']} to {targetGrafanaInstall['name']}")
        cloneAlerts(sourceGrafanaInstallation, targetGrafanaInstall)
        log.info(f"Copying contact points from {sourceGrafanaInstallation['name']} to {targetGrafanaInstall['name']}")
        cloneContactPoints(sourceGrafanaInstallation, targetGrafanaInstall)
        log.info(f"Copying mute timings from {sourceGrafanaInstallation['name']} to {targetGrafanaInstall['name']}")
        cloneMuteTimings(sourceGrafanaInstallation, targetGrafanaInstall)
        log.info(f"Copying notification policies from {sourceGrafanaInstallation['name']} to {targetGrafanaInstall['name']}")
        cloneNotificationPolicies(sourceGrafanaInstallation, targetGrafanaInstall)
        log.info(f"Copying specified dashboards from {sourceGrafanaInstallation['name']} to {targetGrafanaInstall['name']}")
        cloneDashboards(sourceGrafanaInstallation, targetGrafanaInstall, grafanaDashboardsToCopy)


def getFoundationInfo(foundationName):
    for configFoundation in listOfGrafanaInstallations:
        if configFoundation['name'] == foundationName:
            return configFoundation
    else:
        log.fatal(f"No destination foundation known as: {foundationName}")
        sys.exit(1)

# A method to either GET or DELETE from a Grafana endpoint
def getGrafana(grafanaConfig: dict, path: str, method="GET", silence=False) -> dict:
    url = f"{grafanaConfig['url']}/{path}"
    log.debug(f"HTTP {method.upper()}: {url}")
    preparedRequest = request.Request(url, headers={"Authorization": f"Bearer {grafanaConfig['token']}"}, method=method)
    try:
        with request.urlopen(preparedRequest) as response:
            data = response.read().decode('utf-8')
            log.debug(f"\nRESPONSE: {data}")
            return json.loads(data)
    except json.JSONDecodeError as err:
        if method == "DELETE":
            return
        if not silence:
            log.debug(f"Got JSON parsing error while reaching Grafana {err}: {err.read().decode()}")
    except Exception as err:
        if not silence:
            log.fatal(f"Error while reaching Grafana: {err}")
            sys.exit(1)



# A method to either POST or PUT to a Grafana endpoint
def postGrafana(grafanaConfig: dict, path: str, data: dict, method="POST"):
    url = f"{grafanaConfig['url']}/{path}"
    dataAsJson = json.dumps(data).encode("utf-8")
    postHeaders = {
        "Authorization": f"Bearer {grafanaConfig['token']}",
        "Content-Type": "application/json; charset=utf-8",
        "Content-Length": len(dataAsJson),
        "X-Disable-Provenance": "True"
    }
    log.debug(f"HTTP {method.upper()}: {url}\n CONTENT: {dataAsJson}")
    prepared_request = request.Request(url, data=dataAsJson, headers=postHeaders, method=method)

    try:
        with request.urlopen(prepared_request) as response:
            data = response.read().decode('utf-8')
            return
    except Exception as err:
        log.fatal(f"Error while reaching Grafana: {err}: {err.read().decode()}")
        sys.exit(1)


def cloneFolders(sourceGrafanaConfig: dict, destinationGrafanaConfig: dict):
    sourceFolders = getGrafana(sourceGrafanaConfig, "api/folders")
    destFolders = getGrafana(destinationGrafanaConfig, "api/folders")

    for sourceFolder in sourceFolders:
        folderFound = False
        log.debug(f"Checking if {sourceFolder['title']} is a dest folders")
        for destFolder in destFolders:
            if destFolder['title'] == sourceFolder['title']:
                log.debug(f"{sourceGrafanaConfig['name']} and {destinationGrafanaConfig['name']} Grafanas have similar folders ({destFolder['title']}), don't need to create")
                folderFound = True
                break
        if folderFound:
            continue
        log.debug(f"Destination Grafana does not have folder: {sourceFolder['title']}, creating a new one")
        postGrafana(destinationGrafanaConfig, f"api/folders", sourceFolder)



def cloneDashboards(sourceGrafanaConfig: dict, destinationGrafanaConfig: dict, dashboardsToClone: list):
    for dashboard in dashboardsToClone:
        log.debug(f"Cloning {dashboard} from {sourceGrafanaConfig['name']} to {destinationGrafanaConfig['name']}")
        
        sourceDashboardUid = dashboardNameToUid(sourceGrafanaConfig, dashboard)
        destinationDashboardUid = dashboardNameToUid(destinationGrafanaConfig, dashboard)

        #dashboardNameToUid can return None when no dashboard is available (rather than erroring), need to validate that first.
        if sourceDashboardUid is None:
            log.fatal(f"Couldn't find a dashboard named {dashboard} in {sourceGrafanaConfig['name']}")
            sys.exit(1)
        
        # Get dasboard JSON
        sourceDashboardAsJson = getGrafana(sourceGrafanaConfig, f"api/dashboards/uid/{sourceDashboardUid}")

        # QUICKFIX: Handle dashboard renaming
        try:
            potentiallyRenamedDB = getGrafana(destinationGrafanaConfig, f"api/dashboards/uid/{sourceDashboardUid}", silence=True)
            if potentiallyRenamedDB['dashboard']['uid']:
                log.debug(f"Found a renamed dashboard: {potentiallyRenamedDB['dashboard']['title']} -> {sourceDashboardAsJson['dashboard']['title']} Remapping.")
                destinationDashboardUid = potentiallyRenamedDB['dashboard']['uid']
        except:
            pass

        # We need to check if the destination Grafana already has a dashboard by this name. If it does, let's
        # keep the UID the same, to make things easier for everyone (except me)
        if destinationDashboardUid is not None:
            log.debug("Updating dashboard in place")
            destDashboardAsJson = getGrafana(destinationGrafanaConfig, f"api/dashboards/uid/{destinationDashboardUid}")
            modifiedDb = harmonizeGrafanaDashboard(sourceGrafanaConfig, destinationGrafanaConfig, sourceDashboardAsJson, destDashboardAsJson=destDashboardAsJson)
            postGrafana(destinationGrafanaConfig, "api/dashboards/db", modifiedDb)
        else:
            log.debug("Creating new dashboard")
            modifiedDb = harmonizeGrafanaDashboard(sourceGrafanaConfig, destinationGrafanaConfig, sourceDashboardAsJson)
            postGrafana(destinationGrafanaConfig, "api/dashboards/db", modifiedDb)
            


# This function takes two dashboards and homologates them into an acceptable dashboard JSON that the destination Grafana will accept
def harmonizeGrafanaDashboard(sourceGrafanaConfig, destinationGrafanaConfig, sourceDashboardAsJson: dict, destDashboardAsJson={}) -> dict:
    # This was done on the Friday before engagement ending; sorry it's ugly. It's to update the BASE_FQDN variable from incoming dashboards
    try:
        for pos, grafanaVariable in enumerate(sourceDashboardAsJson['dashboard']['templating']['list']):
            if grafanaVariable['name'] == "BASE_FQDN":
                sourceDashboardAsJson['dashboard']['templating']['list'][pos]['query'] = ".".join(destinationGrafanaConfig['url'].split('.')[1:])
    except:
        pass
    if destDashboardAsJson: # Existing dashboard
        sourceDashboardAsJson['dashboard']['uid'] = destDashboardAsJson['dashboard']['uid']
        sourceDashboardAsJson['dashboard']['id'] = destDashboardAsJson['dashboard']['id']
        sourceDashboardAsJson['dashboard']['version'] = (destDashboardAsJson['dashboard']['version'] + 1)
        sourceDashboardAsJson['folderUid'] = folderNameToUid(destinationGrafanaConfig, sourceDashboardAsJson['meta']['folderTitle'])
        sourceDashboardAsJson['meta'] = destDashboardAsJson['meta']
        sourceDashboardAsJson['meta']['version'] = (sourceDashboardAsJson['meta']['version'] + 1)
        sourceDashboardAsJson['overwrite'] = True
        return sourceDashboardAsJson
    else:
        sourceDashboardAsJson['dashboard']['version'] = 0
        sourceDashboardAsJson['dashboard']['id'] = None
        sourceDashboardAsJson['folderUid'] = folderNameToUid(destinationGrafanaConfig, sourceDashboardAsJson['meta']['folderTitle'])
        sourceDashboardAsJson['meta'] = {}
        sourceDashboardAsJson['meta']['version'] = 0
        return sourceDashboardAsJson


def folderNameToUid(grafanaConfig: dict, folderName: str) -> str | None:
    folders = getGrafana(grafanaConfig, "api/folders")
    for folder in folders:
        if folder['title'] == folderName:
            return folder['uid']
    return None


def dashboardNameToUid(grafanaConfig: dict, dashboardName: str) -> str | None:
    # Currently, we only get the first result if multiple dashboards have the same name. Not sure how to make this better.
    dashboards = getGrafana(grafanaConfig, f"api/search?query={urllib.parse.quote(dashboardName)}")
    if len(dashboards) == 0:
        log.debug(f"Couldn't find a dashboard named {dashboardName} in {grafanaConfig['name']}")
        return None
    return dashboards[0]['uid']

def cloneAlerts(sourceGrafanaConfig: dict, destinationGrafanaConfig: dict):
    # Get the alert rules in the destination Grafana and delete existing rules
    destinationAlertRulesJson = getGrafana(destinationGrafanaConfig, "api/v1/provisioning/alert-rules")
    for rule in destinationAlertRulesJson:
        getGrafana(destinationGrafanaConfig, f"api/v1/provisioning/alert-rules/{rule['uid']}", method="DELETE")

    # Get alert rules from source Grafana
    sourceAlertRulesJson = getGrafana(sourceGrafanaConfig, "api/v1/provisioning/alert-rules")

    # We need the destination folder UID for the General Alerting folder (company specific) in order to place alert rules there
    # There is an outstanding bug in Grafana (as of 5/2/24) that will create invisible rules if the proper folder uid isn't specified
    # This logic of grabbing the folder UID and using it is required to get around that bug.
    gaFolderUid = folderNameToUid(destinationGrafanaConfig, "General Alerting")

    # Loop through each rule, edit foundation-specific information, and create them on destination Grafana
    for rule in sourceAlertRulesJson:
        editedRule = harmonizeGrafanaAlert(sourceGrafanaConfig, destinationGrafanaConfig, rule, gaFolderUid)
        postGrafana(destinationGrafanaConfig, "api/v1/provisioning/alert-rules", editedRule)



# This function takes a Grafana alert from one foundation and modifies it to match the destination Grafana's information
def harmonizeGrafanaAlert(sourceGrafanaConfig: dict, destinationGrafanaConfig: dict, rule: dict, gaFolderUid: str) -> dict:
    try:
        # Clear out any dashboard-links; it's too difficult to handle at the moment.
        alertMessage = rule['annotations']['message']
        rule['annotations'] = {}

        # Modify the alert message to match foundation-specific info
        rule['annotations']['message'] = alertMessage.replace(sourceGrafanaConfig['name'], f"{destinationGrafanaConfig['name']}")
        rule['annotations']['message'] = rule['annotations']['message'].replace(sourceGrafanaConfig['url'], f"{destinationGrafanaConfig['url']}")
        
        # Set alert rule to be stored within "General Alerting" folder
        rule['folderUID'] = gaFolderUid 
        return rule
    except KeyError as err:
        log.fatal(f"There was an issue harmonizing '{rule['title']}': Is the alert message set properly? Error: {err}")
        sys.exit(1)



def cloneContactPoints(sourceGrafanaConfig: dict, destinationGrafanaConfig: dict):
    # Get dest and source Grafana contact points
    destinationGrafanaCPList = getGrafana(destinationGrafanaConfig, "api/v1/provisioning/contact-points")
    sourceGrafanaCPList = getGrafana(sourceGrafanaConfig, "api/v1/provisioning/contact-points")

    # Grab webhook password from Vault. It's a base64 encoded 'user:pass' (single quotes included), we need just the pass.
    pcfTicketingAccountBase64 = getFromVault(pcfTicketingApiAuthPathInVault, "value")
    pcfTicketingPassword = str(base64.b64decode(pcfTicketingAccountBase64)).split(":")[1].replace("'", "")

    # Grafana does not allow for deleting contact points that are in use, so instead we need to iterate over the existing
    # contact points and check if they match incoming ones. If so, update the incoming UIDs to match the existing ones,
    # and modify in place rather than create. We also have to insert the password to the webhook auth, as Grafana doesn't
    # export that info for security reasons.
    for sourceContactPoint in sourceGrafanaCPList:
        contactPointFound = False
        log.debug(f"Checking if {sourceContactPoint['name']} is in dest data")
        for destContactPoint in destinationGrafanaCPList:
            log.debug(f"Checking if {destContactPoint['name']} is in source data")
            if destContactPoint['name'] == sourceContactPoint['name']:
                log.debug(f"{sourceGrafanaConfig['name']} and {destinationGrafanaConfig['name']} Grafanas have similar contact points ({destContactPoint['name']}), mapping UIDs to match what destination Grafana expects.")
                sourceContactPoint['uid'] = destContactPoint['uid']
                sourceContactPoint['settings']['password'] = pcfTicketingPassword
                postGrafana(destinationGrafanaConfig, f"api/v1/provisioning/contact-points/{destContactPoint['uid']}", sourceContactPoint, method="PUT")
                contactPointFound = True
                break
        if contactPointFound:
            continue
        log.debug(f"Destination Grafana does not have contact point: {sourceContactPoint['name']}, creating a new one")
        postGrafana(destinationGrafanaConfig, f"api/v1/provisioning/contact-points", sourceContactPoint)


def cloneNotificationPolicies(sourceGrafanaConfig: dict, destinationGrafanaConfig: dict):
    # Get notification policies from source Grafana
    sourceGrafanaNotifPolicyList = getGrafana(sourceGrafanaConfig, "api/v1/provisioning/policies")
    log.debug("Sending notification policies")
    postGrafana(destinationGrafanaConfig, "api/v1/provisioning/policies", sourceGrafanaNotifPolicyList, method="PUT")


def cloneMuteTimings(sourceGrafanaConfig: dict, destinationGrafanaConfig: dict):
    # Get dest and source mute timings from source Grafana
    sourceGrafanaMuteTimingsList = getGrafana(sourceGrafanaConfig, "api/v1/provisioning/mute-timings")
    destinationGrafanaMuteTimingsList = getGrafana(destinationGrafanaConfig, "api/v1/provisioning/mute-timings")

    # We have to use different methods (POST vs. PUT) to either create a new mute timing or update one in place
    # we need the below logic to figure out what the dest Grafana already has, and PUT an updated config, or,
    # if there's no mute timing with the same name, POST the configuration.
    # Grafana, PUT should be allowed to create a new config when one doesn't exist...
    for sourceMuteTiming in sourceGrafanaMuteTimingsList:
        muteTimingFound = False
        log.debug(f"Checking if {sourceMuteTiming['name']} is in dest data")
        for destMuteTiming in destinationGrafanaMuteTimingsList:
            log.debug(f"Checking if {destMuteTiming['name']} is in source data")
            if destMuteTiming['name'] == sourceMuteTiming['name']:
                log.debug(f"{sourceGrafanaConfig['name']} and {destinationGrafanaConfig['name']} Grafanas have similar mute timings ({destMuteTiming['name']}), updating in-place")
                postGrafana(destinationGrafanaConfig, f"api/v1/provisioning/mute-timings/{destMuteTiming['name']}", sourceMuteTiming, method="PUT")
                muteTimingFound = True
                break
        if muteTimingFound:
            continue
        log.debug(f"Destination Grafana does not have mute timing: {sourceMuteTiming['name']}, creating a new one")
        postGrafana(destinationGrafanaConfig, f"api/v1/provisioning/mute-timings", sourceMuteTiming)

    


def getFromVault(path: str, field: str):
    # Assemble vault command
    vaultCommand = ["vault", "read", f"-field={field}", path]
    log.debug(f"Running vault command: \"{' '.join(vaultCommand)}\"")

    # Execute the vault command and do some error handling
    try:
        process = subprocess.Popen(vaultCommand, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        commandOutput, commandError = process.communicate()
        if commandError:
            log.fatal(f"Something happened with executing Vault commands. {commandError}")
            sys.exit(1)
        return commandOutput.decode() # Set token into the source data structure
    except Exception as err:
        log.fatal(f"Error while trying to run Vault commands, error: {err}")
        sys.exit(1)
    
def getGrafanaTokens():
    # Get source Grafana token (default is EDC1-PreProd)
    log.debug(f"Grabbing token for {sourceGrafanaInstallation['name']}")
    sourceGrafanaInstallation['token'] = getFromVault(grafanaApiKeysPathInVault, sourceGrafanaInstallation['name'])

    # Get destination Grafana tokens
    for grafanaInstall in listOfGrafanaInstallations:
        log.debug(f"Grabbing token for {grafanaInstall['name']}")
        grafanaInstall['token']= getFromVault(grafanaApiKeysPathInVault, grafanaInstall['name'])


# Don't mess with this
if __name__ == "__main__":
    try:
        foundations = sys.argv[1:]
        main(foundations)
    except Exception as err:
        log.fatal("Unhandled error while trying to run clone script.")
        raise
	

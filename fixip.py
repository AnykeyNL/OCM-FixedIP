import requests
import oci
import sys
import argparse
import os
import ipaddress

configfile = "~/.oci/config"  # Linux
configProfile = "DEFAULT"

def create_signer(config_profile, is_instance_principals, is_delegation_token):

    # if instance principals authentications
    if is_instance_principals:
        try:
            signer = oci.auth.signers.InstancePrincipalsSecurityTokenSigner()
            config = {'region': signer.region, 'tenancy': signer.tenancy_id}
            return config, signer

        except Exception:
            print("Error obtaining instance principals certificate, aborting")
            sys.exit(-1)

    # -----------------------------
    # Delegation Token
    # -----------------------------
    elif is_delegation_token:

        print ("Using delegation token - should only run in cloud shell")
        try:
            # check if env variables OCI_CONFIG_FILE, OCI_CONFIG_PROFILE exist and use them
            env_config_file = os.environ.get('OCI_CONFIG_FILE')
            env_config_section = os.environ.get('OCI_CONFIG_PROFILE')

            # check if file exist
            if env_config_file is None or env_config_section is None:
                print("*** OCI_CONFIG_FILE and OCI_CONFIG_PROFILE env variables not found, abort. ***")
                print("")
                sys.exit(-1)

            config = oci.config.from_file(env_config_file, env_config_section)
            delegation_token_location = config["delegation_token_file"]

            with open(delegation_token_location, 'r') as delegation_token_file:
                delegation_token = delegation_token_file.read().strip()
                # get signer from delegation token
                signer = oci.auth.signers.InstancePrincipalsDelegationTokenSigner(delegation_token=delegation_token)

                return config, signer

        except KeyError:
            print("* Key Error obtaining delegation_token_file")
            sys.exit(-1)

        except Exception:
            raise

    # -----------------------------
    # config file authentication
    # -----------------------------
    else:
        try:
            config = oci.config.from_file(
                oci.config.DEFAULT_LOCATION,
                (config_profile if config_profile else oci.config.DEFAULT_PROFILE)
            )
            signer = oci.signer.Signer(
                tenancy=config["tenancy"],
                user=config["user"],
                fingerprint=config["fingerprint"],
                private_key_file_location=config.get("key_file"),
                pass_phrase=oci.config.get_config_value_or_default(config, "pass_phrase"),
                private_key_content=config.get("key_content")
            )
        except:
            print("Error obtaining authentication, did you configure config file? aborting")
            sys.exit(-1)

        return config, signer


def input_command_line(help=False):
    parser = argparse.ArgumentParser(formatter_class=lambda prog: argparse.HelpFormatter(prog, max_help_position=80, width=130))
    parser.add_argument('-cp', default="", dest='config_profile', help='Config Profile inside the config file')
    parser.add_argument('-ip', action='store_true', default=False, dest='is_instance_principals', help='Use Instance Principals for Authentication')
    parser.add_argument('-dt', action='store_true', default=False, dest='is_delegation_token', help='Use Delegation Token for Authentication')
    parser.add_argument("-rg", default="", dest='region', help="Region")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("-target_id", default="", dest='targetOCID', help="Target Asset OCID")
    group.add_argument("-migration_id", default="", dest='migrationPlanOCID', help="Migration Plan OCID")
    parser.add_argument("-fixip", action='store_true', default=False, dest='fixip', help="Set static IP to existing Static IP")
    cmd = parser.parse_args()
    if help:
        parser.print_help()

    return cmd

def clearLine():
    print("\033[A                                                                                                            \033[A")

def getTarget(region, targetID, signer):
    migrations = oci.cloud_migrations.MigrationClient(config, signer=signer)
    data = migrations.get_target_asset(target_asset_id=targetID).data
    return data

def processTarget(region, targetID, cmd, signer):
    print(f"Getting {cmd.targetOCID}")
    migrations = oci.cloud_migrations.MigrationClient(config, signer=signer)
    network = oci.core.VirtualNetworkClient(config, signer=signer)
    target = migrations.get_target_asset(target_asset_id=targetID).data
    if target:
        migration_asset = target.migration_asset
        source_asset = migration_asset.source_asset_data
        computeNics = source_asset['compute']['nics']
        clearLine()
        print(f"VM: {source_asset['displayName']}")
        try:
            targetSubnetOCID = target.user_spec.create_vnic_details.subnet_id
        except:
            targetSubnetOCID = target.recommended_spec.create_vnic_details.subnet_id
        if not targetSubnetOCID:
            targetSubnetOCID = target.recommended_spec.create_vnic_details.subnet_id

        subnetDetails = network.get_subnet(subnet_id=targetSubnetOCID).data
        print (f" - Target OCI Subnet: {subnetDetails.display_name} [{subnetDetails.cidr_block}]")
        foundMatch = False
        IPs = ""
        for nic in computeNics:
            if len(nic['ipAddresses']) > 0:
                IPs = IPs + nic['ipAddresses'][0] + " "
                if ipaddress.ip_address(nic['ipAddresses'][0]) in ipaddress.ip_network(subnetDetails.cidr_block):
                    print(" - Possible source IP map: {} - {}".format(nic['networkName'], nic['ipAddresses'][0]))
                    MappedIP = nic['ipAddresses'][0]
                    foundMatch = True
                    break
        if not foundMatch:
            print (" - No possible IP match found to target subnet: " + IPs)

        #print (target)
        if cmd.fixip:
            if foundMatch:
                migration_asset = target.migration_asset
                user_spec = oci.cloud_migrations.models.launch_instance_details.LaunchInstanceDetails()
                user_spec = target.user_spec
                source_asset = migration_asset.source_asset_data
                if source_asset['assetType'] == "VMWARE_VM":
                    vnic_details = oci.cloud_migrations.models.CreateVnicDetails()
                    vnic_details.private_ip = MappedIP
                    user_spec.create_vnic_details = vnic_details
                    print(f" - Setting fix ip to {MappedIP}")
                    migrations = oci.cloud_migrations.MigrationClient(config, signer=signer)
                    update_details = oci.cloud_migrations.models.UpdateTargetAssetDetails()
                    target_details = oci.cloud_migrations.models.UpdateVmTargetAssetDetails()
                    target_details.type = "INSTANCE"
                    target_details.user_spec = user_spec
                    result = migrations.update_target_asset(target_asset_id=targetID,update_target_asset_details=target_details)
                else:
                    print(" - sorry script only accepts VMware VMs as source")
            else:
                print (f" - Not matchable subnet found, not setting a fixed IP")


cmd = input_command_line()
configProfile = cmd.config_profile if cmd.config_profile else configProfile
config, signer = create_signer(cmd.config_profile, cmd.is_instance_principals, cmd.is_delegation_token)
if cmd.region:
    config["region"] = cmd.region

identity = oci.identity.IdentityClient(config, signer=signer)
tenancy = identity.get_tenancy(config['tenancy']).data
print ("OCM Migration Plan / Target Asset fixed IP tool")
print ("Tenancy: {}".format(tenancy.name))

if cmd.targetOCID:
    processTarget(config["region"], cmd.targetOCID, cmd, signer)
elif cmd.migrationPlanOCID:
    migrations = oci.cloud_migrations.MigrationClient(config, signer=signer)
    targets = migrations.list_target_assets(migration_plan_id=cmd.migrationPlanOCID).data.items
    for target in targets:
        processTarget(config["region"], target.id, cmd, signer)

else:
    print ("Please specify target OCID or Migration Plan OCID")

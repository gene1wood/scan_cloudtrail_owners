#!/usr/bin/env python

# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

import sys
import json
import boto.ec2
import boto.iam
import boto.cloudtrail
import boto.ec2.autoscale
import zlib
import logging
import socket
import argparse
from datetime import datetime, timedelta

def type_loglevel(level):
    try:
        result = getattr(logging, level.upper())
    except AttributeError:
        raise argparse.ArgumentTypeError("'%s' is not a valid log level. Please use %s" %
                                         (level, 
                                          [x for x in logging._levelNames.keys() 
                                           if isinstance(x, str)]))
    return result

def get_owner_from_instance_event(cloudtrail, instance_id):
    # Other interesting values
    # event['eventTime']
    # event['userIdentity']['invokedBy']
    owner=next((
        event['userIdentity']['userName'] for event in cloudtrail
        if event['eventName'] == 'RunInstances'
        and not event['responseElements'] is None
        and instance_id in [item['instanceId'] 
                            for item 
                            in event['responseElements']['instancesSet']['items']]), None)
    # What if the instance_id isn't in the cloudtrail
    # TODO return None if the instance_id isn't found
    return owner

def get_owner_from_asg_creation_event(cloudtrail, asg_name):
    owner=next((
        event['userIdentity']['userName'] for event in cloudtrail
        if event['eventName'] == 'CreateAutoScalingGroup'
        and not event['responseElements'] is None
        and event['requestParameters']['autoScalingGroupName'] == asg_name), None)
    return owner

def main():
    parser = argparse.ArgumentParser(description=
                                     'Scan CloudTrail for instances and '
                                     'autoscale Groups without Owner tags')
    parser.add_argument('--dryrun', action='store_true')
    parser.add_argument('-l', '--loglevel', type=type_loglevel,
                        default='INFO', help='Log level verbosity')
    args = parser.parse_args()
    
    loglevel=logging.INFO
    logging.basicConfig(level=loglevel)

    all_regions = [x.name for x in 
                   boto.ec2.connect_to_region('us-east-1').get_all_regions()]

    tagname="Owner"

    conn_s3 = boto.connect_s3()
    conn_iam = boto.iam.connect_to_region('universal')

    IS_EC2 = False
    try:
        if socket.gethostbyname('instance-data.ec2.internal'):
            IS_EC2 = True
    except socket.gaierror:
        pass

    if IS_EC2:
        # We are on an ec2 instance using an IAM Role
        account_id = boto.utils.get_instance_metadata()['iam']['info']['InstanceProfileArn'].split(':')[4]
    else:
        # We're not running on an ec2 instance
        account_id = conn_iam.get_user()['get_user_response']['get_user_result']['user']['arn'].split(':')[4]

        yesterday = datetime.now() - timedelta(days=1)

    for region in all_regions:
        conn_cloudtrail = boto.cloudtrail.connect_to_region(region)
        # Supported regions
        # http://docs.aws.amazon.com/awscloudtrail/latest/userguide/what_is_cloud_trail_supported_regions.html
    
        if conn_cloudtrail is None:
            logging.info("Skipping region %s"
                          % region)
            continue
        trails = boto.cloudtrail.connect_to_region(region).describe_trails()['trailList']
        if len(trails) == 0:
            logging.info("Skipping region %s as it has no CloudTrails configured" 
                          % region)
            continue
        elif len(trails) > 1:
            # We shouldn't have over one CloudTrail but the API allows for it
            raise("Region %s is unexpectedly configured with more than one CloudTrail"
                   % region)
    
        bucket = conn_s3.get_bucket(trails[0]['S3BucketName'], validate=False)
        search_prefix = "%s/AWSLogs/%s/CloudTrail/%s/%d/%02d/%02d/" % (
                         trails[0]['S3KeyPrefix'], 
                         account_id, 
                         region,
                         yesterday.year,
                         yesterday.month,
                         yesterday.day)
        logs = bucket.list(prefix=search_prefix)
        cloudtrail = []
        logging.info("Fetching logs for region %s" % region)
        for log in logs:
            logging.debug("Fetching log %s" % log.name)
            sys.stdout.write('.')
            sys.stdout.flush()
            compressed_json = log.get_contents_as_string()
            json_string = zlib.decompress(compressed_json, zlib.MAX_WBITS | 16)
            cloudtrail.extend(json.loads(json_string)['Records'])
    
        print ""
    
        conn_ec2 = boto.ec2.connect_to_region(region)
        conn_autoscale = boto.ec2.autoscale.connect_to_region(region)
        
        all_instances = conn_ec2.get_only_instances()
        
        logging.info("Searching for new instances in %s missing the %s tag" % (region, tagname))
        for instance in all_instances:
            if not tagname in instance.tags:
                tagvalue = get_owner_from_instance_event(cloudtrail, instance.id)
                if tagvalue:
                    logging.info("Instance %s in region %s, owned by %s is missing an %s tag" 
                                 % (instance.id, region, owner, tagname))
                    if not args.dryrun:
                        instances[0].add_tag(tagname, owner)
                        logging.info("Instance %s in region %s is now tagged with %s %s" 
                                     % (instance.id, region, tagname, owner))
                else:
                    logging.debug("Instance %s in region %s, is missing an %s tag "
                                  "however the instance doesn't appear in the cloudtrail"
                                  % (instance.id, region, tagname))
           
        logging.info("Searching for new Autoscale Groups in %s which don't propagate the "
                     "%s tag to their instances" % (region, tagname))
    
        all_asgs = conn_autoscale.get_all_groups()
        for asg in all_asgs:
            if not tagname in [x.key for x in asg.tags if x.propagate_at_launch]:
                owner = get_owner_from_asg_creation_event(cloudtrail, asg.name)
                if owner is None:
                    logging.debug("AutoScale Group %s in region %s does not apply an %s "
                                  "tag to its instances however the AutoScale Group "
                                  "does not appear in the cloudtrail" 
                                   % (asg.name, 
                                      region, 
                                      tagname))
                else:
                    logging.info("AutoScale Group %s in region %s, owned by %s does not "
                                   "apply an %s tag to its instances" 
                                   % (asg.name, 
                                      region, 
                                      owner,
                                      tagname))
if __name__ == '__main__':
    main()

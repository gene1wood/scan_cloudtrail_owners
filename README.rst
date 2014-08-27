**********************
Scan CloudTrail Owners
**********************

`scan_cloudtrail_owners` fetches CloudTrail logs for each region in which CloudTrail is enabled, 
parses the logs and identifies any instances created without an "Owner" tag as well as any
autoscale groups created which don't propagate to its instances an "Owner" tag. `scan_cloudtrail_owners`
tags the instances and reports on the autoscale groups (as ASGs can't be changed once created).

Time Period
***********

Currently the tool scans yesterday's CloudTrail logs. To scan broader sets of logs will require a bit more
code to iterate over each days S3 Bucket folder.

Options
*******

* `--dryrun` : This reports instances and autoscale groups missing the Owner tag but doesn't fix instances
* `--loglevel` : This allows changing the output verbocity

AWS Permissions
***************

These are the permissions needed to run this tool
* ec2:DescribeInstances
* iam:GetUser
* s3:GetObject
* s3:ListBucket
* cloudtrail:DescribeTrails
* ec2:DescribeRegions

It also requires that no S3 Bucket policy on the CloudTrail log bucket prevent it from being able to read the contents.

Example IAM Policy
------------------

::

    {
      "Version": "2012-10-17",
      "Statement": [
        {
          "Action": [
            "ec2:DescribeInstances",
            "iam:GetUser",
            "s3:GetObject",
            "s3:ListBucket",
            "cloudtrail:DescribeTrails",
            "ec2:DescribeRegions"
          ],
          "Effect": "Allow",
          "Resource": "*"
        }
      ]
    }

How to Build
============

::

    sudo yum install http://ftp.linux.ncsu.edu/pub/epel/6/i386/epel-release-6-8.noarch.rpm
    sudo yum install rubygems ruby-devel gcc python-setuptools rpm-build
    sudo easy_install pip
    sudo gem install fpm
    git clone https://github.com/mozilla/identity-ops.git
    
    cd identity-ops/aws-tools/scan_cloudtrail_owners # This is required
    fpm -s python -t rpm --workdir ../ ./setup.py

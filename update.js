const os = require('os');
const program = require('commander');
const colors = require('colors');
const AWS = require('aws-sdk');
const async = require('async');
const fs = require('fs');
const http = require('http');

const osHomeDir = os.homedir();

program
  .option('-r, --region [region]', 'AWS region', 'us-east-1')
  .option('-p, --profile [profile]', 'AWS credentials profile', 'default')
  .option('-s, --securityGroup [securityGroup]', 'Security group', '')
  .option('--protocol [protocol]', 'IP protocol', 'tcp')
  .option('--fromPort [fromPort]', 'The start of port range', '22')
  .option('--toPort [toPort]', 'The start of port range', '22')
  .option(
    '-d, --description [description]',
    'Description for security group rule',
    `osHostname_protocol_fromPort_toPort`,
  )
  .option('-f, --force', 'Force update')
  .parse(process.argv);

if (program.securityGroup === '') {
  console.error('Please specify security group to update!'.red);
  process.exit(1);
}

let ruleDescription = program.description;
if (ruleDescription === 'osHostname_protocol_fromPort_toPort') {
  ruleDescription = `${os.hostname()}_${program.protocol}_${program.fromPort}_${program.toPort}`;
}

const awsCredentials = new AWS.SharedIniFileCredentials({ profile: program.profile });

AWS.config.update({
  region: program.region,
  credentials: awsCredentials,
});

const ec2 = new AWS.EC2({ apiVersion: '2016-11-15' });

let previousIp;
let currentIp;

async.series(
  [
    done => {
      http
        .get('http://api.ipify.org', res => {
          const { statusCode } = res;
          if (statusCode !== 200) {
            done(new Error('Unable to get current IP address'));
          }

          res.setEncoding('utf8');
          let rawData = '';
          res.on('data', chunk => {
            rawData += chunk;
          });
          res.on('end', () => {
            currentIp = `${rawData}/32`;
            done();
          });
        })
        .on('error', done);
    },
    done => {
      ec2.describeSecurityGroups(
        {
          GroupIds: [program.securityGroup],
        },
        (err, data) => {
          if (err) {
            return done(err);
          }

          const { SecurityGroups } = data;

          if (SecurityGroups.length === 0) {
            return done(new Error('Security group not found'));
          }

          const [securityGroup] = SecurityGroups;

          for (let i = 0, n = securityGroup.IpPermissions.length; i < n; i += 1) {
            const ipPermissions = securityGroup.IpPermissions[i];

            if (
              ipPermissions.FromPort === parseInt(program.fromPort, 10) &&
              ipPermissions.ToPort === parseInt(program.toPort, 10)
            ) {
              for (let k = 0, m = ipPermissions.IpRanges.length; k < m; k += 1) {
                const { Description, CidrIp } = ipPermissions.IpRanges[k];
                if (Description === ruleDescription) {
                  previousIp = CidrIp;
                }
              }
            }
          }

          return done();
        },
      );
    },
    done => {
      if (!previousIp) {
        return done();
      }

      const ruleParams = {
        GroupId: program.securityGroup,
        IpPermissions: [
          {
            FromPort: parseInt(program.fromPort, 10),
            ToPort: parseInt(program.toPort, 10),
            IpProtocol: program.protocol,
            IpRanges: [
              {
                CidrIp: `${previousIp}`,
                Description: ruleDescription,
              },
            ],
          },
        ],
      };

      return ec2.revokeSecurityGroupIngress(ruleParams, err => {
        if (err && !program.force) {
          done(err);
        } else {
          done();
        }
      });
    },
    done => {
      const ruleParams = {
        GroupId: program.securityGroup,
        IpPermissions: [
          {
            FromPort: parseInt(program.fromPort, 10),
            ToPort: parseInt(program.toPort, 10),
            IpProtocol: program.protocol,
            IpRanges: [
              {
                CidrIp: `${currentIp}`,
                Description: ruleDescription,
              },
            ],
          },
        ],
      };

      ec2.authorizeSecurityGroupIngress(ruleParams, err => {
        if (err && !program.force) {
          done(err);
        } else {
          done();
        }
      });
    },
  ],
  err => {
    if (err) {
      console.log(`Error: ${JSON.stringify(err)}`);
    }

    process.exit(0);
  },
);

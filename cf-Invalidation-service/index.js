'use strict';

/*
*
*   Title : Invalidation Service for Covid Alert QA Tools
*   Purpose : Receive an API call to trigger invalidation.
*   Author : Timothy Patrick Jodoin
*   Title : Principal Solution Architect
*   Email : tj@fsdcsolutions.com
*   Firm : FSDC Solutions Inc.
*   Date : Jan 12th, 2021
*   Client : CDS
*
*/

const
    AWS = require( 'aws-sdk' ),
    uuid = require( 'uuid' ),
    CF = new AWS.CloudFront();
    AWS.config.update({region: 'ca-central-1'});

exports.handler = async event => {

    var distribution_ID = process.env.distributionID;   //encrypted env_var
    let callerReference = uuid.v1();  // RFC4122 standard uuid Timestamp based generation

// populate invalidation object
    console.log("ID :",distribution_ID);
    let distribution = {
        DistributionId: distribution_ID,
        InvalidationBatch: {
            CallerReference: callerReference,                 //unique caller reference id to prevent repeat call attack
            Paths: {
                Quantity: 1,
                Items: [
                    '/',                                //invaldate root of folder
                ]
            }
        }
    };
    try {
        let data = await CF.createInvalidation(distribution);
        console.log('INVALIDATION_SUCCESS :', data);
        return 'INVALIDATION_SUCCESS';
    }
    catch (err) {
        console.log(err, err.stack); // an error occurred
        return 'INVALIDATION_FAILED';
    }
};

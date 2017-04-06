'use strict';

var fs = require('fs');
var AWS = require('lambda-helpers').AWS;

var data_table = '';

let config = {};

try {
    config = require('./resources.conf.json');
    data_table = config.tables.data;
} catch (e) {
}

let get_valid_sets = function(grants,sets) {
  var valid_sets = [];
  // Filter metadata by the JWT permissions
  sets.map( set => {
    let bits = set.name.split('/');
    return { 'group_id' : bits[0], 'id' : bits[1], 'rdata' : set.rdata };
  }).forEach(function(set) {
    let valid_prots = null;
    if (grants[set.group_id+'/'+set.id]) {
      valid_prots = grants[set.group_id+'/'+set.id];
      if (valid_prots.indexOf('*') === 0) {
        valid_sets.push(set.rdata);
      }
    }
    if (grants[set.group_id+'/*']) {
      valid_prots = grants[set.group_id+'/*'];
      if (valid_prots.indexOf('*') === 0) {
        valid_sets.push(set.rdata);
      }
    }
  });
  return valid_sets;
};

const expand_resource = function expand_resource(methodarn,resources) {
  let method_base = methodarn.split('/').slice(0,2).join('/');
  let all_resources = [
    method_base + '/POST/repository/src/contrib/PACKAGES'
  ];
  all_resources = all_resources.concat( resources.map( resource => {
    return method_base + '/POST/repository/src/contrib/' + resource;
  }) );
  return all_resources;
};

const generatePolicyDocument = function generatePolicyDocument(principalId, effect,methodarn,resources) {
  let authResponse = {};
  authResponse.principalId = typeof principalId === 'string' ? principalId : JSON.stringify(principalId);
  var policyDocument = {};
  policyDocument.Version = '2012-10-17'; // default version
  policyDocument.Statement = [];
  var statementOne = {};
  statementOne.Action = 'execute-api:Invoke'; // default action
  statementOne.Effect = effect;
  statementOne.Resource = expand_resource(methodarn,resources);
  policyDocument.Statement[0] = statementOne;
  authResponse.policyDocument = policyDocument;
  return authResponse;
}

exports.generatePolicyDocument = function(grants_promise,methodarn) {
  let dynamo = new AWS.DynamoDB.DocumentClient();
  let datasetnames = dynamo.query({'TableName' : data_table,
                                 'KeyConditionExpression' : 'acc = :acc',
                                 'FilterExpression' : 'attribute_exists(rdata_file) AND size(group_ids) > :min_size',
                                 'ProjectionExpression' : 'dataset,group_ids,rdata_file',
                                  ExpressionAttributeValues: {
                                    ':acc': 'metadata',
                                    ':min_size' : 0
                                  }
                                  }).promise().then( (data) => {
    console.log('Populating data sets');
    let all_sets = [];
    data.Items.forEach( set => {
      set.group_ids.values.map( group => `${group}/${set.dataset}` ).forEach( setname => {
        all_sets.push({ name: setname, rdata: set.rdata_file });
      });
    });
    console.log('We have ',all_sets.length, 'accessible sets in total with Rdata files');
    return all_sets;
  });
  return Promise.all([grants_promise,datasetnames]).then( (results) => {
    console.log(results[0],results[1]);
    let valid_sets = get_valid_sets(results[0].access,results[1]);
    return generatePolicyDocument(results[0].access,'allow',methodarn,valid_sets);
  });
};
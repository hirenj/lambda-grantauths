'use strict';
/*jshint esversion: 6, node:true */

/**
 * Lambda function to support JWT.
 * Used for authenticating API requests for API Gateway
 * as a custom authorizer:
 *
 */
var jwt = require('jsonwebtoken');
var jwkToPem = require('jwk-to-pem');
var fs = require('fs');
var AWS = require('lambda-helpers').AWS;

var grants_table = '';
var pubkeys_table = '';

var bucket = 'gator';

let config = {};

try {
    config = require('./resources.conf.json');
    pubkeys_table = config.tables.pubkeys;
    grants_table = config.tables.grants;
    bucket = config.buckets.dataBucket;
} catch (e) {
}

if (config.region) {
  require('lambda-helpers').AWS.setRegion(config.region);
}

let dynamo = new AWS.DynamoDB();


var get_certificates = Promise.resolve({'keys' : []});

let read_file = function(filename) {
  return new Promise(function(resolve,reject) {
    fs.readFile(filename,function(err,data) {
      if (err) {
        reject(err);
      } else {
        resolve(data);
      }
    });
  });
};

let retrieve_certs = function() {
  get_certificates = read_file('public_keys').then(function(result){
    return JSON.parse(result.toString());
  });
  return get_certificates;
};

// When we load up this module, make
// sure that the certificates are loaded up

retrieve_certs();

const tennants = JSON.parse(fs.readFileSync('tennants.json'));

var valid_microsoft_tennant = function(tennant_id) {
  return Object.keys(tennants).filter(function(tennant) {
    return tennants[tennant].id == tennant_id;
  });
};

const all_sets = [
    'public/glycodomain_10029',
    'public/glycodomain_10090',
    'public/glycodomain_10116',
    'public/glycodomain_559292',
    'public/glycodomain_6239',
    'public/glycodomain_7227',
    'public/glycodomain_9606',
    'googlegroup-test-glycodomain-dataset-users@googlegroups.com/google-0By48KKDu9leCQWdzbVhQckZJc1k',
    'googlegroup-test-glycodomain-dataset-users@googlegroups.com/google-0By48KKDu9leCQnR5V0NMMkNPZ2s',
    'googlegroup-test-glycodomain-dataset-users@googlegroups.com/google-0By48KKDu9leCRXhiRFROX2paMU0',
    'googlegroup-test-glycodomain-dataset-users@googlegroups.com/google-0By48KKDu9leCTGFSX3UxN2l6dGc',
    'googlegroup-test-glycodomain-dataset-users@googlegroups.com/google-0By48KKDu9leCY2J6NmozVEdMR2s',
    'googlegroup-test-glycodomain-dataset-users@googlegroups.com/google-0By48KKDu9leCZlpiTzQ4R2M3T1E',
    'googlegroup-test-glycodomain-dataset-users@googlegroups.com/google-0By48KKDu9leCam5MbXhTb1JQODg',
    'googlegroup-test-glycodomain-dataset-users@googlegroups.com/google-0By48KKDu9leCd1dmSGhGazYtVkU',
    'homology/homology',
    'homology/homology_alignment',
    'public/published_gastric_cancer_ags',
    'public/published_gastric_cancer_gastric_control',
    'public/published_gastric_cancer_gastric_sera',
    'public/published_gastric_cancer_kato_iii',
    'public/published_gastric_cancer_mkn45',
    'public/published_ha_ca_t_sc_phosphoproteome_phosphoproteome',
    'public/published_mda231_o_man_mda231mb',
    'public/published_simple_cell_embo_colo205',
    'public/published_simple_cell_embo_hacat',
    'public/published_simple_cell_embo_hek293',
    'public/published_simple_cell_embo_hela',
    'public/published_simple_cell_embo_hepg2',
    'public/published_simple_cell_embo_imr32',
    'public/published_simple_cell_embo_k562',
    'public/published_simple_cell_embo_mcf7',
    'public/published_simple_cell_embo_mda231mb',
    'public/published_simple_cell_embo_ovcar3',
    'public/published_simple_cell_embo_t3m4',
    'public/published_simple_cell_embo_t47d'
];


const expand_set = function(group_set) {
  let set_parts = group_set.split('/');
  let group = set_parts[0];
  let set = set_parts[1];
  if (set_parts[1] !== '*') {
    return [group+':'+set];
  }
  return all_sets.filter( (group_set) => group_set.indexOf(group) === 0 )
                 .map( (group_set) => group + ':' + group_set.split('/')[1] );
};

const expand_resource = function(methodarn,grants) {
  let method_base = methodarn.split('/').slice(0,2).join('/');
  let all_resources = [
    method_base + '/GET/data/latest/combined/*',
    method_base + '/GET/data/latest/homology/*',
    method_base + '/GET/data/latest/uniprot/*',
    method_base + '/GET/metadata',
    method_base + '/GET/doi/*'
  ];
  Object.keys(grants).forEach( (group_set) => {
    expand_set(group_set).forEach((set) => {
      if (grants[group_set].length == 1 && grants[group_set][0] == '*') {
        all_resources.push(method_base + '/GET/data/latest/'+set+'/*');
      } else {
        grants[group_set].forEach( (uniprot) => all_resources.push(method_base + '/GET/data/latest/'+set+'/'+uniprot.toLowerCase()) );
      }
    });
  });
  return all_resources;
};

function generatePolicyDocument(principalId, effect,methodarn,resource) {
  let authResponse = {};
  authResponse.principalId = typeof principalId === 'string' ? principalId : JSON.stringify(principalId);
  if (effect && methodarn) {
    var policyDocument = {};
    policyDocument.Version = '2012-10-17'; // default version
    policyDocument.Statement = [];
    var statementOne = {};
    statementOne.Action = 'execute-api:Invoke'; // default action
    statementOne.Effect = effect;
    statementOne.Resource = resource ? expand_resource(methodarn,resource) : methodarn;
    policyDocument.Statement[0] = statementOne;
    authResponse.policyDocument = policyDocument;
  }
  return authResponse;
}

var summarise_sets = function(grants) {
  let datasets = {};
  grants.forEach(function(grant) {
    (grant.sets || '').split(',').forEach(function(set) {
      if (! datasets[set]) {
        datasets[set] = [];
      }
      grant.protein = grant.protein || '';
      if (grant.protein == 'any') {
        datasets[set] = ['*'];
      } else if (datasets[set][0] !== '*') {
        grant.protein.split(',').forEach(function(prot) {
          if (datasets[set].indexOf(prot) < 0) {
            datasets[set] = datasets[set].concat([prot]);
          }
        });
      }
    });
  });
  return datasets;
};

var generate_signing_key = function() {
  return read_file('private').then((dat) => JSON.parse(dat));
};

var get_signing_key = function(key_id) {
  return get_certificates.then(function(certs) {
    console.log(certs.keys.map((key) => key.kid ).join(','));
    return jwkToPem(certs.keys.filter(function(cert) { return cert.kid == key_id; })[0]);
  });
};

var get_userid_from_token = function(authorization) {
  if ( ! authorization ) {
    return 'anonymous';
  }
  let token = authorization.split(' ');

  if( token[0] !== 'Bearer' ) {
    throw new Error('Unauthorized');
  }

  var current_token = jwt.decode(token[1],{complete: true});

  if (current_token.payload.iss == 'glycodomain') {
    throw new Error('exchanged');
  }
  let user_id = null;
  if (current_token.payload.iss === 'accounts.google.com') {
    user_id = current_token.payload.email;
  }
  if (current_token.payload.iss.match(/^https:\/\/login\.microsoftonline\.com\//)) {
    let valid_tennants = valid_microsoft_tennant(current_token.payload.tid);
    if (valid_tennants.length < 1) {
      throw new Error('Not a valid tennant for microsoft login');
    }
    user_id = current_token.payload.email || current_token.payload.preferred_username;
    if ( ! user_id.match(valid_tennants[0].email_pattern)) {
      throw new Error('Microsoft account invalid tennant pattern');
    }
  }
  if ( ! user_id ) {
    throw new Error('No valid token provider');
  }
  return user_id;
};

var copy_token = function(authorization) {
  if ( ! authorization ) {
    throw new Error('No token to copy');
  }
  let token = authorization.split(' ');

  let current_token = jwt.decode(token[1],{complete: true});
  let earliest_expiry = Math.floor((new Date()).getTime() / 1000) + 86400;

  let token_content = {
    'access' : current_token.payload.access,
    'grantnames' : current_token.payload.grantnames,
    'iss' : 'glycodomain',
    'exp' : earliest_expiry,
    'sub' : current_token.payload.sub,
  };

  return token_content;
};

var get_grant_token = function(user_id,grantnames) {
  if (user_id) {
    user_id = user_id.toLowerCase();
  }
  let params = {
    TableName : grants_table,
    ProjectionExpression : '#nm,datasets,proteins,valid_from,valid_to',
    FilterExpression: 'contains(#usr,:userid) OR contains(#usr,:anon)',
    ExpressionAttributeNames:{
        '#usr': 'users',
        '#nm': 'Name'
    },
    ExpressionAttributeValues: {
        ':userid': { 'S' : user_id },
        ':anon' : { 'S' : 'anonymous'}
    }
  };
  if ( ! user_id ) {
    params = {};
    params[grants_table] = {
      'Keys' : grantnames.map( (grant) => { return { 'Name' : {'S' : grant[0] }, 'valid_to' : {'N' : grant[1] } }; })
    };
    params = { 'RequestItems' : params };
  }
  let query_promise = (user_id ? dynamo.scan(params) : dynamo.batchGetItem(params) ).promise();
  return query_promise.then(function(data) {
    if ( ! data.Items && data.Responses ) {
      data.Items = data.Responses[grants_table];
    }
    let sets = [];
    let earliest_expiry = Math.floor((new Date()).getTime() / 1000);

    // Add a day to the expiry time, but we should
    // be doing this depending on the user that is
    // being supplied to us

    earliest_expiry = earliest_expiry + 86400;

    data.Items.forEach(function(grant) {
      if (grant.valid_to.N < earliest_expiry ) {
        earliest_expiry = grant.valid_to.N;
      }
      sets.push({'protein' : grant.proteins.S, 'name' : grant.Name.S, 'valid_to' : grant.valid_to.N, 'sets' : grant.datasets.S });
    });

    // TODO - remove long sets of proteins
    let summary_grant = summarise_sets(sets);

    let token_content = {
      'grantnames' : sets.map( (set) => [ set.name, set.valid_to ]),
      'access' : summary_grant,
      'iss' : 'glycodomain',
      'exp' : earliest_expiry,
      'sub' : user_id,
    };
    return token_content;
  });
};

var get_signed_token = function(token_content) {
  return generate_signing_key().then(function(key) {
    return new Promise(function(resolve) {
      jwt.sign(token_content,key.private,{'algorithm' : 'RS256', 'headers' : { 'kid' : key.kid } }, function(token) {
        resolve(token);
      });
    });
  });
};

// We should have one function to check that the JWT from google
// properly identifies the user, and then the lambda function that
// this wraps around creates a new access token (another jwt) that
// contains the group information for this user. The policy here
// should just allow for calling the exchanging function (and reading
// the groups?)

// We then have a second authorisation function that takes our own
// JWTs and makes sure that is valid, before creating a policy for
// the user that matches the user + groups. The policy should encapsulate
// the S3 permissions and the lambda permissions


// Alternative method is to use IAM federation and use the identity
// to variable substitute permissions in policies per user. The group
// membership would have to be some auto-generated policies, or use
// a custom authorizer to add extra permissions.

// Make sure we pass the Authorisation header along.
// http://stackoverflow.com/a/31375476

/**
 * Check authorisation for requests asking for data
 */
// Permissions: Roles grantReader
//   - Dynamodb read grants table
exports.exchangetoken = function exchangetoken(event,context) {
  // Read the current JWT

  let get_userid = Promise.resolve(true).then(function() {
    return get_userid_from_token(event.Authorization,context);
  });

  // Read the capabilities from the grants table for the user
  // Encode into new JWT

  let result = get_userid.then(get_grant_token).catch(function(err) {
    if (err.message == 'exchanged') {
      console.log('Renewing token');
      return copy_token(event.Authorization);
    }
  }).then(token => {
    // We wish to restrict the size of this token
    Object.keys(token.access).forEach(set => {
      if (token.access[set].length > 10) {
        console.log('Too many proteins in grant for',set);
        token.access[set] = [];
      }
    });
    return token;
  }).then(get_signed_token);

  result.then(function(token) {
    context.succeed(token);
  }).catch(function(err) {
    console.error(err);
    console.error(err.stack);
    context.fail('Unauthorized');
  });


  // what happens when a user has a new set of capabilities
  // while the current set is still valid? i.e. the user accepts
  // a grant to read some data in one browser tab, we should
  // get the other tabs to know about the grant. Same deal in the
  // opposite direction too.
  // Provide capacity to re-build
};

var jwt_verify = function(token,cert) {
  return new Promise(function(resolve,reject) {
    jwt.verify(token, cert, { algorithms: ['RS256','RS384','RS512'] }, function(err, data){
      if (err) {
        reject(err);
        return;
      }
      resolve(data);
    });
  });
};

var is_valid_timestamp = function(decoded_token) {
  if (! decoded_token.exp || decoded_token.exp < Math.floor((new Date()).getTime() / 1000)) {
    return Promise.reject(new Error('Expired'));
  }
  return Promise.resolve(true);
};

var accept_openid_connect_token = function(token) {
  console.log('Trying to validate bearer on openid token '+token);
  let decoded = jwt.decode(token,{complete: true});
  let cert_id = decoded.header.kid;

  // FIXME - We should be checking timestamps on the JWT
  // so that we aren't accepting ancient tokens, just
  // in case someone tries to do that.
  return is_valid_timestamp(decoded.payload).then(() => get_certificates).then(function(certs) {
    return jwt_verify(token, jwkToPem(certs.keys.filter(function(cert) { return cert.kid == cert_id; })[0]) );
  }).then(function(data){
    if (data && data.iss && data.iss == 'accounts.google.com'){
      console.log('LOGIN', data);
      // Restrict the functions to only the token exchange user
      return data;
    } else {
      console.log('Invalid User', data);
      throw new Error('Unauthorized');
    }
  });
};

var accept_self_token = function(token,anonymous) {
  console.log('Trying to validate bearer on self token '+token);
  let decoded = jwt.decode(token,{complete: true});
  let cert_id = decoded.header.kid;
  console.log('Decoded token');

  return is_valid_timestamp(decoded.payload).then(function() {
    console.log('Trying to get cert ',cert_id);
    return get_signing_key(cert_id);
  }).then(function(cert) {
    console.log('Trying to verify JWT using cert ',cert);
    return jwt_verify(token,cert);
  }).then(function(data) {
    console.log('Done verifying');
    if (data && data.sub && (! anonymous && data.sub !== 'anonymous') || (data.sub === 'anonymous' && anonymous) ){
      console.log('LOGIN', data);
      // Restrict the functions to only the token exchange user
      return data;
    } else {
      console.log('Invalid User', data);
      throw new Error('Unauthorized');
    }
  });
};

var accept_token = function(token) {
  let decoded_token = jwt.decode(token);
  let validation_promise = null;
  if (decoded_token.iss === 'glycodomain' && decoded_token.sub !== 'anonymous') {
    // This is one of our own tokens
    validation_promise = accept_self_token(token);
  } else if (decoded_token.iss === 'glycodomain' && decoded_token.sub === 'anonymous') {
    // This is also one of our own tokens
    validation_promise = accept_self_token(token,'anonymous');
  } else {
    // Check that this is a openid connect kind of token
    validation_promise = accept_openid_connect_token(token);
  }
  if ( ! validation_promise ) {
    return Promise.reject(new Error('Unauthorized'));
  }
  return validation_promise;
};

var check_data_access = function(token,dataset,protein_id) {
  let grants = jwt.decode(token).access;
  let valid = false;
  let dataset_parts = dataset.split(':');
  let group = dataset_parts[0];
  let set_id = dataset_parts[1];
  if ( typeof set_id === 'undefined') {
    set_id = group;
    group = '*';
  }
  console.log('Grants for user ',grants);
  console.log('Trying to get access to ',group,set_id);

  if ((['combined','uniprot','homology'].indexOf(set_id) >= 0) && group === '*') {
    valid = true;
    console.log('Getting built-in dataset, not checking grants');
  }

  if (! valid ) {
    Object.keys(grants).forEach(function(set) {
      let grant_set_parts = set.split('/');
      let valid_set = false;
      if (grant_set_parts[0] === group && (grant_set_parts[1] === '*' || grant_set_parts[1] === set_id )) {
        valid_set = true;
      }
      if (valid_set) {
        grants[set].forEach(function(grant_protein_id) {
          if (grant_protein_id == '*') {
            valid = true;
          }
        });
        console.log('Valid grants for',set,grants[set].join(','));
        valid = valid || grants[set].filter(function(prot) { return prot.toLowerCase() === protein_id; }).length > 0;
      }
    });
  }

  if (valid) {
    // We can also push through the valid datasets here
    // and shove it into the principalId field that can
    // then be decoded in the target function
    return Promise.resolve(grants);
  }
  let err = new Error('No access');
  err.grants = grants;
  return Promise.reject(err);
};

/**
 * Check authorisation for requests asking for data
 */
exports.datahandler = function datahandler(event,context) {
  console.log(JSON.stringify(event));
  let token = event.authorizationToken.split(' ');
  let target = event.methodArn.split(':').slice(5).join(':');
  console.log('Desired target is ',target);
  if (target.match('/GET/doi/') || target.match('/GET/metadata')) {
    target = '/data/latest/combined/publications';
  }
  let resource = (target.split('/data/latest/')[1] || 'test/test').split('/');
  console.log('Checking access for',resource);
  if(token[0] === 'Bearer'){

    // We should instead be generating a single complete
    // policy document that can be reused all over the
    // place, and then caching that.

    // So we need to get the full set of datasets
    // and the group ids for each of them
    // so that we can populate the grants
    console.time('grant_token');
    let grants_promise = get_grant_token(null,jwt.decode(token[1]).grantnames).then( (tok) => {
      console.timeEnd('grant_token');
      return tok;
    });
    console.time('access_check');
    Promise.all([
      accept_token(token[1]),
      check_data_access(token[1],resource[0],resource[1].toLowerCase())
    ]).catch(function(err) {
      console.error(err);
      console.error(err.stack);
    })
    .then( () => console.timeEnd('access_check'))
    .then( () =>  grants_promise )
    .then(function(grant_token) {
      context.succeed(generatePolicyDocument(grant_token.access, 'Allow', event.methodArn,grant_token.access));
    }).catch(function(err) {
      console.error(err);
      console.error(err.stack);
      context.fail('Error generating policy document');
    });
  } else {
    // Require a 'Bearer' token
    console.log('Wrong token type', token[0]);
    context.fail('Unauthorized');
  }
};

/**
 * Handle requests from API Gateway
 * 'event' is an object with an 'authorizationToken'
 */
exports.loginhandler = function loginhandler(event, context){
  let token = event.authorizationToken.split(' ');
  if(token[0] === 'Bearer'){
    accept_token(token[1]).then(function(token) {
      context.succeed(generatePolicyDocument(token.sub, 'Allow', event.methodArn));
    }).catch(function(err) {
      context.fail(err.message);
    });
  } else {
    // Require a 'Bearer' token
    console.log('Wrong token type', token[0]);
    context.fail('Unauthorized');
  }
};


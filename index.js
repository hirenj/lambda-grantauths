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
const rdatasets = require('./rdatasets');
const uuid = require('node-uuid');

var grants_table = '';
var pubkeys_table = '';

var bucket = 'gator';

var stack = 'test';

let config = {};

try {
    config = require('./resources.conf.json');
    pubkeys_table = config.tables.pubkeys;
    grants_table = config.tables.grants;
    bucket = config.buckets.dataBucket;
    stack = config.stack;
} catch (e) {
}

if (config.region) {
  require('lambda-helpers').AWS.setRegion(config.region);
}

const AUTH0_DOMAIN = process.env.AUTH0_DOMAIN;
const GOOGLE_ACCOUNTS_ENABLED = process.env.ENABLE_LOGIN_GOOGLE_ACCOUNTS || false;
const AUTH0_API_IDENTIFIER = process.env.AUTH0_API_IDENTIFIER || `https://${stack}.glycocode.com`;

let dynamo = new AWS.DynamoDB();
let s3 = new AWS.S3();

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

const expand_resource = function(methodarn,resource) {
  let method_base = methodarn.split('/').slice(0,2).join('/');
  let all_resources = [
    method_base + '/GET/data/latest/combined/*',
    method_base + '/GET/data/latest/uniprot/*',
    method_base + '/GET/metadata',
    method_base + '/GET/doi/*'
  ];
  // We need to special case the grants for the
  // data-feature grants, as they dont get accessed
  // via the combined endpoint
  Object.keys(resource)
  .filter( sets => sets.indexOf('data-feature/') === 0 )
  .map( set => set.replace('data-feature/','') )
  .forEach(feature => {
    all_resources.push( method_base + '/GET/data/latest/'+feature+'/*');
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
  let protein_lists = {};
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
  let list_idx = 1;
  Object.keys(datasets).forEach((set) => {
    if (datasets[set].length > 0 && datasets[set][0] !== '*') {
      let ids = datasets[set].sort();
      let set_summarised = ids.join(',');
      if (! protein_lists[set_summarised]) {
        protein_lists[set_summarised] = { 'idx' : list_idx++, 'ids' : ids };
      }
      datasets[set] = [ 'proteins_'+protein_lists[set_summarised].idx ];
    }
  });
  datasets.proteins = Object.keys(protein_lists).sort( (a,b) => a.idx - b.idx ).map( (list) => list.ids );
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
  let user_id = null;

  if (current_token.payload.iss == 'glycodomain') {
    user_id = current_token.payload.sub;
  }
  if (GOOGLE_ACCOUNTS_ENABLED && current_token.payload.iss === 'accounts.google.com') {
    user_id = current_token.payload.email;
  }
  if (current_token.payload.iss === 'https://'+AUTH0_DOMAIN+'.auth0.com/' && current_token.payload.aud === AUTH0_API_IDENTIFIER ) {
    user_id = current_token.payload.email || current_token.payload['http://glycocode/email'];
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
        '#nm': 'id'
    },
    ExpressionAttributeValues: {
        ':userid': { 'S' : user_id },
        ':anon' : { 'S' : 'anonymous'}
    }
  };
  if ( ! user_id ) {
    params = {};
    params[grants_table] = {
      'Keys' : grantnames.map( (grant) => { return { 'id' : {'S' : grant[0] }, 'valid_to' : {'N' : grant[1] } }; })
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
      sets.push({'protein' : grant.proteins.S, 'name' : grant.id.S, 'valid_to' : grant.valid_to.N, 'sets' : grant.datasets.S });
    });

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


const upload_session = function(session_id,final_token) {
  return s3.putObject({Bucket: bucket, Key: 'sessions/'+session_id, Body: final_token }).promise();
};

const get_session = function(session_id) {
  return s3.getObject({Bucket: bucket, Key: 'sessions/'+session_id }).promise()
  .then( result => result.Body.toString() );
};

const make_session_id = function(token_content) {
  let session = uuid.v4();
  token_content.session_id = session;
  return token_content;
};

var get_signed_token = function(token_content) {
  return generate_signing_key().then(function(key) {
    return new Promise(function(resolve) {
      jwt.sign(token_content,key.private,{'algorithm' : 'RS256', 'headers' : { 'kid' : key.kid } }, function(token) {
        resolve({ id_token:token, session_id:token_content.session_id });
      });
    })
    .then( signed_token => {
      return upload_session(signed_token.session_id, signed_token.id_token )
      .then( () => signed_token );
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
    return get_userid_from_token(event.Authorization);
  });

  // Read the capabilities from the grants table for the user
  // Encode into new JWT

  let result = get_userid.then(get_grant_token).catch(function(err) {
    if (err.message == 'exchanged') {
      console.log('Renewing token');
      return copy_token(event.Authorization);
    }
    console.log(err);
    throw err;
  }).then(token => {
    token.access.proteins = token.access.proteins.filter( (list) => list.length <= 10 );
    delete token.access;
    delete token.grantnames;
    return token;
  }).then(token => {
    return make_session_id(token);
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
    } else if (data && data.iss && data.iss == 'https://'+AUTH0_DOMAIN+'.auth0.com/') {
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
  if ( ! decoded_token ) {
    return Promise.reject(new Error('Unauthorized'));
  }
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


/**
 * Check authorisation for requests asking for data
 */
exports.datahandler = function datahandler(event,context) {
  console.log(JSON.stringify(event));
  let token = event.authorizationToken.split(' ');
  let target = event.methodArn.split(':').slice(5).join(':');
  console.log('Desired target is ',target);
  if(token[0] === 'Bearer'){
    // We should instead be generating a single complete
    // policy document that can be reused all over the
    // place, and then caching that.

    // So we need to get the full set of datasets
    // and the group ids for each of them
    // so that we can populate the grants

    let get_userid = Promise.resolve(true).then(function() {
      return get_userid_from_token(event.authorizationToken);
    });

    console.time('grant_token');
    let grants_promise = get_userid.then(get_grant_token).then( (tok) => {
      console.timeEnd('grant_token');
      return tok;
    });
    console.time('access_check');
    accept_token(token[1])
    .catch(function(err) {
      if (err.message == 'invalid signature') {
        throw new Error('Unauthorized');
      }
      if (err.message == 'Unauthorized') {
        throw err;
      }
      if (err.message == 'Expired') {
        throw new Error('Unauthorized');
      }
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
      context.fail('Unauthorized');
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
      console.log(err);
      context.fail('Unauthorized');
    });
  } else {
    // Require a 'Bearer' token
    console.log('Wrong token type', token[0]);
    context.fail('Unauthorized');
  }
};

exports.rdatasethandler = function(event,context) {
  let session_id = event.authorizationToken;
  get_session(session_id).then( token => {
    let get_userid = Promise.resolve(true).then(function() {
      return get_userid_from_token('Bearer '+token);
    });
    return Promise.all([get_userid,accept_token(token)]).then( (resolved) => {
      let user_id = resolved[0];
      return rdatasets.generatePolicyDocument(get_grant_token(user_id),event.methodArn);
    });
  })
  .then( document => context.succeed(document) )
  .catch( (err) => {
    console.log(err);
    console.log(err.stack);
    context.fail('Unauthorized');
  });
};

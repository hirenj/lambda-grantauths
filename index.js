'use strict';
/*jshint esversion: 6, node:true */

/**
 * Lambda function to support JWT.
 * Used for authenticating API requests for API Gateway
 * as a custom authorizer:
 *
 * @see https://jwt.io/introduction/
 * @see http://docs.aws.amazon.com/apigateway/latest/developerguide/use-custom-authorizer.html
 * @author Chris Moyer <cmoyer@aci.info>
 */
var jwt = require('jsonwebtoken');
var jwkToPem = require('jwk-to-pem');
var fs = require('fs');
var AWS = require('lambda-helpers').AWS;

var grants_table = '';
var pubkeys_table = '';

var bucket = 'gator';

try {
    var config = require('./resources.conf.json');
    pubkeys_table = config.tables.pubkeys;
    grants_table = config.tables.grants;
    bucket = config.buckets.dataBucket;
} catch (e) {
}

var get_certificates = Promise.resolve({'keys' : []});

let retrieve_certs = function() {
	let s3 = new AWS.S3();
	let params = {
		Bucket: bucket,
		Key: 'conf/authcerts'
	};

	get_certificates = s3.getObject(params).promise().then(function(result){
		JSON.parse(result.Body.toString());
	});
	return get_certificates;
};

// When we load up this module, make
// sure that the certificates are loaded up

retrieve_certs();

var write_certificates = function(certs) {
	let s3 = new AWS.S3();
	let params = {
		Bucket: bucket,
		Key: 'conf/authcerts',
		Body: JSON.stringify(certs),
		ACL: 'public-read'
	};
	return s3.putObject(params).promise();
};

const tennants = JSON.parse(fs.readFileSync('tennants.json'));

var valid_microsoft_tennant = function(tennant_id) {
	return Object.keys(tennants).filter(function(tennant) {
		return tennants[tennant].id == tennant_id;
	});
};

function generatePolicyDocument(principalId, effect, resource) {
	let authResponse = {};
	authResponse.principalId = principalId;
	if (effect && resource) {
		var policyDocument = {};
		policyDocument.Version = '2012-10-17'; // default version
		policyDocument.Statement = [];
		var statementOne = {};
		statementOne.Action = 'execute-api:Invoke'; // default action
		statementOne.Effect = effect;
		statementOne.Resource = resource;
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
	let NodeRSA = require('node-rsa');
	let uuid = require('node-uuid');
	let key_id = uuid.v4();
	let key = new NodeRSA({b: 512 });
	let dynamo = new AWS.DynamoDB();
	// We should write the pubkey to S3 here too
	let pubkey = key.exportKey('pkcs1-public-pem');
	let params = {'TableName': pubkeys_table, 'Item' : { kid: { S: key_id }, key: { S: pubkey } } };
	return dynamo.putItem(params).promise().then(function() {
		return {'kid' : key_id, 'private' : key.exportKey('pkcs1-private-pem')};
	});
};

var get_signing_key = function(key_id) {
	let params = {
		AttributesToGet: [ 'key' ],
		TableName : pubkeys_table,
		Key : { 'kid' : { 'S' : key_id } }
    };
	let dynamo = new AWS.DynamoDB();
	console.log('Getting signing pubkey');
	return dynamo.getItem(params).promise().then(function(result) {
		console.log('Got signing pubkey');
		return(result.Item.key.S);
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
		'iss' : 'glycodomain',
		'exp' : earliest_expiry,
		'sub' : current_token.payload.sub,
	};

	return token_content;
};

var get_grant_token = function(user_id) {
	let params = {
		TableName : grants_table,
		ProjectionExpression : 'datasets,proteins,valid_from,valid_to',
		FilterExpression: 'contains(#usr,:userid) OR contains(#usr,:anon)',
		ExpressionAttributeNames:{
		    '#usr': 'users'
		},
		ExpressionAttributeValues: {
		    ':userid': { 'S' : user_id },
		    ':anon' : { 'S' : 'anonymous'}
		}
	};
	let dynamo = new AWS.DynamoDB();

	return dynamo.scan(params).promise().then(function(data) {
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
			sets.push({'protein' : grant.proteins.S, 'sets' : grant.datasets.S });
		});
		let summary_grant = summarise_sets(sets);

		let token_content = {
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
// Permissions: Roles managePublicKey, grantReader
//   - Dynamodb read publickey table
//   - Dynamodb write publickey table
//   - Dynamodb read grants table
exports.exchangetoken = function exchangetoken(event,context) {
	// Read the current JWT
	console.log(JSON.stringify(event));

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
	return is_valid_timestamp(decoded.payload).then(retrieve_certs).then(function(certs) {
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
	console.log(grants);
	console.log(group,set_id);
	Object.keys(grants).forEach(function(set) {
		let grant_set_parts = set.split('/');
		let valid_set = false;
		if (grant_set_parts[0] === group && (grant_set_parts[1] === '*' || grant_set_parts[1] === set_id )) {
			valid_set = true;
		}
		if (group === 'combined' && typeof set_id === 'undefined') {
			valid_set = true;
		}
		if (valid_set) {
			grants[set].forEach(function(grant_protein_id) {
				if (grant_protein_id == '*') {
					valid = true;
				}
			});
			console.log(set,grants[set].join(','));
			valid = valid || grants[set].filter(function(prot) { return prot.toLowerCase() === protein_id; }).length > 0;
		}
	});
	if (valid) {
		// We can also push through the valid datasets here
		// and shove it into the principalId field that can
		// then be decoded in the target function
		return Promise.resolve(JSON.stringify(grants));
	}
	return Promise.reject(new Error('No access'));
};

/**
 * Check authorisation for requests asking for data
 */
// Permissions: Roles readPublicKey
//   - Dynamodb read publickey table
exports.datahandler = function datahandler(event,context) {
	console.log(JSON.stringify(event));
	let token = event.authorizationToken.split(' ');
	let target = event.methodArn.split(':').slice(5).join(':');
	let resource = target.split('/data/latest/')[1].split('/');
	console.log(resource);
	if(token[0] === 'Bearer'){
		Promise.all([
			accept_token(token[1]),
			check_data_access(token[1],resource[0],resource[1].toLowerCase())
		]).then(function(results) {
			context.succeed(generatePolicyDocument(results[1], 'Allow', event.methodArn));
		}).catch(function(err) {
			console.error(err);
			console.error(err.stack);
			context.succeed(generatePolicyDocument('user', 'Deny', event.methodArn));
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
// Permissions: Roles readPublicKey
//   - Dynamodb read publickey table
exports.loginhandler = function jwtHandler(event, context){
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

const get_file = require('lambda-helpers').get_file;

var get_jwks = function(conf_url) {
	return get_file(conf_url).then(function(conf) {
		return get_file(conf.jwks_uri);
	});
};

// Microsoft keys from
// https://login.microsoftonline.com/common/discovery/v2.0/keys
// Derived from https://login.microsoftonline.com/common/v2.0/.well-known/openid-configuration (jwks_uri)

// Google keys from
// https://accounts.google.com/.well-known/openid-configuration
// https://www.googleapis.com/oauth2/v3/certs

const google_conf = 'https://accounts.google.com/.well-known/openid-configuration';
const ms_conf = 'https://login.microsoftonline.com/common/v2.0/.well-known/openid-configuration';

exports.updateCertificates = function updateCertificates(event,context) {
	let events = require('lambda-helpers').events;
	Promise.all( [ get_jwks(ms_conf), get_jwks(google_conf) ] ).then(function(configs) {
		let confs = configs.reduce(function(curr,next) {
			if ( ! curr ) {
				return next;
			}
			curr.keys = curr.keys.concat(next.keys);
			return curr;
		});
		return write_certificates(confs);
	}).then(function() {
		return events.setInterval('updateCertificates','12 hours').then(function() {
			return events.subscribe('updateCertificates',context.invokedFunctionArn,{});
		});
	}).then(function() {
		context.succeed('OK');
	}).catch(function(err) {
		console.log(err);
		context.fail('NOT OK');
	});
};

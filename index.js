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
var fs = require('fs');
var AWS = require('aws-sdk');

var grants_table = '';
var pubkeys_table = '';


try {
    var config = require('./resources.conf.json');
    pubkeys_table = config.tables.pubkeys;
    grants_table = config.tables.grants;
} catch (e) {
}

require('es6-promise').polyfill();

//TODO - get a fresh copy of this file each time
//we deploy this function
var certs = JSON.parse(fs.readFileSync('certs.json'));

function generatePolicyDocument(principalId, effect, resource) {
	var authResponse = {};
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
	var datasets = {};
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
	var NodeRSA = require('node-rsa');
	var uuid = require('node-uuid');
	var key_id = uuid.v4();
	var key = new NodeRSA({b: 512 });
	var AWS = require('aws-sdk');
	var dynamo = new AWS.DynamoDB({region:'us-east-1'});
	var item = {};
	console.log(pubkeys_table);
	// We should write the pubkey to S3 here too
	return new Promise(function(resolve,reject) {
		var pubkey = key.exportKey('pkcs1-public-pem');
		dynamo.putItem({'TableName': pubkeys_table, 'Item' : { kid: { S: key_id }, key: { S: pubkey } } },function(err,result) {
			if (err) {
				reject(err);
				return;
			}
			resolve({'kid' : key_id, 'private' : key.exportKey('pkcs1-private-pem')});
		});
	});
};

var get_signing_key = function(key_id) {
	var params = {
		AttributesToGet: [ "key" ],
		TableName : pubkeys_table,
		Key : { "kid" : { "S" : key_id } }
    };
	var dynamo = new AWS.DynamoDB({region:'us-east-1'});
	return new Promise(function(resolve,reject) {
		console.log("Getting signing pubkey");
		dynamo.getItem(params,function(err,result) {
			console.log("Got signing pubkey");
			if (err) {
				reject(err);
				return;
			}
			resolve(result.Item.key.S);
		});

	});
};

var get_userid_from_token = function(authorization) {
	if ( ! authorization ) {
		return "anonymous";
	}
	var token = authorization.split(' ');

	if(token[0] !== 'Bearer') {
		throw new Error('Unauthorized');
	}

	var current_token = jwt.decode(token[1],{complete: true});

	if (current_token.payload.iss == 'glycodomain') {
		throw new Error("exchanged");
	}
	var user_id = current_token.payload.sub;
	if (current_token.payload.iss === 'accounts.google.com') {
		user_id = 'googleuser-'+user_id;
	}

	return user_id;
};

var copy_token = function(authorization) {
	if ( ! authorization ) {
		throw new Error("No token to copy");
	}
	var token = authorization.split(' ');

	var current_token = jwt.decode(token[1],{complete: true});
	var earliest_expiry = Math.floor((new Date()).getTime() / 1000) + 86400;

	var token_content = {
		'access' : current_token.payload.access,
		'iss' : 'glycodomain',
		'exp' : earliest_expiry,
		'sub' : current_token.payload.sub,
	};

	return token_content;
}

var get_grant_token = function(user_id) {
	var params = {
		TableName : grants_table,
		ProjectionExpression : "datasets,proteins,valid_from,valid_to",
		FilterExpression: "contains(#usr,:userid) OR contains(#usr,:anon)",
		ExpressionAttributeNames:{
		    "#usr": "users"
		},
		ExpressionAttributeValues: {
		    ":userid": { 'S' : user_id },
		    ":anon" : { 'S' : 'anonymous'}
		}
	};
	var dynamo = new AWS.DynamoDB({region:'us-east-1'});

	return new Promise(function(resolve,reject) {
		dynamo.scan(params,function(err,data) {
			if (err) {
				reject(err);
				return;
			}
			var sets = [];
			var earliest_expiry = Math.floor((new Date()).getTime() / 1000);

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
			var summary_grant = summarise_sets(sets);

			var token_content = {
				'access' : summary_grant,
				'iss' : 'glycodomain',
				'exp' : earliest_expiry,
				'sub' : user_id,
			};
			resolve(token_content);
		});
	});
};

var get_signed_token = function(token_content) {
	return generate_signing_key().then(function(key) {
		return new Promise(function(resolve,reject) {
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

	var get_userid = Promise.resolve(true).then(function() {
		return get_userid_from_token(event.Authorization,context);
	});

	// Read the capabilities from the grants table for the user
	// Encode into new JWT

	var result = get_userid.then(get_grant_token).catch(function(err) {
		if (err.message == 'exchanged') {
			console.log("Renewing token");
			return copy_token(event.Authorization);
		}
	}).then(get_signed_token);

	result.then(function(token) {
		context.succeed(token);
	}).catch(function(err) {
		console.error(err);
		console.error(err.stack);
		context.fail('Unauthorized');
	})


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

var accept_openid_connect_token = function(token) {
	console.log("Trying to validate bearer on openid token "+token);
	var cert_id = jwt.decode(token,{complete: true}).header.kid;

	// FIXME - We should be checking timestamps on the JWT
	// so that we aren't accepting ancient tokens, just
	// in case someone tries to do that.
	return is_valid_timestamp(decoded.payload).then(function() {
		return jwt_verify(token,certs[cert_id]);
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

var is_valid_timestamp = function(decoded_token) {
	if (! decoded_token.exp || decoded_token.exp < Math.floor((new Date()).getTime() / 1000)) {
		return Promise.reject(new Error('Expired'));
	}
	return Promise.resolve(true);
}

var accept_self_token = function(token,anonymous) {
	console.log("Trying to validate bearer on self token "+token);
	var decoded = jwt.decode(token,{complete: true});
	var cert_id = decoded.header.kid;
	console.log("Decoded token");

	return is_valid_timestamp(decoded.payload).then(function() {
		console.log("Trying to get cert");
		return get_signing_key(cert_id);
	}).then(function(cert) {
		console.log("Trying to verify JWT");
		return jwt_verify(token,cert);
	}).then(function(data) {
		console.log("Done verifying");
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
	var decoded_token = jwt.decode(token);
	var validation_promise = null;
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
	var grants = jwt.decode(token).access;
	var valid = false;
	var dataset_parts = dataset.split(':');
	var group = dataset_parts[0];
	var set_id = dataset_parts[1];
	console.log(grants);
	console.log(group,set_id);
	Object.keys(grants).forEach(function(set) {
		var grant_set_parts = set.split('/');
		var valid_set = false;
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
			valid = valid || grants[set].filter(function(prot) { return prot.toLowerCase() === protein_id.toLowerCase(); }).length > 0;
		}
	});
	if (valid) {
		// We can also push through the valid datasets here
		// and shove it into the principalId field that can
		// then be decoded in the target function
		return Promise.resolve(true);
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
	var token = event.authorizationToken.split(' ');
	var target = event.methodArn.split(':').slice(5).join(':');
	var resource = target.split('/data/latest/')[1].split('/');
	console.log(resource);
	if(token[0] === 'Bearer'){
		Promise.all([
			accept_token(token[1]),
			check_data_access(token[1],resource[0],resource[1])
		]).then(function(results) {
			context.succeed(generatePolicyDocument(results[0].sub, 'Allow', event.methodArn));
		}).catch(function(err) {
			console.error(err);
			console.error(err.stack);
			context.succeed(generatePolicyDocument("user", 'Deny', event.methodArn));
		});
	} else {
		// Require a "Bearer" token
		console.log('Wrong token type', token[0]);
		context.fail('Unauthorized');
	}
};

/**
 * Handle requests from API Gateway
 * "event" is an object with an "authorizationToken"
 */
// Permissions: Roles readPublicKey
//   - Dynamodb read publickey table
exports.loginhandler = function jwtHandler(event, context){
	var token = event.authorizationToken.split(' ');
	if(token[0] === 'Bearer'){
		accept_token(token[1]).then(function(token) {
			context.succeed(generatePolicyDocument(token.sub, 'Allow', event.methodArn));
		}).catch(function(err) {
			context.fail(err.message);
		});
	} else {
		// Require a "Bearer" token
		console.log('Wrong token type', token[0]);
		context.fail('Unauthorized');
	}
};

/**
 * Lambda function to support JWT.
 * Used for authenticating API requests for API Gateway
 * as a custom authorizor:
 *
 * @see https://jwt.io/introduction/
 * @see http://docs.aws.amazon.com/apigateway/latest/developerguide/use-custom-authorizer.html
 * @author Chris Moyer <cmoyer@aci.info>
 */
var jwt = require('jsonwebtoken');
var fs = require('fs');

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

var get_signing_key = function(callback) {
	var NodeRSA = require('node-rsa');
	var uuid = require('node-uuid');
	var key_id = uuid.v4();
	var key = new NodeRSA({b: 512 });
	var AWS = require('aws-sdk');
	var s3 = new AWS.S3({region:'us-east-1'});
	s3.putObject({'Bucket' : 'test-gator', 'Key': 'pubkeys/'+key_id, 'Body': key.exportKey('pkcs1-public-pem')},function(err,result) {
	});
	callback(null,{'kid' : key_id, 'private' : key.exportKey('pkcs1-private-pem')});
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

// TODO - test whether the policies here can restrict / expand on execution
// roles

// Make sure we pass the Authorisation header along.
// http://stackoverflow.com/a/31375476

// Wire up to API endpoint
exports.exchangetoken = function exchangetoken(event,context) {
	// Read the current JWT
	console.log(JSON.stringify(event));
	var token = event.Authorization.split(' ');
	if(token[0] !== 'Bearer') {
		context.fail('Unauthorized');
	}

	var current_token = jwt.decode(token[1],{complete: true});
	var AWS = require('aws-sdk');
	var dynamo = new AWS.DynamoDB({region:'us-east-1'});
	if (current_token.payload.user) {
		context.succeed("Already exchanged");
		return;
	}
	var user_id = current_token.payload.sub;

	var params = {
		TableName : "grants",
		ProjectionExpression : "datasets,proteins,valid_from,valid_to",
		FilterExpression: "contains(#usr,:userid)",
		ExpressionAttributeNames:{
		    "#usr": "users"
		},
		ExpressionAttributeValues: {
		    ":userid": { 'S' : "googleuser-"+user_id }
		}
	};
	dynamo.scan(params,function(err,data) {
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

		// FIXME - Use more JWT-like names for the content of the token
		var token_content = {
			'access' : summary_grant,
			'expires' : earliest_expiry,
			'user' : "googleuser-"+user_id,
		};

		get_signing_key(function(err,key) {
			jwt.sign(token_content,key.private,{'algorithm' : 'RS256', 'headers' : { 'kid' : key.kid } }, function(token) {
				context.succeed(token);
			});
		});
	});


	// Read the capabilities from the grants table for the user
	// Encode into new JWT

	//  Depending on performance - ( Hash JWT to get the new access_token )
	//  Depending on performance - ( Store the JWT so that we can look-up rights easily (without
	// dicking around in the grants table etc). )

	// what happens when a user has a new set of capabilities
	// while the current set is still valid? i.e. the user accepts
	// a grant to read some data in one browser tab, we should
	// get the other tabs to know about the grant. Same deal in the
	// opposite direction too.
	// Provide capacity to re-build

	// Doesn't the signing key only have to reside on the server-side?
	// We just store the encrypted key on S3, restrict access to the function
	// and then decrypt it whenever we do a login.
	// The public key is fine to remain public, and we simply switch accross
	// from one key to another every few hours. Certificate never leaves
	// data center, and we can ensure that we are signing the tokens.
};

var accept_openid_connect_token = function(token,context) {
	console.log("Trying to validate bearer "+token);
	var cert_id = jwt.decode(token,{complete: true}).header.kid;

	// FIXME - We should be checking timestamps on the JWT
	// we shouldn't be accepting ancient tokens too, just
	// in case someone tries to do that.

	jwt.verify(token, certs[cert_id], { algorithms: ['RS256','RS384','RS512'] }, function(err, data){
		if(err){
			console.log('Verification Failure', err);
			context.fail('Unauthorized');
		} else if (data && data.iss && data.iss == 'accounts.google.com'){
			console.log('LOGIN', data);
			// Restrict the functions to only the token exchange user
			context.succeed(generatePolicyDocument(data.sub, 'Allow', event.methodArn));
		} else {
			console.log('Invalid User', data);
			context.fail('Unauthorized');
		}
	});
};

var accept_self_token = function(token,context) {
	console.log("Trying to validate bearer "+token);
	var cert_id = jwt.decode(token,{complete: true}).header.kid;
	var AWS = require('aws-sdk');
	var s3 = new AWS.S3({region:'us-east-1'});

	// FIXME - We should be checking timestamps on the JWT
	// we shouldn't be accepting ancient tokens too, just
	// in case someone tries to do that.

	s3.getObject({'Bucket' : 'test-gator', 'Key': 'pubkeys/'+cert_id},function(err,result) {
		jwt.verify(token, result, { algorithms: ['RS256','RS384','RS512'] }, function(err, data){
			if(err){
				console.log('Verification Failure', err);
				context.fail('Unauthorized');
			} else if (data && data.user){
				console.log('LOGIN', data);
				// Restrict the functions to only the token exchange user
				context.succeed(generatePolicyDocument(data.sub, 'Allow', event.methodArn));
			} else {
				console.log('Invalid User', data);
				context.fail('Unauthorized');
			}
		});
	});
};

/**
 * Handle requests from API Gateway
 * "event" is an object with an "authorizationToken"
 */
exports.loginhandler = function jwtHandler(event, context){
	var token = event.authorizationToken.split(' ');
	if(token[0] === 'Bearer'){
		if (jwt.decode(token).user) {
			// This is one of our own tokens
			accept_self_token(token[1],context);
		} else {
			// Check that this is a openid connect kind of token
			accept_openid_connect_token(token[1],context);
		}
	} else {
		// Require a "Bearer" token
		console.log('Wrong token type', token[0]);
		context.fail('Unauthorized');
	}
	// If we have no token at all, we should create an anonymous
	// user identifier, and exchange that for a JWT.
};

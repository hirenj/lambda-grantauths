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

exports.exchangetoken = function exchangetoken(event,context) {
	// Read the current JWT
	// Read the capabilities from the grants table for the user
	// Encode into new JWT
	// Hash JWT to get the new access_token
	// Store the JWT so that we can look-up rights easily (without
	// dicking around in the grants table etc).
	// what happens when a user has a new set of capabilities
	// while the current set is still valid? i.e. the user accepts
	// a grant to read some data in one browser tab, we should
	// get the other tabs to know about the grant. Same deal in the
	// opposite direction too.
	// Provide capacity to re-build
};

var accept_openid_connect_token = function(token,context) {
	console.log("Trying to validate bearer "+token);
	var cert_id = jwt.decode(token,{complete: true}).header.kid;
	jwt.verify(token, certs[cert_id], function(err, data){
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

/**
 * Handle requests from API Gateway
 * "event" is an object with an "authorizationToken"
 */
exports.loginhandler = function jwtHandler(event, context){
	var token = event.authorizationToken.split(' ');
	if(token[0] === 'Bearer'){
		// Check that this is a openid connect kind of token
		accept_openid_connect_token(token[1],context);

		// Otherwise it's one of our own tokens that we need to check

	} else {
		// Require a "Bearer" token
		console.log('Wrong token type', token[0]);
		context.fail('Unauthorized');
	}
	// If we have no token at all, we should create an anonymous
	// user identifier, and exchange that for a JWT.
};

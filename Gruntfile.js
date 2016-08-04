/**
 * Grunt Uploader for Lambda scripts
 * @author: Chris Moyer <cmoyer@aci.info>
 */
'use strict';
module.exports = function(grunt) {
	require('load-grunt-tasks')(grunt);

	var path = require('path');

	var config = {'functions' : {} };
	try {
		config = require('./resources.conf.json');
	} catch (e) {
	}

	grunt.initConfig({
		lambda_invoke: {
			loginhandler: {
				package: 'jwtAuthorize',
				options: {
					file_name: 'index.js',
					handler: 'loginhandler',
					event: 'event.json',
				},
			}
		},
		lambda_deploy: {
			loginhandler: {
				package: 'jwtAuthorize',
				options: {
					file_name: 'index.js',
					handler: 'loginhandler',
				},
				function: config.functions['loginhandler'] || 'loginhandler',
				arn: null,
			},
			exchangeToken: {
				package: 'jwtAuthorize',
				options: {
					file_name: 'index.js',
					handler: 'index.exchangetoken',
				},
				function: config.functions['exchangetoken'] || 'exchangetoken',
				arn: null,
			},
			datahandler : {
				package: 'jwtAuthorize',
				options: {
					file_name: 'index.js',
					handler: 'index.datahandler',
				},
				function: config.functions['datahandler'] || 'datahandler',
				arn: null,
			}
		},
		lambda_package: {
			loginhandler: {
				package: 'jwtAuthorize',
			},
			exchangeToken: {
				package: 'jwtAuthorize',
			},
			datahandler: {
				package: 'jwtAuthorize',
			}
		},
		env: {
			prod: {
				NODE_ENV: 'production',
			},
		},

	});

	grunt.registerTask('rotateCertificates',function() {
		var AWS = require('lambda-helpers').AWS;
		var lambda = new AWS.Lambda();
		var done = this.async();
		var params = {
			FunctionName: config.functions['rotateCertificates'],
			InvocationType: 'RequestResponse',
			LogType: 'Tail',
			Payload: '{}'
		};
		lambda.invoke(params).promise().then(function(result) {
			console.log(result.Payload);
			console.log(new Buffer(result.LogResult,"base64").toString());
		}).catch(function(err) {
			console.log(err.stack,err);
		}).then(function() {
			done();
		});
	});

	grunt.registerTask('deploy', ['env:prod', 'lambda_package', 'lambda_deploy', 'rotateCertificates']);
	grunt.registerTask('deploy:loginhandler', ['env:prod', 'lambda_package:loginhandler', 'lambda_deploy:loginhandler', 'rotateCertificates']);
	grunt.registerTask('deploy:datahandler', ['env:prod', 'lambda_package:datahandler', 'lambda_deploy:datahandler', 'rotateCertificates']);
	grunt.registerTask('deploy:exchangeToken', ['env:prod', 'lambda_package:exchangeToken', 'lambda_deploy:exchangeToken', 'rotateCertificates']);
	grunt.registerTask('test', ['lambda_invoke']);
};

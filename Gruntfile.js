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

	grunt.registerTask('deploy', ['env:prod', 'lambda_package', 'lambda_deploy']);
	grunt.registerTask('deploy:loginhandler', ['env:prod', 'lambda_package:loginhandler', 'lambda_deploy:loginhandler']);
	grunt.registerTask('deploy:datahandler', ['env:prod', 'lambda_package:datahandler', 'lambda_deploy:datahandler']);
	grunt.registerTask('deploy:exchangeToken', ['env:prod', 'lambda_package:exchangeToken', 'lambda_deploy:exchangeToken']);
	grunt.registerTask('test', ['lambda_invoke']);
};

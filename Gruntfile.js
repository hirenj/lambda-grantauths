/**
 * Grunt Uploader for Lambda scripts
 * @author: Chris Moyer <cmoyer@aci.info>
 */
'use strict';
module.exports = function(grunt) {
	require('load-grunt-tasks')(grunt);

	var path = require('path');
	grunt.initConfig({
		lambda_invoke: {
			default: {
				package: 'jwtAuthorize',
				options: {
					file_name: 'index.js',
					handler: 'loginhandler',
					event: 'event.json',
				},
			}
		},
		lambda_deploy: {
			default: {
				package: 'jwtAuthorize',
				options: {
					file_name: 'index.js',
					handler: 'loginhandler',
				},
				function: 'jwtAuthorize',
				arn: null,
			},
			exchangeToken: {
				package: 'jwtAuthorize',
				options: {
					file_name: 'index.js',
					handler: 'index.exchangetoken',
				},
				function: 'exchangeToken',
				arn: null,
			},
			datahandler : {
				package: 'jwtAuthorize',
				options: {
					file_name: 'index.js',
					handler: 'index.datahandler',
				},
				function: 'datahandler',
				arn: null,
			}
		},
		lambda_package: {
			default: {
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
	grunt.registerTask('deploy:datahandler', ['env:prod', 'lambda_package:datahandler', 'lambda_deploy:datahandler']);
	grunt.registerTask('deploy:exchangeToken', ['env:prod', 'lambda_package:exchangeToken', 'lambda_deploy:exchangeToken']);
	grunt.registerTask('test', ['lambda_invoke']);
};

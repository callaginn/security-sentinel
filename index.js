/**
	@title
	Security Tester
	
	@description
	A tool designed to perform various network and security tests on a given hostname or URL.
	It includes checks for network vulnerabilities, security headers, cookies, and more.
	
	@author Stephen Ginn at Crema Design Studio
	@date 2023-10-05
*/

import fetch from 'node-fetch';
import chalk from 'chalk';

import * as common from './bin/common.js';
import * as network from './bin/network.js';
import * as security from './bin/security.js';

(async () => {
	const { hostname, url } = await common.getUserInput();
	const ipAddresses = await network.getIpAddresses(hostname);
	
	for (const ipAddress of ipAddresses) {
		console.group('\n' + chalk.bold.cyan(`Network Tests for ${ipAddress}...`));
		await network.testMySQLService(ipAddress);
		await network.testSelfSignedCertificate(ipAddress);
		await network.testEmailServiceWithoutTLS(ipAddress);
		await network.testOpenSSHVersion(ipAddress);
		console.groupEnd();
	}
	
	try {
		const response = await fetch(url);
		await security.testRedirectChainAndHTTPS(url);
		await security.testSecurityHeaders(response);
		await security.testCSP(response);
		await security.testCookies(response);
		await security.testBrowserLogs(url);
	} catch (err) {
		console.error(chalk.red(`❌ Error: ${err.message}`));
	}
	
	console.log();
})();